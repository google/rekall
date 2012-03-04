# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Derived from source in PyFlag developed by:
# Copyright 2004: Commonwealth of Australia.
# Michael Cohen <scudette@users.sourceforge.net> 
# David Collett <daveco@users.sourceforge.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#
#
# Special thanks to Michael Cohen for ideas and comments!
#

#pylint: disable-msg=C0111

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems.
"""
import logging

from volatility import registry
from volatility import addrspace
from volatility import constants
from volatility import conf

########### Following is the new implementation of the scanning
########### framework. The old framework was based on PyFlag's
########### scanning framework which is probably too complex for this.

class BaseScanner(object):
    """ A more thorough scanner which checks every byte """

    __metaclass__ = registry.MetaclassRegistry

    checks = []
    def __init__(self, profile=None, window_size = 8):
        """The base scanner.

        Args:
           profile: The kernel profile to use for this scan.
           window_size: The size of the overlap window between each buffer read.
        """
        # Make a temporary buffer address space to run the checkers on.
        self.buffer = addrspace.BufferAddressSpace(conf.DummyConfig(), data = '\x00' * 1024)
        self.window_size = window_size
        self.constraints = []
        self.profile = profile

        ## Build our constraints from the specified ScannerCheck
        ## classes:
        for class_name, args in self.checks:
            check = ScannerCheck.classes[class_name](
                profile=profile, address_space=self.buffer, **args)
            self.constraints.append(check)

        self.max_length = None
        self.base_offset = None
        self.error_count = 0

    def check_addr(self, found):
        """ This calls all our constraints on the offset found and
        returns the number of contraints that matched.

        We shortcut the loop as soon as its obvious that there will
        not be sufficient matches to fit the criteria. This allows for
        an early exit and a speed boost.
        """
        cnt = 0
        for check in self.constraints:
            # Ask the check if this offset is possible.
            val = check.check(found)
            if not val:
                cnt = cnt + 1

            if cnt > self.error_count:
                return False

        return True

    overlap = 20
    def scan(self, address_space, offset = 0, maxlen = None):
        self.base_offset = offset
        self.max_length = maxlen

        ## Which checks also have skippers?
        skippers = [ c for c in self.constraints if hasattr(c, "skip") ]
        while 1:
            if (self.max_length != None):
                l = min(constants.SCAN_BLOCKSIZE + self.overlap, self.max_length)
            else:
                l = constants.SCAN_BLOCKSIZE + self.overlap

            data = address_space.read(self.base_offset, l)
            if not data:
                break

            length = min(constants.SCAN_BLOCKSIZE, len(data))

            self.buffer.assign_buffer(data, self.base_offset)
            i = 0
            ## Find all occurances of the pool tag in this buffer and
            ## check them:
            while i < length:
                if self.check_addr(i + self.base_offset):
                    ## yield the offset to the start of the memory
                    ## (after the pool tag)
                    yield i + self.base_offset

                ## Where should we go next? By default we go 1 byte
                ## ahead, but if some of the checkers have skippers,
                ## we may actually go much farther. Checkers with
                ## skippers basically tell us that there is no way
                ## they can match anything before the skipped result,
                ## so there is no point in trying them on all the data
                ## in between. This optimization is useful to really
                ## speed things up. FIXME - currently skippers assume
                ## that the check must match, therefore we can skip
                ## the unmatchable region, but its possible that a
                ## scanner needs to match only some checkers.
                skip = 1
                for s in skippers:
                    skip = max(skip, s.skip(data, i))

                i += skip

            self.base_offset += min(constants.SCAN_BLOCKSIZE, l)
            if (self.max_length != None):
                self.max_length -= min(constants.SCAN_BLOCKSIZE, l)


class DiscontigScanner(BaseScanner):
    def scan(self, address_space, offset = 0, maxlen = None):
        for (o, l) in address_space.get_available_addresses():
            # Rely on shortcutting
            if (o + l > offset) and ((maxlen == None) or (o < offset + maxlen)):
                for match in BaseScanner.scan(self, address_space, o, l):
                    yield match


class ScannerCheck(object):
    """ A scanner check is a special class which is invoked on an AS to check for a specific condition.

    The main method is def check(self, offset):
    This will return True if the condition is true or False otherwise.

    This class is the base class for all checks.
    """

    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    def __init__(self, profile=None, address_space=None, **_kwargs):
        """The profile that this scanner check should use."""
        self.profile = profile
        self.address_space = address_space

    def object_offset(self, offset):
        return offset

    def check(self, offset):
        return False

    ## If you want to speed up the scanning define this method - it
    ## will be used to skip the data which is obviously not going to
    ## match. You will need to return the number of bytes from offset
    ## to skip to. We take the maximum number of bytes to guarantee
    ## that all checks have a chance of passing.
    def skip(self, data, offset):
        return -1

class PoolScanner(DiscontigScanner):
    ## These are the objects that follow the pool tags
    preamble = [ '_POOL_HEADER', ]

    def object_offset(self, found, address_space):
        """ This returns the offset of the object contained within
        this pool allocation.
        """
        ## The offset of the object is determined by subtracting the offset
        ## of the PoolTag member to get the start of Pool Object and then
        ## adding the size of the preamble data structures. This done 
        ## because PoolScanners search for the PoolTag.
        total_preamble_size = sum([self.profile.get_obj_size(c) for c in self.preamble])
        pool_tag_relative_offset = self.profile.get_obj_offset('_POOL_HEADER', 'PoolTag')

        return found + total_preamble_size - pool_tag_relative_offset

    def scan(self, address_space, offset = 0, maxlen = None):
        for i in DiscontigScanner.scan(self, address_space, offset, maxlen):
            yield self.object_offset(i, address_space)
