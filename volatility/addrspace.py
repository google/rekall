# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Original Source:
# Copyright (C) 2004,2005,2006 4tphi Research
# Author: {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
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

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems

   Alias for all address spaces 

"""

#pylint: disable-msg=C0111
import volatility.registry as registry
import volatility.debug as debug
from volatility import conf



class BaseAddressSpace(object):
    """ This is the base class of all Address Spaces. """

    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    def __init__(self, base=None, session=None, write=None, **kwargs):
        """ base is the AS we will be stacking on top of, opts are
        options which we may use.
        """
        self.base = base
        self.session = session
        self.writeable = (self.session and self.session.writable_address_space) or write

    def get_config(self):
        """Returns the config object used by the vm for use in other vms"""
        return self.session

    def as_assert(self, assertion, error = None):
        """Duplicate for the assert command (so that optimizations don't disable them)

           It had to be called as_assert, since assert is a keyword
        """
        if not assertion:
            if error == None:
                error = "Instantiation failed for unspecified reason"
            raise ASAssertionError, error

    def read(self, addr, length):
        """ Read some date from a certain offset """

    def get_available_addresses(self):
        """ Return a generator of address ranges as (offset, size) covered by this AS """
        return []

    def is_valid_address(self, _addr):
        """ Tell us if the address is valid """
        return True

    def write(self, _addr, _buf):
        raise NotImplementedError("Write support for this type of Address Space has not "
                                  "been implemented")



class DummyAddressSpace(BaseAddressSpace):
    """An AS which always returns nulls."""
    __name = 'dummy'
    __abstract = True

    def is_valid_address(self, _offset):
        return True

    def read(self, _offset, length):
        return '0x00' * length


class AbstractVirtualAddressSpace(BaseAddressSpace):
    """Base Ancestor for all Virtual address spaces, as determined by astype"""
    __abstract = True

    def __init__(self, astype = 'virtual', **kwargs):
        super(AbstractVirtualAddressSpace, self).__init__(**kwargs)
        self.astype = astype

        self.as_assert(self.astype == 'virtual' or self.astype == 'any',
                       "User requested non-virtual AS")

    def vtop(self, vaddr):
        raise NotImplementedError("This is a virtual class and should not be "
                                  "referenced directly")


## This is a specialised AS for use internally - Its used to provide
## transparent support for a string buffer so types can be
## instantiated off the buffer.
class BufferAddressSpace(BaseAddressSpace):
    __abstract = True

    def __init__(self, base_offset = 0, data = '', **kwargs):
        self.fname = "Buffer"
        self.data = data
        self.base_offset = base_offset

    def assign_buffer(self, data, base_offset = 0):
        self.base_offset = base_offset
        self.data = data

    def is_valid_address(self, addr):
        return not (addr < self.base_offset or addr > self.base_offset + len(self.data))

    def read(self, addr, length):
        offset = addr - self.base_offset
        return self.data[offset: offset + length]

    def write(self, addr, data):
        self.data = self.data[:addr] + data + self.data[addr + len(data):]
        return True

    def get_available_addresses(self):
        yield (self.base_offset, len(self.data))



class Error(Exception):
    """Address space errors."""


class ASAssertionError(Error):
    """The address space failed to instantiate."""


class AddrSpaceError(Error):
    """Address Space Exception, so we can catch and deal with it in the main program"""

    def __init__(self):
        self.reasons = []
        Error.__init__(self, "No suitable address space mapping found")

    def append_reason(self, driver, reason):
        self.reasons.append((driver, reason))

    def __str__(self):
        result = Error.__str__(self) + "\nTried to open image as:\n"
        for k, v in self.reasons:
            result += " {0}: {1}\n".format(k, v)

        return result


def AddressSpaceFactory(session = None, specification = '', astype = 'virtual', **kwargs):
    """Build the address space from the specification.

    Args:
       session: A SessionObject.
       specification: A column separated list of AS class names to be stacked.
    """
    base_as = None
    for as_name in specification.split(":"):
        as_cls = BaseAddressSpace.classes.get(as_name)
        if as_cls is None:
            raise Error("No such address space %s" % as_name)

        base_as = as_cls(base=base_as, session=session, astype = astype, **kwargs)

    return base_as

