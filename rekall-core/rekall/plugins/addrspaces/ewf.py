# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Copyright (C) 2012 Michael Cohen <scudette@users.sourceforge.net>
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

""" This Address Space allows us to open ewf files """

from rekall import addrspace
from rekall import utils
from rekall.plugins.tools import ewf



class EWFAddressSpace(addrspace.CachingAddressSpaceMixIn,
                      addrspace.BaseAddressSpace):
    """ An EWF capable address space.

    In order for us to work we need:
    1) There must be a base AS.
    2) The first 6 bytes must be 45 56 46 09 0D 0A (EVF header)

    NOTE: We currently only support opening a single segment file since it is
    passed from the base address space. This address space supports stacking.
    """
    order = 20
    __image = True

    def __init__(self, **kwargs):
        super(EWFAddressSpace, self).__init__(**kwargs)

        # Fail quickly if this is not an EWF file.
        self.as_assert(self.base != None, "No base address space provided")

        self.as_assert(self.base.read(0, 6) == "\x45\x56\x46\x09\x0D\x0A",
                       "EWF signature not present")

        # Now try to open it as an ewf file.
        self.ewf_file = ewf.EWFFile(
            session=self.session, address_space=self.base)

        self.name = "%s (EWF)" % self.base.name

    def cached_read_partial(self, offset, length):
        """Implement our own read method for caching."""
        res = ""
        if offset != None:
            res = self.ewf_file.read(offset, length)

        if len(res) < length:
            to_read = length - len(res)
            data = addrspace.ZEROER.GetZeros(to_read)
            return res + data

        return res

    def get_mappings(self, start=0, end=2**64):
        yield addrspace.Run(start=0, end=self.ewf_file.size,
                            file_offset=0, address_space=self)
