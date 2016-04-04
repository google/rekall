# Rekall Memory Forensics
# Copyright (C) 2012
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
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

""" These are standard address spaces supported by Rekall Memory Forensics """

import mmap
import os

from rekall import addrspace


class MmapFileAddressSpace(addrspace.BaseAddressSpace):
    """ This is an AS which uses an mmap of a file.

    For this AS to be instantiated, we need

    1) A valid config.LOCATION (starting with file://)

    2) no one else has picked the AS before us

    3) base == self (we dont operate on anyone else so we need to be
    right at the bottom of the AS stack.)
    """
    # We should be the AS of last resort but before the FileAddressSpace
    order = 110
    __image = True

    def __init__(self, filename=None, **kwargs):
        super(MmapFileAddressSpace, self).__init__(**kwargs)
        self.as_assert(self.base is self, 'Must be first Address Space')

        path = self.session.GetParameter("filename") or filename
        self.as_assert(path and os.path.exists(path),
                       'Filename must be specified and exist')

        self.fname = self.name = os.path.abspath(path)
        self.mode = 'rb'
        if self.session.GetParameter("writable_physical_memory"):
            self.mode += '+'

        self.fhandle = open(self.fname, self.mode)
        self.fhandle.seek(0, 2)
        self.fsize = self.fhandle.tell()
        self.offset = 0

        # On 64 bit architectures we can just map the entire image into our
        # process. Its probably not worth the effort to make it work on 32 bit
        # systems, which should just fall back to the slightly slower
        # FileAddressSpace.
        try:
            self.map = mmap.mmap(self.fhandle.fileno(), self.fsize,
                                 access=mmap.ACCESS_READ)
        except Exception as e:
            raise addrspace.ASAssertionError("Unable to mmap: %s" % e)

    def read(self, addr, length):
        result = ""
        if addr != None:
            result = self.map[addr:addr + length]

        return result + addrspace.ZEROER.GetZeros(length - len(result))

    def get_mappings(self, start=0, end=2**64):
        yield addrspace.Run(start=0,
                            end=self.fsize, file_offset=0,
                            address_space=self.base)

    def is_valid_address(self, addr):
        if addr == None:
            return False
        return addr < self.fsize - 1

    def close(self):
        self.map.close()
        self.fhandle.close()

    def write(self, addr, data):
        try:
            self.map[addr:addr + len(data)] = data
        except IOError:
            return 0

        return len(data)

    def __eq__(self, other):
        return (self.__class__ == other.__class__
                and self.fname == other.fname)
