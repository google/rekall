# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2004,2005,2006 4tphi Research
#
# Authors:
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
# Michael Cohen <scudette@users.sourceforge.net>
# Mike Auty <mike.auty@gmail.com>
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

""" These are standard address spaces supported by Volatility """
import struct
import urllib
import os

from volatility import addrspace


class FileAddressSpace(addrspace.BaseAddressSpace):
    """ This is a direct file AS.

    For this AS to be instantiated, we need

    1) A valid config.filename

    2) no one else has picked the AS before us

    3) base == None (we dont operate on anyone else so we need to be
    right at the bottom of the AS stack.)
    """

    __name = "file"

    ## We should be the AS of last resort
    order = 100

    def __init__(self, filename=None, **kwargs):
        super(FileAddressSpace, self).__init__(**kwargs)

        self.as_assert(self.base == None, 'Must be first Address Space')

        path = (self.session and self.session.filename) or filename
        self.as_assert(path, "Filename must be specified in session (e.g. "
                       "session.filename = 'MyFile.raw').")

        self.name = os.path.abspath(path)
        self.fname = self.name
        self.mode = 'rb'
        if self.writeable:
            self.mode += '+'

        self.fhandle = open(self.fname, self.mode)
        self.fhandle.seek(0, 2)
        self.fsize = self.fhandle.tell()
        self.offset = 0

    def fread(self, length):
        return self.fhandle.read(length)

    def read(self, addr, length):
        self.fhandle.seek(addr)
        return self.fhandle.read(length)

    def zread(self, addr, length):
        return self.read(addr, length)

    def read_long(self, addr):
        string = self.read(addr, 4)
        (longval,) = struct.unpack('=I', string)
        return longval

    def get_available_addresses(self):
        # Since the second parameter is the length of the run
        # not the end location, it must be set to fsize, not fsize - 1
        yield (0, self.fsize)

    def is_valid_address(self, addr):
        if addr == None:
            return False
        return addr < self.fsize

    def close(self):
        self.fhandle.close()

    def write(self, addr, data):
        if not self.writeable:
            return False

        try:
            self.fhandle.seek(addr)
            self.fhandle.write(data)
        except IOError:
            return False

        return True

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.base == other.base and
                self.fname == other.fname)


class AbstractPagedMemory(addrspace.AbstractVirtualAddressSpace):
    """ Class to handle all the associated details of a paged address space

    Note: Pages can be of any size
    """
    __abstract = True

    def vtop(self, addr):
        """Abstract function that converts virtual (paged) addresses to physical addresses"""
        pass

    def get_available_pages(self):
        """A generator that returns (addr, size) for each of the virtual addresses present"""
        pass

    def get_available_addresses(self):
        """A generator that returns (addr, size) for each valid address block"""
        runLength = None
        currentOffset = None
        for (offset, size) in self.get_available_pages():
            if (runLength is None):
                runLength = size
                currentOffset = offset
            else:
                if (offset == (currentOffset + runLength)):
                    runLength += size
                else:
                    yield (currentOffset, runLength)
                    runLength = size
                    currentOffset = offset
        if (runLength is not None and currentOffset is not None):
            yield (currentOffset, runLength)

    def is_valid_address(self, vaddr):
        """Returns whether a virtual address is valid"""
        if vaddr == None:
            return False
        try:
            paddr = self.vtop(vaddr)
        except:
            return False
        if paddr == None:
            return False
        return self.base.is_valid_address(paddr)


class AbstractWritablePagedMemory(AbstractPagedMemory):
    """
    Mixin class that can be used to add write functionality
    to any standard address space that supports write() and
    vtop().
    """

    __abstract = True

    def write(self, vaddr, buf):
        if not self.writeable:
            return False

        length = len(buf)
        first_block = 0x1000 - vaddr % 0x1000
        full_blocks = ((length + (vaddr % 0x1000)) / 0x1000) - 1
        left_over = (length + vaddr) % 0x1000

        paddr = self.vtop(vaddr)
        if paddr == None:
            return False

        if length < first_block:
            return self.base.write(paddr, buf)

        self.base.write(paddr, buf[:first_block])
        buf = buf[first_block:]

        new_vaddr = vaddr + first_block
        for _i in range(0, full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                raise Exception("Failed to write to page at {0:#x}".format(new_vaddr))
            if not self.base.write(paddr, buf[:0x1000]):
                return False
            new_vaddr = new_vaddr + 0x1000
            buf = buf[0x1000:]

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                raise Exception("Failed to write to page at {0:#x}".format(new_vaddr))
            assert len(buf) == left_over
            return self.base.write(paddr, buf)

    def write_long_phys(self, addr, val):
        if not self.writeable:
            return False
        buf = struct.pack('=I', val)
        return self.base.write(addr, buf)
