# Rekall Memory Forensics
#
# Copyright (c) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
# Copyright 2013 Google Inc. All Rights Reserved.
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
# Code found in WindowsHiberFileSpace32 for parsing meta information
# is inspired by the work of Matthieu Suiche:  http://sandman.msuiche.net/.
# A special thanks to Matthieu for all his help integrating
# this code in Rekall Memory Forensics.

""" A Hiber file Address Space """
from rekall import addrspace
from rekall import obj
from rekall import utils
from rekall.plugins.addrspaces import xpress
import struct


# pylint: disable=C0111

PAGE_SIZE = 0x1000
page_shift = 12


class HibernationSupport(obj.ProfileModification):
    """Support hibernation file structures for different versions of windows."""

    vtypes = {
        '_PO_MEMORY_RANGE_ARRAY_LINK' : [ 0x10, {
                'NextTable' : [ 0x4, ['unsigned long']],
                'EntryCount' : [ 0xc, ['unsigned long']],
                } ],
        '_PO_MEMORY_RANGE_ARRAY_RANGE' : [ 0x10, {
                'StartPage' : [ 0x4, ['unsigned long']],
                'EndPage' : [ 0x8, ['unsigned long']],
                } ],
        '_PO_MEMORY_RANGE_ARRAY' : [ 0x20, {
                'MemArrayLink' : [ 0x0, ['_PO_MEMORY_RANGE_ARRAY_LINK']],
                'RangeTable': [ 0x10, ['array', lambda x: x.MemArrayLink.EntryCount,
                                       ['_PO_MEMORY_RANGE_ARRAY_RANGE']]],
                } ],

        '_IMAGE_XPRESS_HEADER' : [  0x20 , {
                'u09' : [ 0x9, ['unsigned char']],
                'u0A' : [ 0xA, ['unsigned char']],
                'u0B' : [ 0xB, ['unsigned char']],
                } ]
        }

    vistasp01_vtypes = {
        '_PO_MEMORY_RANGE_ARRAY' : [ 0x20, {
                'RangeTable': [ 0x10, ['array', lambda x: x.Link.EntryCount,
                                       ['_PO_MEMORY_RANGE_ARRAY_RANGE']]],
                } ],
        }

    vistasp2_vtypes = {
        '_PO_MEMORY_RANGE_ARRAY_LINK' : [ 0x10, {
                'NextTable' : [ 0x4, ['unsigned long']],
                'EntryCount' : [ 0x8, ['unsigned long']],
                } ],
        '_PO_MEMORY_RANGE_ARRAY_RANGE' : [ 0x8, {
                'StartPage' : [ 0x0, ['unsigned long']],
                'EndPage' : [ 0x4, ['unsigned long']],
                } ],
        '_PO_MEMORY_RANGE_ARRAY' : [ 0x20, {
                'MemArrayLink' : [ 0x0, ['_PO_MEMORY_RANGE_ARRAY_LINK']],
                'RangeTable': [ 0xc, ['array', lambda x: x.MemArrayLink.EntryCount,
                                      ['_PO_MEMORY_RANGE_ARRAY_RANGE']]],
                } ],
        }

    win7_vtypes = {
        '_PO_MEMORY_RANGE_ARRAY_LINK' : [ 0x10, {
                'NextTable' : [ 0x0, ['unsigned long']],
                'EntryCount' : [ 0x4, ['unsigned long']],
                } ],
        '_PO_MEMORY_RANGE_ARRAY_RANGE' : [ 0x8, {
                'StartPage' : [ 0x0, ['unsigned long']],
                'EndPage' : [ 0x4, ['unsigned long']],
                } ],
        '_PO_MEMORY_RANGE_ARRAY' : [ 0x20, {
                'MemArrayLink' : [ 0x0, ['_PO_MEMORY_RANGE_ARRAY_LINK']],
                'RangeTable': [ 0x8, ['array', lambda x: x.MemArrayLink.EntryCount,
                                      ['_PO_MEMORY_RANGE_ARRAY_RANGE']]],
                } ],
        }

    win7_x64_vtypes = {
        '_PO_MEMORY_RANGE_ARRAY_LINK' : [ 0x10, {
                'NextTable' : [ 0x0, ['unsigned long long']],
                'EntryCount' : [ 0x8, ['unsigned long']],
                } ],
        '_PO_MEMORY_RANGE_ARRAY_RANGE' : [ 0x10, {
                'StartPage' : [ 0x0, ['unsigned long long']],
                'EndPage' : [ 0x8, ['unsigned long long']],
                } ],
        '_PO_MEMORY_RANGE_ARRAY' : [ 0x20, {
                'MemArrayLink' : [ 0x0, ['_PO_MEMORY_RANGE_ARRAY_LINK']],
                'RangeTable': [ 0x10, ['array', lambda x: x.MemArrayLink.EntryCount,
                                       ['_PO_MEMORY_RANGE_ARRAY_RANGE']]],
                } ],
        }

    x64_vtypes = {
        '_PO_MEMORY_RANGE_ARRAY_LINK' : [ 0x20, {
                'NextTable' : [ 0x8, ['unsigned long long']],
                'EntryCount' : [ 0x14, ['unsigned long']],
                } ],
        '_PO_MEMORY_RANGE_ARRAY_RANGE' : [ 0x20, {
                'StartPage' : [ 0x8, ['unsigned long long']],
                'EndPage' : [ 0x10, ['unsigned long long']],
                } ],
        '_PO_MEMORY_RANGE_ARRAY' : [ 0x40, {
                'MemArrayLink' : [ 0x0, ['_PO_MEMORY_RANGE_ARRAY_LINK']],
                'RangeTable': [ 0x20, ['array', lambda x: x.MemArrayLink.EntryCount,
                                       ['_PO_MEMORY_RANGE_ARRAY_RANGE']]],
                } ],
        }

    vistaSP2_x64_vtypes = {
        '_PO_MEMORY_RANGE_ARRAY_LINK' : [ 0x18, {
                'NextTable' : [ 0x8, ['unsigned long long']],
                'EntryCount' : [ 0x10, ['unsigned long']],
                } ],
        '_PO_MEMORY_RANGE_ARRAY_RANGE' : [ 0x10, {
                'StartPage' : [ 0x0, ['unsigned long long']],
                'EndPage' : [ 0x8, ['unsigned long long']],
                } ],
        '_PO_MEMORY_RANGE_ARRAY' : [ 0x28, {
                'MemArrayLink' : [ 0x0, ['_PO_MEMORY_RANGE_ARRAY_LINK']],
                'RangeTable': [ 0x18, ['array', lambda x: x.MemArrayLink.EntryCount,
                                       ['_PO_MEMORY_RANGE_ARRAY_RANGE']]],
                } ],
        }

    @classmethod
    def modify(cls, profile):
        profile.add_overlay(cls.vtypes)
        profile.add_constants(HibrProcPage=0x2, HibrEntryCount=0xff)

        major = profile.metadata("major")
        minor = profile.metadata("minor")
        build = profile.metadata("build")
        architecture = profile.metadata("arch")

        if architecture == "I386":
            if major == 6 and minor == 0:
                if build < 6000:
                    profile.add_overlay(cls.vistasp01_vtypes)

                elif build == 6000:
                    profile.add_overlay(cls.vistasp01_vtypes)
                    profile.add_constants(HibrProcPage=0x4, HibrEntryCount=0xff)

                elif build == 6001:
                    profile.add_overlay(cls.vistasp01_vtypes)
                    profile.add_constants(HibrProcPage=0x1, HibrEntryCount=0xff)

                elif build == 6002:
                    profile.add_constants(HibrProcPage=0x1, HibrEntryCount=0x1fe)
                    profile.add_overlay(cls.vistasp2_vtypes)

            elif major == 6 and minor == 1:
                profile.add_constants(HibrProcPage=0x1, HibrEntryCount=0x1ff)

                if build <= 7601:
                    profile.add_overlay(cls.win7_vtypes)

        elif architecture == "AMD64":
            # Windows 2003
            if major == 5 and minor == 2 and build <= 3790:
                profile.add_constants(HibrProcPage=0x2, HibrEntryCount=0x7f)
                profile.add_overlay(cls.x64_vtypes)

            elif major == 6 and minor == 0:
                if build <= 6000:
                    profile.add_constants(HibrProcPage=0x4, HibrEntryCount=0x7f)
                    profile.add_overlay(cls.x64_vtypes)

                elif build == 6001:
                    profile.add_constants(HibrProcPage=0x1, HibrEntryCount=0x7f)
                    profile.add_overlay(cls.x64_vtypes)

                elif build == 6002:
                    profile.add_constants(HibrProcPage=0x1, HibrEntryCount=0xfe)
                    profile.add_overlay(cls.vistaSP2_x64_vtypes)

            elif major == 6 and minor == 1:
                profile.add_constants(HibrProcPage=0x1, HibrEntryCount=0xff)

                if build <= 7601:
                    profile.add_overlay(cls.win7_x64_vtypes)


class WindowsHiberFileSpace(addrspace.BaseAddressSpace):
    """ This is a hibernate address space for windows hibernation files.

    In order for us to work we need to:
    1) have a valid baseAddressSpace
    2) the first 4 bytes must be 'hibr'
    """

    __name = "hiber"
    __image = True

    order = 100

    def __init__(self, **kwargs):
        self.as_assert(self.base == None, "No base Address Space")
        self.as_assert(self.base.read(0, 4).lower() in ["hibr", "wake"])
        self.runs = []
        self.PageDict = {}
        self.HighestPage = 0
        self.PageIndex = 0
        self.AddressList = []
        self.LookupCache = {}
        self.PageCache = utils.FastStore(500)
        self.MemRangeCnt = 0
        self.offset = 0
        self.entry_count = 0xFF

        # Modify the profile by adding version specific definitions.
        self.profile = HibernationSupport(self.profile)

        # Extract header information
        self.as_assert(self.profile.has_type("PO_MEMORY_IMAGE"),
                       "PO_MEMORY_IMAGE is not available in profile")

        self.header = self.profile.Object('PO_MEMORY_IMAGE', offset=0, vm=self.base)
        self.entry_count = self.profile.get_constant("HibrEntryCount")

        proc_page = self.profile.get_constant("HibrProcPage")

        # Check it's definitely a hibernation file
        self.as_assert(self._get_first_table_page() is not None,
                       "No xpress signature found")

        # Extract processor state
        self.ProcState = self.profile.Object(
            "_KPROCESSOR_STATE", offset=proc_page * 4096, vm=base)

        ## This is a pointer to the page table - any ASs above us dont
        ## need to search for it.
        self.dtb = self.ProcState.SpecialRegisters.Cr3.v()

        # This is a lengthy process, it was cached, but it may be best to delay this
        # until it's absolutely necessary and/or convert it into a generator...
        self.build_page_cache()
        super(WindowsHiberFileSpace, self).__init__(**kwargs)

    def _get_first_table_page(self):
        if self.header:
            return self.header.FirstTablePage

        for i in range(10):
            if self.base.read(i * PAGE_SIZE, 8) == "\x81\x81xpress":
                return i - 1

    def build_page_cache(self):
        XpressIndex = 0

        XpressHeader = self.profile.Object("_IMAGE_XPRESS_HEADER",
            offset=(self._get_first_table_page() + 1) * 4096,
            vm=self.base)

        XpressBlockSize = self.get_xpress_block_size(XpressHeader)

        MemoryArrayOffset = self._get_first_table_page() * 4096

        while MemoryArrayOffset:
            MemoryArray = self.profile.Object(
                '_PO_MEMORY_RANGE_ARRAY', MemoryArrayOffset, self.base)

            EntryCount = MemoryArray.MemArrayLink.EntryCount.v()
            for i in MemoryArray.RangeTable:
                start = i.StartPage.v()
                end = i.EndPage.v()
                LocalPageCnt = end - start

                if end > self.HighestPage:
                    self.HighestPage = end

                self.AddressList.append((start * 0x1000,  # virtual address
                                         start * 0x1000,  # physical address
                                         LocalPageCnt * 0x1000))

                for j in range(0, LocalPageCnt):
                    if (XpressIndex and ((XpressIndex % 0x10) == 0)):
                        XpressHeader, XpressBlockSize = \
                                      self.next_xpress(XpressHeader, XpressBlockSize)

                    PageNumber = start + j
                    XpressPage = XpressIndex % 0x10
                    if XpressHeader.obj_offset not in self.PageDict:
                        self.PageDict[XpressHeader.obj_offset] = [
                            (PageNumber, XpressBlockSize, XpressPage)]
                    else:
                        self.PageDict[XpressHeader.obj_offset].append(
                            (PageNumber, XpressBlockSize, XpressPage))

                    ## Update the lookup cache
                    self.LookupCache[PageNumber] = (
                        XpressHeader.obj_offset, XpressBlockSize, XpressPage)

                    self.PageIndex += 1
                    XpressIndex += 1

            NextTable = MemoryArray.MemArrayLink.NextTable.v()

            # This entry count (EntryCount) should probably be calculated
            if (NextTable and (EntryCount == self.entry_count)):
                MemoryArrayOffset = NextTable * 0x1000
                self.MemRangeCnt += 1

                XpressHeader, XpressBlockSize = self.next_xpress(
                    XpressHeader, XpressBlockSize)

                # Make sure the xpress block is after the Memory Table
                while (XpressHeader.obj_offset < MemoryArrayOffset):
                    XpressHeader, XpressBlockSize = self.next_xpress(
                        XpressHeader, 0)

                XpressIndex = 0
            else:
                MemoryArrayOffset = 0

    def convert_to_raw(self, ofile):
        page_count = 0
        for _i, xb in enumerate(self.PageDict.keys()):
            size = self.PageDict[xb][0][1]
            data_z = self.base.read(xb + 0x20, size)
            if size == 0x10000:
                data_uz = data_z
            else:
                data_uz = xpress.xpress_decode(data_z)
            for page, size, offset in self.PageDict[xb]:
                ofile.seek(page * 0x1000)
                ofile.write(data_uz[offset * 0x1000:offset * 0x1000 + 0x1000])
                page_count += 1
            del data_z, data_uz
            yield page_count

    def next_xpress(self, XpressHeader, XpressBlockSize):
        XpressHeaderOffset = int(XpressBlockSize) + XpressHeader.obj_offset + \
            XpressHeader.size()

        ## We only search this far
        BLOCKSIZE = 1024
        original_offset = XpressHeaderOffset
        while 1:
            data = self.base.read(XpressHeaderOffset, BLOCKSIZE)
            Magic_offset = data.find("\x81\x81xpress")
            if Magic_offset >= 0:
                XpressHeaderOffset += Magic_offset
                break

            else:
                XpressHeaderOffset += len(data)

            ## Only search this far in advance
            if XpressHeaderOffset - original_offset > 10240:
                return None, None

        XpressHeader = self.profile.Object(
            "_IMAGE_XPRESS_HEADER", XpressHeaderOffset, self.base)
        XpressBlockSize = self.get_xpress_block_size(XpressHeader)

        return XpressHeader, XpressBlockSize

    def get_xpress_block_size(self, xpress_header):
        u0B = xpress_header.u0B.v() << 24
        u0A = xpress_header.u0A.v() << 16
        u09 = xpress_header.u09.v() << 8

        Size = u0B + u0A + u09
        Size = Size >> 10
        Size = Size + 1

        if ((Size % 8) == 0):
            return Size
        return (Size & ~7) + 8

    def get_header(self):
        return self.header

    def get_base(self):
        return self.base

    def get_signature(self):
        return self.header.Signature

    def get_system_time(self):
        return self.header.SystemTime

    def is_paging(self):
        return (self.ProcState.SpecialRegisters.Cr0.v() >> 31) & 1

    def is_pse(self):
        return (self.ProcState.SpecialRegisters.Cr4.v() >> 4) & 1

    def is_pae(self):
        return (self.ProcState.SpecialRegisters.Cr4.v() >> 5) & 1

    def get_number_of_memranges(self):
        return self.MemRangeCnt

    def get_number_of_pages(self):
        return self.PageIndex

    def get_addr(self, addr):
        page = addr >> page_shift
        if page in self.LookupCache:
            (hoffset, size, pageoffset) = self.LookupCache[page]
            return hoffset, size, pageoffset
        return None, None, None

    def get_block_offset(self, _xb, addr):
        page = addr >> page_shift
        if page in self.LookupCache:
            (_hoffset, _size, pageoffset) = self.LookupCache[page]
            return pageoffset
        return None

    def is_valid_address(self, addr):
        XpressHeaderOffset, _XpressBlockSize, _XpressPage = self.get_addr(addr)
        return XpressHeaderOffset != None

    def read_xpress(self, baddr, BlockSize):
        data_uz = self.PageCache.Get(baddr)
        if data_uz is None:
            data_read = self.base.read(baddr, BlockSize)
            if BlockSize == 0x10000:
                data_uz = data_read
            else:
                data_uz = xpress.xpress_decode(data_read)

                self.PageCache.Put(baddr, data_uz)

        return data_uz

    def fread(self, length):
        data = self.read(self.offset, length)
        self.offset += len(data)
        return data

    def _partial_read(self, addr, len):
        """ A function which reads as much as possible from the current page.

        May return a short read.
        """
        ## The offset within the page where we start
        page_offset = (addr & 0x00000FFF)

        ## How much data can we satisfy?
        available = min(PAGE_SIZE - page_offset, len)

        ImageXpressHeader, BlockSize, XpressPage = self.get_addr(addr)
        if not ImageXpressHeader:
            return None

        baddr = ImageXpressHeader + 0x20

        data = self.read_xpress(baddr, BlockSize)

        ## Each block decompressed contains 2**page_shift pages. We
        ## need to know which page to use here.
        offset = XpressPage * 0x1000 + page_offset

        return data[offset:offset + available]

    def read(self, addr, length):
        result = ''
        while length > 0:
            data = self._partial_read(addr, length)
            if not data:
                break

            addr += len(data)
            length -= len(data)
            result += data

        if result == '':
            result = obj.NoneObject("Unable to read data at %s for length %s." % (
                    addr, length))

        return result

    def read_long(self, addr):
        _baseaddr = self.get_addr(addr)
        string = self.read(addr, 4)
        if not string:
            return obj.NoneObject("Could not read long at %s" % addr)
        (longval,) = struct.unpack('=I', string)
        return longval

    def get_available_pages(self):
        page_list = []
        for _i, xb in enumerate(self.PageDict.keys()):
            for page, _size, _offset in self.PageDict[xb]:
                page_list.append([page * 0x1000, page * 0x1000, 0x1000])
        return page_list

    def get_address_range(self):
        """ This relates to the logical address range that is indexable """
        size = self.HighestPage * 0x1000 + 0x1000
        return [0, size]

    def check_address_range(self, addr):
        memrange = self.get_address_range()
        if addr < memrange[0] or addr > memrange[1]:
            raise IOError

    def get_available_addresses(self):
        """ This returns the ranges  of valid addresses """
        for i in self.AddressList:
            yield i

    def close(self):
        self.base.close()
