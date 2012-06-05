# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
# Copyright (c) 2010, 2011, 2012 Michael Ligh <michael.ligh@mnin.org>
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

"""References:
http://msdn.microsoft.com/en-us/magazine/ms809762.aspx
http://msdn.microsoft.com/en-us/magazine/cc301805.aspx
http://code.google.com/p/corkami/downloads/detail?name=pe-20110117.pdf
"""
import copy

from volatility import addrspace
from volatility import obj
from volatility.plugins.overlays import basic


IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

class IndexedArray(obj.Array):
    """An array which can be addressed via constant names."""

    def __init__(self, index_table=None, **kwargs):
        super(IndexedArray, self).__init__(**kwargs)
        self.index_table = index_table or {}

    def __getitem__(self, item):
        # Still support numeric indexes
        if isinstance(item, (int, long)):
            index = item
        elif item in self.index_table:
            index = self.index_table[item]
        else:
            raise KeyError("Unknown index %s" % item)

        return super(IndexedArray, self).__getitem__(index)


class RVAPointer(obj.Pointer):
    """A pointer through a relative virtual address."""
    image_base = 0

    def __init__(self, image_base=None, **kwargs):
        super(RVAPointer, self).__init__(**kwargs)

        try:
            image_base = self.obj_vm.image_base
        except AttributeError:
            pass

        # By default find the ImageBase member of a parent.
        if image_base is None:
            parent = self.obj_parent
            while parent:
                try:
                    image_base = parent.ImageBase
                    break
                except AttributeError:
                    parent = parent.obj_parent

        self.image_base = image_base or 0

    def v(self):
        rva_pointer = super(RVAPointer, self).v()
        if rva_pointer:
            rva_pointer += self.image_base

        return rva_pointer


pe_overlays = {
    "_IMAGE_OPTIONAL_HEADER": [ None, {
            'Subsystem' : [ None, ['Enumeration', {
                        'choices': {
                            0: 'IMAGE_SUBSYSTEM_UNKNOWN',
                            1: 'IMAGE_SUBSYSTEM_NATIVE',
                            2: 'IMAGE_SUBSYSTEM_WINDOWS_GUI',
                            3: 'IMAGE_SUBSYSTEM_WINDOWS_CUI',
                            5: 'IMAGE_SUBSYSTEM_OS2_CUI',
                            7: 'IMAGE_SUBSYSTEM_POSIX_CUI',
                            9: 'IMAGE_SUBSYSTEM_WINDOWS_CE_GUI',
                            10:'IMAGE_SUBSYSTEM_EFI_APPLICATION',
                            11:'IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER',
                            12:'IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER',
                            13:'IMAGE_SUBSYSTEM_EFI_ROM',
                            14:'IMAGE_SUBSYSTEM_XBOX'},
                        'target': 'unsigned short'}]],

            'DataDirectory' : [None, ['IndexedArray', {
                        'count': IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
                        'index_table': {
                            'IMAGE_DIRECTORY_ENTRY_EXPORT':        0,
                            'IMAGE_DIRECTORY_ENTRY_IMPORT':        1,
                            'IMAGE_DIRECTORY_ENTRY_RESOURCE':      2,
                            'IMAGE_DIRECTORY_ENTRY_EXCEPTION':     3,
                            'IMAGE_DIRECTORY_ENTRY_SECURITY':      4,
                            'IMAGE_DIRECTORY_ENTRY_BASERELOC':     5,
                            'IMAGE_DIRECTORY_ENTRY_DEBUG':         6,
                            'IMAGE_DIRECTORY_ENTRY_COPYRIGHT':     7,
                            'IMAGE_DIRECTORY_ENTRY_GLOBALPTR':     8,
                            'IMAGE_DIRECTORY_ENTRY_TLS':           9,
                            'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG':   10,
                            'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT':  11,
                            'IMAGE_DIRECTORY_ENTRY_IAT':           12,
                            'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT':  13,
                            'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR':14,
                            'IMAGE_DIRECTORY_ENTRY_RESERVED':      15,
                            },
                        'target': '_IMAGE_DATA_DIRECTORY'}]],
            }],
    "_IMAGE_FILE_HEADER": [None, {
            'Machine' : [ 0x0, ['Enumeration', {
                        'choices': {
                            0x0000: 'IMAGE_FILE_MACHINE_UNKNOWN',
                            0x01d3: 'IMAGE_FILE_MACHINE_AM33',
                            0x8664: 'IMAGE_FILE_MACHINE_AMD64',
                            0x01c0: 'IMAGE_FILE_MACHINE_ARM',
                            0x0ebc: 'IMAGE_FILE_MACHINE_EBC',
                            0x014c: 'IMAGE_FILE_MACHINE_I386',
                            0x0200: 'IMAGE_FILE_MACHINE_IA64',
                            0x9041: 'IMAGE_FILE_MACHINE_MR32',
                            0x0266: 'IMAGE_FILE_MACHINE_MIPS16',
                            0x0366: 'IMAGE_FILE_MACHINE_MIPSFPU',
                            0x0466: 'IMAGE_FILE_MACHINE_MIPSFPU16',
                            0x01f0: 'IMAGE_FILE_MACHINE_POWERPC',
                            0x01f1: 'IMAGE_FILE_MACHINE_POWERPCFP',
                            0x0166: 'IMAGE_FILE_MACHINE_R4000',
                            0x01a2: 'IMAGE_FILE_MACHINE_SH3',
                            0x01a3: 'IMAGE_FILE_MACHINE_SH3DSP',
                            0x01a6: 'IMAGE_FILE_MACHINE_SH4',
                            0x01a8: 'IMAGE_FILE_MACHINE_SH5',
                            0x01c2: 'IMAGE_FILE_MACHINE_THUMB',
                            0x0169: 'IMAGE_FILE_MACHINE_WCEMIPSV2'},
                        'target': 'unsigned short'
                        }]],

            'Characteristics' : [ 0x12, ['Flags', {
                        'bitmap': {
                            # 0x0001
                            0: 'IMAGE_FILE_RELOCS_STRIPPED',
                            # 0x0002
                            1: 'IMAGE_FILE_EXECUTABLE_IMAGE',
                            # 0x0004
                            2: 'IMAGE_FILE_LINE_NUMS_STRIPPED',
                            # 0x0008
                            3: 'IMAGE_FILE_LOCAL_SYMS_STRIPPED',
                            # 0x0010
                            4: 'IMAGE_FILE_AGGRESIVE_WS_TRIM',
                            # 0x0020
                            5: 'IMAGE_FILE_LARGE_ADDRESS_AWARE',
                            # 0x0040
                            6: 'IMAGE_FILE_16BIT_MACHINE',
                            # 0x0080
                            7: 'IMAGE_FILE_BYTES_REVERSED_LO',
                            # 0x0100
                            8: 'IMAGE_FILE_32BIT_MACHINE',
                            # 0x0200
                            9: 'IMAGE_FILE_DEBUG_STRIPPED',
                            # 0x0400
                            10: 'IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP',
                            # 0x0800
                            11: 'IMAGE_FILE_NET_RUN_FROM_SWAP',
                            # 0x1000
                            12: 'IMAGE_FILE_SYSTEM',
                            # 0x2000
                            13: 'IMAGE_FILE_DLL',
                            # 0x4000
                            14: 'IMAGE_FILE_UP_SYSTEM_ONLY',
                            # 0x8000
                            15: 'IMAGE_FILE_BYTES_REVERSED_HI'},
                        'target': 'unsigned short'}]],
            'TimeDateStamp' : [ 0x4, ['UnixTimeStamp', {}]],
            }],

    "_IMAGE_SECTION_HEADER": [None, {
            'Name' : [ 0x0, ['String', {'length': 8}]],
            'Characteristics' : [ 0x24, ['Flags', {
                        'maskmap': {
                            'IMAGE_SCN_CNT_CODE':                  0x00000020,
                            'IMAGE_SCN_CNT_INITIALIZED_DATA':      0x00000040,
                            'IMAGE_SCN_CNT_UNINITIALIZED_DATA':    0x00000080,
                            'IMAGE_SCN_LNK_OTHER':                 0x00000100,
                            'IMAGE_SCN_LNK_INFO':                  0x00000200,
                            'IMAGE_SCN_LNK_REMOVE':                0x00000800,
                            'IMAGE_SCN_LNK_COMDAT':                0x00001000,
                            'IMAGE_SCN_MEM_FARDATA':               0x00008000,
                            'IMAGE_SCN_MEM_PURGEABLE':             0x00020000,
                            'IMAGE_SCN_MEM_16BIT':                 0x00020000,
                            'IMAGE_SCN_MEM_LOCKED':                0x00040000,
                            'IMAGE_SCN_MEM_PRELOAD':               0x00080000,
                            'IMAGE_SCN_ALIGN_1BYTES':              0x00100000,
                            'IMAGE_SCN_ALIGN_2BYTES':              0x00200000,
                            'IMAGE_SCN_ALIGN_4BYTES':              0x00300000,
                            'IMAGE_SCN_ALIGN_8BYTES':              0x00400000,
                            'IMAGE_SCN_ALIGN_16BYTES':             0x00500000,
                            'IMAGE_SCN_ALIGN_32BYTES':             0x00600000,
                            'IMAGE_SCN_ALIGN_64BYTES':             0x00700000,
                            'IMAGE_SCN_ALIGN_128BYTES':            0x00800000,
                            'IMAGE_SCN_ALIGN_256BYTES':            0x00900000,
                            'IMAGE_SCN_ALIGN_512BYTES':            0x00A00000,
                            'IMAGE_SCN_ALIGN_1024BYTES':           0x00B00000,
                            'IMAGE_SCN_ALIGN_2048BYTES':           0x00C00000,
                            'IMAGE_SCN_ALIGN_4096BYTES':           0x00D00000,
                            'IMAGE_SCN_ALIGN_8192BYTES':           0x00E00000,
                            'IMAGE_SCN_ALIGN_MASK':                0x00F00000,
                            'IMAGE_SCN_LNK_NRELOC_OVFL':           0x01000000,
                            'IMAGE_SCN_MEM_DISCARDABLE':           0x02000000,
                            'IMAGE_SCN_MEM_NOT_CACHED':            0x04000000,
                            'IMAGE_SCN_MEM_NOT_PAGED':             0x08000000,
                            'IMAGE_SCN_MEM_SHARED':                0x10000000,
                            'IMAGE_SCN_MEM_EXECUTE':               0x20000000,
                            'IMAGE_SCN_MEM_READ':                  0x40000000,
                            'IMAGE_SCN_MEM_WRITE':                 0x80000000L},
                        'target': 'unsigned long'}]],
            }],

    "_IMAGE_IMPORT_DESCRIPTOR": [None, {
            'Name': [ 0xC, ['RVAPointer', dict(target="String",
                                               target_args=dict(length=128))]],

            # This is an RVA pointer to an array of _IMAGE_THUNK_DATA structs.
            'FirstThunk': [ 0x10, ['RVAPointer', dict(
                        target="Array",
                        target_args=dict(targetType="_IMAGE_THUNK_DATA",
                                         count=0xFFFF))]],

            # This is a copy of the original IAT in memory.
            'OriginalFirstThunk': [ 0x0, ['RVAPointer', dict(
                        target="Array",
                        target_args=dict(targetType="_IMAGE_THUNK_DATA",
                                         count=0xFFFF))]],
            }],

    "_IMAGE_IMPORT_DESCRIPTOR64": [None, {
            'Name': [ 0xC, ['RVAPointer', dict(target="String",
                                               target_args=dict(length=128))]],

            # This is an RVA pointer to an array of _IMAGE_THUNK_DATA structs.
            'FirstThunk': [ 0x10, ['RVAPointer', dict(
                        target="Array",
                        target_args=dict(targetType="_IMAGE_THUNK_DATA64",
                                         count=0xFFFF))]],

            # This is a copy of the original IAT in memory.
            'OriginalFirstThunk': [ 0x0, ['RVAPointer', dict(
                        target="Array",
                        target_args=dict(targetType="_IMAGE_THUNK_DATA64",
                                         count=0xFFFF))]],
            }],

    "_IMAGE_THUNK_DATA": [None, {
            'AddressOfData' : [ 0x0, ['RVAPointer', dict(target="_IMAGE_IMPORT_BY_NAME")]],
            }],

    "_IMAGE_THUNK_DATA64": [None, {
            'AddressOfData' : [ 0x0, ['RVAPointer', dict(target="_IMAGE_IMPORT_BY_NAME")]],
            }],

    }

# _IMAGE_OPTIONAL_HEADER64 is the same as _IMAGE_OPTIONAL_HEADER but offsets are
# different
pe_overlays["_IMAGE_OPTIONAL_HEADER64"] = copy.deepcopy(
    pe_overlays["_IMAGE_OPTIONAL_HEADER"])


pe_vtypes = {
    '_IMAGE_EXPORT_DIRECTORY': [ 0x28, {
            'Base': [ 0x10, ['unsigned int']],
            'NumberOfFunctions': [ 0x14, ['unsigned int']],
            'NumberOfNames': [ 0x18, ['unsigned int']],
            'AddressOfFunctions': [ 0x1C, ['unsigned int']],
            'AddressOfNames': [ 0x20, ['unsigned int']],
            'AddressOfNameOrdinals': [ 0x24, ['unsigned int']],
            }],

    '_IMAGE_IMPORT_DESCRIPTOR': [ 0x14, {
            'TimeDateStamp': [ 0x4, ['UnixTimeStamp', {}]],
            'ForwarderChain': [ 0x8, ['unsigned int']],
            }],

    '_IMAGE_IMPORT_DESCRIPTOR64': [ 0x14, {
            'TimeDateStamp': [ 0x4, ['UnixTimeStamp', {}]],
            'ForwarderChain': [ 0x8, ['unsigned int']],
            }],

    # This is really a union of members.
    '_IMAGE_THUNK_DATA' : [ 0x4, {
            # Fake member for testing if the highest bit is set
            'OrdinalBit' : [ 0x0, ['BitField', dict(start_bit = 31, end_bit = 32)]],
            'Function' : [ 0x0, ['pointer', ['void']]],
            'Ordinal' : [ 0x0, ['unsigned long']],
            'AddressOfData' : [ 0x0, ['unsigned long']],
            'ForwarderString' : [ 0x0, ['unsigned int']],
            }],

    '_IMAGE_IMPORT_BY_NAME' : [ 4, {
            'Hint' : [ 0x0, ['unsigned short']],
            'Name' : [ 0x2, ['String', dict(length = 128)]],
            }],

    '__unnamed_156e' : [ 0x4, {
            'PhysicalAddress' : [ 0x0, ['unsigned long']],
            'VirtualSize' : [ 0x0, ['unsigned long']],
            } ],

    '_IMAGE_SECTION_HEADER' : [ 0x28, {
            'Name' : [ 0x0, ['String', {'length': 8}]],
            'Misc' : [ 0x8, ['__unnamed_156e']],
            'VirtualAddress' : [ 0xc, ['unsigned long']],
            'SizeOfRawData' : [ 0x10, ['unsigned long']],
            'PointerToRawData' : [ 0x14, ['unsigned long']],
            'PointerToRelocations' : [ 0x18, ['unsigned long']],
            'PointerToLinenumbers' : [ 0x1c, ['unsigned long']],
            'NumberOfRelocations' : [ 0x20, ['unsigned short']],
            'NumberOfLinenumbers' : [ 0x22, ['unsigned short']],
            } ],

    '_IMAGE_DOS_HEADER' : [ 0x40, {
            'e_magic' : [ 0x0, ['unsigned short']],
            'e_cblp' : [ 0x2, ['unsigned short']],
            'e_cp' : [ 0x4, ['unsigned short']],
            'e_crlc' : [ 0x6, ['unsigned short']],
            'e_cparhdr' : [ 0x8, ['unsigned short']],
            'e_minalloc' : [ 0xa, ['unsigned short']],
            'e_maxalloc' : [ 0xc, ['unsigned short']],
            'e_ss' : [ 0xe, ['unsigned short']],
            'e_sp' : [ 0x10, ['unsigned short']],
            'e_csum' : [ 0x12, ['unsigned short']],
            'e_ip' : [ 0x14, ['unsigned short']],
            'e_cs' : [ 0x16, ['unsigned short']],
            'e_lfarlc' : [ 0x18, ['unsigned short']],
            'e_ovno' : [ 0x1a, ['unsigned short']],
            'e_res' : [ 0x1c, ['array', 4, ['unsigned short']]],
            'e_oemid' : [ 0x24, ['unsigned short']],
            'e_oeminfo' : [ 0x26, ['unsigned short']],
            'e_res2' : [ 0x28, ['array', 10, ['unsigned short']]],
            'e_lfanew' : [ 0x3c, ['long']],
            } ],

    '_IMAGE_NT_HEADERS' : [ 0xf8, {
            'Signature' : [ 0x0, ['unsigned long']],
            'FileHeader' : [ 0x4, ['_IMAGE_FILE_HEADER']],
            'OptionalHeader' : [ 0x18, ['_IMAGE_OPTIONAL_HEADER']],
            } ],

    '_IMAGE_NT_HEADERS64' : [ 0x108, {
            'Signature' : [ 0x0, ['unsigned long']],
            'FileHeader' : [ 0x4, ['_IMAGE_FILE_HEADER']],
            'OptionalHeader' : [ 0x18, ['_IMAGE_OPTIONAL_HEADER64']],
            } ],

    '_IMAGE_OPTIONAL_HEADER64' : [ 0xf0, {
            'Magic' : [ 0x0, ['unsigned short']],
            'MajorLinkerVersion' : [ 0x2, ['unsigned char']],
            'MinorLinkerVersion' : [ 0x3, ['unsigned char']],
            'SizeOfCode' : [ 0x4, ['unsigned long']],
            'SizeOfInitializedData' : [ 0x8, ['unsigned long']],
            'SizeOfUninitializedData' : [ 0xc, ['unsigned long']],
            'AddressOfEntryPoint' : [ 0x10, ['unsigned long']],
            'BaseOfCode' : [ 0x14, ['unsigned long']],
            'ImageBase' : [ 0x18, ['unsigned long long']],
            'SectionAlignment' : [ 0x20, ['unsigned long']],
            'FileAlignment' : [ 0x24, ['unsigned long']],
            'MajorOperatingSystemVersion' : [ 0x28, ['unsigned short']],
            'MinorOperatingSystemVersion' : [ 0x2a, ['unsigned short']],
            'MajorImageVersion' : [ 0x2c, ['unsigned short']],
            'MinorImageVersion' : [ 0x2e, ['unsigned short']],
            'MajorSubsystemVersion' : [ 0x30, ['unsigned short']],
            'MinorSubsystemVersion' : [ 0x32, ['unsigned short']],
            'Win32VersionValue' : [ 0x34, ['unsigned long']],
            'SizeOfImage' : [ 0x38, ['unsigned long']],
            'SizeOfHeaders' : [ 0x3c, ['unsigned long']],
            'CheckSum' : [ 0x40, ['unsigned long']],
            'Subsystem' : [ 0x44, ['unsigned short']],
            'DllCharacteristics' : [ 0x46, ['unsigned short']],
            'SizeOfStackReserve' : [ 0x48, ['unsigned long long']],
            'SizeOfStackCommit' : [ 0x50, ['unsigned long long']],
            'SizeOfHeapReserve' : [ 0x58, ['unsigned long long']],
            'SizeOfHeapCommit' : [ 0x60, ['unsigned long long']],
            'LoaderFlags' : [ 0x68, ['unsigned long']],
            'NumberOfRvaAndSizes' : [ 0x6c, ['unsigned long']],
            'DataDirectory' : [ 0x70, ['array', 16, ['_IMAGE_DATA_DIRECTORY']]],
            } ],

    '_IMAGE_OPTIONAL_HEADER' : [ 0xe0, {
            'Magic' : [ 0x0, ['unsigned short']],
            'MajorLinkerVersion' : [ 0x2, ['unsigned char']],
            'MinorLinkerVersion' : [ 0x3, ['unsigned char']],
            'SizeOfCode' : [ 0x4, ['unsigned long']],
            'SizeOfInitializedData' : [ 0x8, ['unsigned long']],
            'SizeOfUninitializedData' : [ 0xc, ['unsigned long']],
            'AddressOfEntryPoint' : [ 0x10, ['unsigned long']],
            'BaseOfCode' : [ 0x14, ['unsigned long']],
            'BaseOfData' : [ 0x18, ['unsigned long']],
            'ImageBase' : [ 0x1c, ['unsigned long']],
            'SectionAlignment' : [ 0x20, ['unsigned long']],
            'FileAlignment' : [ 0x24, ['unsigned long']],
            'MajorOperatingSystemVersion' : [ 0x28, ['unsigned short']],
            'MinorOperatingSystemVersion' : [ 0x2a, ['unsigned short']],
            'MajorImageVersion' : [ 0x2c, ['unsigned short']],
            'MinorImageVersion' : [ 0x2e, ['unsigned short']],
            'MajorSubsystemVersion' : [ 0x30, ['unsigned short']],
            'MinorSubsystemVersion' : [ 0x32, ['unsigned short']],
            'Win32VersionValue' : [ 0x34, ['unsigned long']],
            'SizeOfImage' : [ 0x38, ['unsigned long']],
            'SizeOfHeaders' : [ 0x3c, ['unsigned long']],
            'CheckSum' : [ 0x40, ['unsigned long']],
            'Subsystem' : [ 0x44, ['unsigned long']],
            'DllCharacteristics' : [ 0x46, ['unsigned short']],
            'SizeOfStackReserve' : [ 0x48, ['unsigned long']],
            'SizeOfStackCommit' : [ 0x4c, ['unsigned long']],
            'SizeOfHeapReserve' : [ 0x50, ['unsigned long']],
            'SizeOfHeapCommit' : [ 0x54, ['unsigned long']],
            'LoaderFlags' : [ 0x58, ['unsigned long']],
            'NumberOfRvaAndSizes' : [ 0x5c, ['unsigned long']],
            'DataDirectory' : [ 0x60, ['unsigned long']],
            } ],

    '_IMAGE_FILE_HEADER' : [ 0x14, {
            'NumberOfSections' : [ 0x2, ['unsigned short']],
            'TimeDateStamp' : [ 0x4, ['UnixTimeStamp', {}]],
            'PointerToSymbolTable' : [ 0x8, ['unsigned long']],
            'NumberOfSymbols' : [ 0xc, ['unsigned long']],
            'SizeOfOptionalHeader' : [ 0x10, ['unsigned short']],
            } ],

    '_IMAGE_DATA_DIRECTORY' : [ 0x8, {
            'VirtualAddress' : [ 0x0, ['RVAPointer']],
            'Size' : [ 0x4, ['unsigned long']],
            } ],

    '_IMAGE_THUNK_DATA64' : [ 0x8, {
            # Fake member for testing if the highest bit is set
            'OrdinalBit' : [ 0x0, ['BitField', dict(start_bit = 63, end_bit = 64)]],
            'Function' : [ 0x0, ['pointer64', ['void']]],
            'Ordinal' : [ 0x0, ['unsigned long long']],
            'AddressOfData' : [ 0x0, ['unsigned long long']],
            'ForwarderString' : [ 0x0, ['unsigned long long']],
            }],
    }


class _IMAGE_EXPORT_DIRECTORY(obj.CType):
    """Class for PE export directory"""

    def valid(self, nt_header):
        """
        Check the sanity of export table fields.

        The RVAs cannot be larger than the module size. The function
        and name counts cannot be larger than 32K.
        """
        try:
            return (self.AddressOfFunctions < nt_header.OptionalHeader.SizeOfImage and
                    self.AddressOfNameOrdinals < nt_header.OptionalHeader.SizeOfImage and
                    self.AddressOfNames < nt_header.OptionalHeader.SizeOfImage and
                    self.NumberOfFunctions < 0x7FFF and
                    self.NumberOfNames < 0x7FFF)
        except obj.InvalidOffsetError:
            return False

    def _name(self, name_rva):
        """
        Return a String object for the function name.

        Names are truncated at 128 characters although its possible
        they may be longer. Thus, infrequently a function name will
        be missing some data. However, that's better than hard-coding
        a larger value which frequently causes us to cross page
        boundaries and return a NoneObject anyway.
        """
        return self.obj_profile.Object("String",
                                       offset = self.obj_parent.DllBase.v() + name_rva,
                                       vm = self.obj_vm, length = 128)

    def _exported_functions(self):
        """
        Generator for exported functions.

        @return: tuple (Ordinal, FunctionRVA, Name)

        Ordinal is an integer and should never be None. If the function
        is forwarded, FunctionRVA is None. Otherwise, FunctionRVA is an
        RVA to the function's code (relative to module base). Name is a
        String containing the exported function's name. If the Name is
        paged, it will be None. If the function is forwarded, Name is the
        forwarded function name including the DLL (ntdll.EtwLogTraceEvent).
        """

        mod_base = self.obj_parent.DllBase.v()
        exp_dir = self.obj_parent.export_dir()

        # PE files with a large number of functions will have arrays
        # that spans multiple pages. Thus the first entries may be valid,
        # last entries may be valid, but middle entries may be invalid
        # (paged). In the various checks below, we test for None (paged)
        # and zero (non-paged but invalid RVA).

        # Array of RVAs to function code
        address_of_functions = self.obj_profile.Object(
            'Array', offset = mod_base + self.AddressOfFunctions,
            targetType = 'unsigned int', count = self.NumberOfFunctions,
            vm = self.obj_vm)

        # Array of RVAs to function names
        address_of_names = self.obj_profile.Object(
            'Array', offset = mod_base + self.AddressOfNames,
            targetType = 'unsigned int', count = self.NumberOfNames,
            vm = self.obj_vm)

        # Array of RVAs to function ordinals
        address_of_name_ordinals = self.obj_profile.Object(
            'Array', offset = mod_base + self.AddressOfNameOrdinals,
            targetType = 'unsigned short', count = self.NumberOfNames,
            vm = self.obj_vm)

        # When functions are exported by Name, it will increase
        # NumberOfNames by 1 and NumberOfFunctions by 1. When
        # functions are exported by Ordinal, only the NumberOfFunctions
        # will increase. First we enum functions exported by Name
        # and track their corresponding Ordinals, so that when we enum
        # functions exported by Ordinal only, we don't duplicate.

        seen_ordinals = []

        # Handle functions exported by name *and* ordinal
        for i in range(self.NumberOfNames):

            name_rva = address_of_names[i]
            ordinal = address_of_name_ordinals[i]

            if name_rva in (0, None):
                continue

            # Check the sanity of ordinal values before using it as an index
            if ordinal == None or ordinal >= self.NumberOfFunctions:
                continue

            func_rva = address_of_functions[ordinal]

            if func_rva in (0, None):
                continue

            # Handle forwarded exports. If the function's RVA is inside the exports
            # section (as given by the VirtualAddress and Size fields in the
            # DataDirectory), the symbol is forwarded. Return the name of the
            # forwarded function and None as the function address.

            if (func_rva >= exp_dir.VirtualAddress and
                    func_rva < exp_dir.VirtualAddress + exp_dir.Size):
                n = self._name(func_rva)
                f = obj.NoneObject("This function is forwarded")
            else:
                n = self._name(name_rva)
                f = func_rva

            # Add the ordinal base and save it
            ordinal += self.Base
            seen_ordinals.append(ordinal)

            yield ordinal, f, n

        # Handle functions exported by ordinal only
        for i in range(self.NumberOfFunctions):

            ordinal = self.Base + i

            # Skip functions already enumberated above
            if ordinal not in seen_ordinals:

                func_rva = address_of_functions[i]

                if func_rva in (0, None):
                    continue

                seen_ordinals.append(ordinal)

                # There is no name RVA
                yield ordinal, func_rva, obj.NoneObject("Name RVA not accessible")


class _IMAGE_IMPORT_DESCRIPTOR(obj.CType):
    """Handles IID entries for imported functions"""

    def valid(self, nt_header):
        """Check the validity of some fields"""
        try:
            return (self.OriginalFirstThunk != 0 and
                    self.OriginalFirstThunk < nt_header.OptionalHeader.SizeOfImage and
                    self.FirstThunk != 0 and
                    self.FirstThunk < nt_header.OptionalHeader.SizeOfImage and
                    self.Name < nt_header.OptionalHeader.SizeOfImage)
        except obj.InvalidOffsetError:
            return False

    def _name(self, name_rva):
        """Return a String object for the name at the given RVA"""

        return self.obj_profile.Object(
            "String", offset = self.obj_parent.DllBase.v() + name_rva,
            vm = self.obj_vm, length = 128)

    def dll_name(self):
        """Returns the name of the DLL for this IID"""
        return self._name(self.Name)

    def _imported_functions(self):
        """
        Generator for imported functions.

        @return: tuple (Ordinal, FunctionVA, Name)

        If the function is imported by ordinal, then Ordinal is the
        ordinal value and Name is None.

        If the function is imported by name, then Ordinal is the
        hint and Name is the imported function name (or None if its
        paged).

        FunctionVA is the virtual address of the imported function,
        as applied to the IAT by the Windows loader. If the FirstThunk
        is paged, then FunctionVA will be None.
        """

        i = 0
        while 1:
            thunk = self.obj_profile.Object(
                '_IMAGE_THUNK_DATA',
                offset = self.obj_parent.DllBase.v() + self.OriginalFirstThunk +
                i * self.obj_profile.get_obj_size('_IMAGE_THUNK_DATA'),
                vm = self.obj_vm)

            # We've reached the end when the element is zero
            if thunk == None or thunk.AddressOfData == 0:
                break

            o = obj.NoneObject("Ordinal not accessible?")
            n = obj.NoneObject("Imported by ordinal?")
            f = obj.NoneObject("FirstThunk not accessible")

            # If the highest bit (32 for x86 and 64 for x64) is set, the function is
            # imported by ordinal and the lowest 16-bits contain the ordinal value.
            # Otherwise, the lowest bits (0-31 for x86 and 0-63 for x64) contain an
            # RVA to an _IMAGE_IMPORT_BY_NAME struct.
            if thunk.OrdinalBit == 1:
                o = thunk.Ordinal & 0xFFFF
            else:
                iibn = self.obj_profile.Object("_IMAGE_IMPORT_BY_NAME",
                                               offset = self.obj_parent.DllBase.v() +
                                               thunk.AddressOfData,
                                               vm = self.obj_vm)
                o = iibn.Hint
                n = iibn.Name

            # See if the import is bound (i.e. resolved)
            first_thunk = self.obj_profile.Object(
                '_IMAGE_THUNK_DATA',
                offset = self.obj_parent.DllBase.v() + self.FirstThunk +
                i * self.obj_profile.get_obj_size('_IMAGE_THUNK_DATA'),
                vm = self.obj_vm)

            if first_thunk:
                f = first_thunk.Function.v()

            yield o, f, n
            i += 1

    def is_list_end(self):
        """Returns True if we've reached the list end"""
        data = self.obj_vm.zread(
                        self.obj_offset,
                        self.obj_profile.get_obj_size('_IMAGE_IMPORT_DESCRIPTOR')
                        )
        return data.count(chr(0)) == len(data)

class _LDR_DATA_TABLE_ENTRY(obj.CType):
    """
    Class for PE file / modules

    If these classes are instantiated by _EPROCESS.list_*_modules()
    then its guaranteed to be in the process address space.
    """

    @property
    def NTHeader(self):
        """Return the _IMAGE_NT_HEADERS object"""

        dos_header = self.obj_profile.Object("_IMAGE_DOS_HEADER", offset = self.DllBase.v(),
                                             vm = self.obj_vm)

        return dos_header.NTHeader

    def _directory(self, dir_index):
        """Return the requested IMAGE_DATA_DIRECTORY"""
        data_dir = self.NTHeader.OptionalHeader.DataDirectory[dir_index]

        # Make sure the directory exists
        if data_dir.VirtualAddress == 0 or data_dir.Size == 0:
            raise ValueError('No export directory')

        # Make sure the directory VA and Size are sane
        if (data_dir.VirtualAddress + data_dir.Size >
            self.NTHeader.OptionalHeader.SizeOfImage):
            raise ValueError('Invalid Export directory')

        return data_dir

    def export_dir(self):
        """Return the IMAGE_DATA_DIRECTORY for exports"""
        return self._directory(0) # DIRECTORY_ENTRY_EXPORT

    def import_dir(self):
        """Return the IMAGE_DATA_DIRECTORY for imports"""
        return self._directory(1) # DIRECTORY_ENTRY_IMPORT

    def getprocaddress(self, func):
        """Return the RVA of func"""
        for _, f, n in self.exports():
            if str(n) == func:
                return f
        return None

    def imports(self):
        """
        Generator for the PE's imported functions.

        The _DIRECTORY_ENTRY_IMPORT.VirtualAddress points to an array
        of _IMAGE_IMPORT_DESCRIPTOR structures. The end is reached when
        the IID structure is all zeros.
        """

        try:
            data_dir = self.import_dir()
        except ValueError:
            return

        i = 0

        desc_size = self.obj_profile.get_obj_size('_IMAGE_IMPORT_DESCRIPTOR')

        while 1:
            desc = self.obj_profile.Object(
                '_IMAGE_IMPORT_DESCRIPTOR', vm = self.obj_vm,
                offset = self.DllBase.v() + data_dir.VirtualAddress + (i * desc_size),
                parent = self)

            # Stop if the IID is paged or all zeros
            if desc == None or desc.is_list_end():
                break

            # Stop if the IID contains invalid fields
            if not desc.valid(self.NTHeader):
                break

            dll_name = desc.dll_name()

            for o, f, n in desc._imported_functions():
                yield dll_name, o, f, n

            i += 1

    def exports(self):
        """Generator for the PE's exported functions"""

        try:
            data_dir = self.export_dir()
        except ValueError, why:
            raise StopIteration(why)

        expdir = self.obj_profile.Object(
            '_IMAGE_EXPORT_DIRECTORY', offset = self.DllBase.v() + data_dir.VirtualAddress,
            vm = self.obj_vm, parent = self)

        if expdir.valid(self.NTHeader):
            # Ordinal, Function RVA, and Name Object
            for o, f, n in expdir._exported_functions():
                yield o, f, n


class _IMAGE_DOS_HEADER(obj.CType):
    """DOS header"""

    @property
    def NTHeader(self):
        """Get the NT header"""

        if self.e_magic != 0x5a4d:
            return obj.NoneObject('e_magic {0:04X} is not a valid DOS signature.'.format(
                    self.e_magic))

        nt_header = self.obj_profile.Object(theType="_IMAGE_NT_HEADERS",
                                            offset = self.e_lfanew + self.obj_offset,
                                            vm = self.obj_vm)

        if nt_header.Signature != 0x4550:
            return obj.NoneObject('NT header signature {0:04X} is not a valid'.format(
                    nt_header.Signature))

        return nt_header


class _IMAGE_NT_HEADERS(obj.CType):
    """PE header"""

    @property
    def OptionalHeader(self):
        optional_header = self.m("OptionalHeader")
        if optional_header.Magic == 0x20b:
            return optional_header.cast("_IMAGE_OPTIONAL_HEADER64")

        return optional_header

    @property
    def Sections(self):
        """Get the PE sections"""
        sect_size = self.obj_profile.get_obj_size("_IMAGE_SECTION_HEADER")
        start_addr = self.FileHeader.SizeOfOptionalHeader + self.OptionalHeader.obj_offset

        for i in range(self.FileHeader.NumberOfSections):
            s_addr = start_addr + (i * sect_size)
            sect = self.obj_profile.Object(theType="_IMAGE_SECTION_HEADER",
                                           offset = s_addr, vm = self.obj_vm,
                                           parent = self)

            yield sect


class _IMAGE_SECTION_HEADER(obj.CType):
    """PE section"""

    def sanity_check_section(self):
        """Sanity checks address boundaries"""
        # Note: all addresses here are RVAs
        image_size = self.obj_parent.OptionalHeader.SizeOfImage
        if self.VirtualAddress > image_size:
            raise ValueError('VirtualAddress {0:08x} is past the end of '
                             'image.'.format(self.VirtualAddress))

        if self.Misc.VirtualSize > image_size:
            raise ValueError('VirtualSize {0:08x} is larger than image '
                             'size.'.format(self.Misc.VirtualSize))

        if self.SizeOfRawData > image_size:
            raise ValueError('SizeOfRawData {0:08x} is larger than image '
                             'size.'.format(self.SizeOfRawData))


# The following adds a profile to deal with PE files. Since PE files are not
# actually related to the kernel version, they get their own domain specific
# profile.
class PEFileImplementation(obj.ProfileModification):
    """An implementation of a parser for PE files."""

    @classmethod
    def Modify(cls, profile):
        profile.add_types(pe_vtypes)
        profile.add_classes({
                '_IMAGE_DOS_HEADER': _IMAGE_DOS_HEADER,
                '_IMAGE_NT_HEADERS': _IMAGE_NT_HEADERS,
                '_IMAGE_SECTION_HEADER': _IMAGE_SECTION_HEADER,
                '_IMAGE_EXPORT_DIRECTORY': _IMAGE_EXPORT_DIRECTORY,
                '_IMAGE_IMPORT_DESCRIPTOR': _IMAGE_IMPORT_DESCRIPTOR,
                '_LDR_DATA_TABLE_ENTRY': _LDR_DATA_TABLE_ENTRY,
                "IndexedArray": IndexedArray,
                "RVAPointer": RVAPointer,
                })
        profile.add_overlay(pe_overlays)

class PEProfile(basic.Profile32Bits, basic.BasicWindowsClasses):
    """A profile for PE files."""

    def __init__(self, **kwargs):
        super(PEProfile, self).__init__(**kwargs)
        PEFileImplementation.Modify(self)


class PEFileAddressSpace(addrspace.BaseAddressSpace):
    """An address space which applies to PE files.

    This basically remaps sections in the PE file to the virtual address space.
    """
    def __init__(self, **kwargs):
        """We layer on top of the file address space."""
        super(PEFileAddressSpace, self).__init__(**kwargs)

        self.as_assert(self.base is not None, "Must layer on another AS.")
        self.as_assert(self.base.read(0, 2) == "MZ", "File does not have a PE signature.")
        self.nt_header = PEProfile().Object(
            "_IMAGE_DOS_HEADER", vm=self.base, offset=0).NTHeader
        self.image_base = int(self.nt_header.OptionalHeader.ImageBase)

        # Now map all the sections into a virtual address space.
        self.runs = []
        for section in self.nt_header.Sections:
            virtual_address = section.VirtualAddress.v() + self.image_base
            self.runs.append(
                (virtual_address, section.SizeOfRawData.v(), section.PointerToRawData.v()))

    def read(self, addr, length):
        for virtual_address, run_length, physical_address in self.runs:
            if addr >= virtual_address and addr <= virtual_address + run_length:
                offset = addr - virtual_address
                to_read = min(run_length - offset, length)

                return self.base.read(physical_address + offset, to_read)

        # Otherwise just null pad the results.
        return '\x00' * length
