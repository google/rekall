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
http://code.google.com/p/pefile/

Version information:
http://msdn.microsoft.com/en-us/library/windows/desktop/ff468916(v=vs.85).aspx
"""
import copy

from volatility import addrspace
from volatility import obj
from volatility import utils
from volatility.plugins.overlays import basic


class IndexedArray(obj.Array):
    """An array which can be addressed via constant names."""

    def __init__(self, index_table=None, **kwargs):
        self.index_table = index_table or {}
        super(IndexedArray, self).__init__(**kwargs)

    def __getitem__(self, item):
        # Still support numeric indexes
        if isinstance(item, (int, long)):
            index = item

            # Try to name the object appropriately.
            for k, v in self.index_table.items():
                if v == item:
                    item = k
                    break

        elif item in self.index_table:
            index = self.index_table[item]
        else:
            raise KeyError("Unknown index %s" % item)

        result = super(IndexedArray, self).__getitem__(index)
        result.obj_name = str(item)

        return result


class SentinalArray(obj.Array):
    """A sential terminated array."""

    def __iter__(self):
        """Break when the sentinal is reached."""
        for member in super(SentinalArray, self).__iter__():
            data = member.obj_vm.zread(member.obj_offset, member.size())
            if data == "\x00" * member.size():
                break

            yield member


class RVAPointer(obj.Pointer):
    """A pointer through a relative virtual address."""
    ImageBase = 0

    def __init__(self, image_base=None, **kwargs):
        super(RVAPointer, self).__init__(**kwargs)
        self.image_base = self.obj_context.get("image_base", 0)

    def v(self):
        rva_pointer = super(RVAPointer, self).v()
        if rva_pointer:
            rva_pointer += self.image_base

        return rva_pointer

class ResourcePointer(obj.Pointer):
    """A pointer relative to our resource section."""
    resource_base = 0

    def __init__(self, resource_base=None, **kwargs):
        super(ResourcePointer, self).__init__(**kwargs)
        # By default find the resource_base from the context.
        self.resource_base = self.obj_context.get("resource_base")

        if self.resource_base is None:
            for parent in self.parents:
                if isinstance(parent, _IMAGE_NT_HEADERS):
                    for section in parent.Sections:
                        if section.Name.startswith(".rsrc"):
                            self.resource_base = (section.VirtualAddress +
                                                  parent.OptionalHeader.ImageBase)
                            self.obj_context['resource_base'] = self.resource_base
                            break

    def v(self):
        # Only the first 31 bits are meaningful.
        resource_pointer = int(super(ResourcePointer, self).v()) & ((1 << 31) - 1)
        if resource_pointer:
            resource_pointer += self.resource_base

        return resource_pointer


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
                        'count': 16,
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
                        'maskmap': {
                            'IMAGE_FILE_RELOCS_STRIPPED': 0x0001,
                            'IMAGE_FILE_EXECUTABLE_IMAGE': 0x0002,
                            'IMAGE_FILE_LINE_NUMS_STRIPPED': 0x0004,
                            'IMAGE_FILE_LOCAL_SYMS_STRIPPED': 0x0008,
                            'IMAGE_FILE_AGGRESIVE_WS_TRIM': 0x0010,
                            'IMAGE_FILE_LARGE_ADDRESS_AWARE': 0x0020,
                            'IMAGE_FILE_16BIT_MACHINE': 0x0040,
                            'IMAGE_FILE_BYTES_REVERSED_LO': 0x0080,
                            'IMAGE_FILE_32BIT_MACHINE': 0x0100,
                            'IMAGE_FILE_DEBUG_STRIPPED': 0x0200,
                            'IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP': 0x0400,
                            'IMAGE_FILE_NET_RUN_FROM_SWAP': 0x0800,
                            'IMAGE_FILE_SYSTEM': 0x1000,
                            'IMAGE_FILE_DLL': 0x2000,
                            'IMAGE_FILE_UP_SYSTEM_ONLY': 0x4000,
                            'IMAGE_FILE_BYTES_REVERSED_HI': 0x8000,
                            },
                        'target': 'unsigned short'}]],
            'TimeDateStamp' : [ 0x4, ['UnixTimeStamp', {}]],
            }],

    "_IMAGE_SECTION_HEADER": [None, {
            'Name' : [ 0x0, ['String', {'length': 8, 'term': None}]],
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
            'FirstThunk': [ 0x10, ['RVAPointer', dict(target="ThunkArray")]],

            # This is a copy of the original IAT in memory.
            'OriginalFirstThunk': [ 0x0, ['RVAPointer', dict(target="ThunkArray")]],
            }],

    "_IMAGE_EXPORT_DIRECTORY": [None, {
            'Name': [ 0xC, ['RVAPointer', dict(target="String",
                                               target_args=dict(length=128))]],

            'AddressOfFunctions': [ None, ['RVAPointer', dict(
                        target="Array",
                        target_args=dict(target="RVAPointer",
                                         target_args=dict(target="Function"),
                                         count=lambda x: x.NumberOfFunctions)
                        )]],

            'AddressOfNames': [ None, ["RVAPointer", dict(
                        target="Array",
                        target_args=dict(
                            target="RVAPointer",
                            target_args=dict(target="String"),
                            count=lambda x: x.NumberOfNames,
                            )
                        )]],

            'AddressOfNameOrdinals': [ None, ['RVAPointer', dict(
                        target="Array",
                        target_args=dict(
                            target="unsigned short int",
                            count=lambda x: x.NumberOfFunctions)
                        )]],
            }],

    "_IMAGE_THUNK_DATA": [None, {
            'AddressOfData' : [ 0x0, ['RVAPointer', dict(target="_IMAGE_IMPORT_BY_NAME")]],
            }],

    "_IMAGE_THUNK_DATA64": [None, {
            'AddressOfData' : [ 0x0, ['RVAPointer', dict(target="_IMAGE_IMPORT_BY_NAME")]],
            }],

    "_IMAGE_NT_HEADERS": [None, {
            # This is a psuedo member to give access to the sections.
            "Sections": [
                # The sections start immediately after the OptionalHeader:
                lambda x: x.FileHeader.SizeOfOptionalHeader + x.OptionalHeader.obj_offset,

                # The sections are an array of _IMAGE_SECTION_HEADER structs.
                # The number of sections is found in the FileHeader
                ['Array', dict(target="_IMAGE_SECTION_HEADER",
                               count=lambda x: x.FileHeader.NumberOfSections)]],
            }],

    "_IMAGE_RESOURCE_DIRECTORY": [0x10, {
            "NumberOfNamedEntries": [0x0c, ['unsigned short int']],
            "NumberOfIdEntries": [0x0e, ['unsigned short int']],
            "Entries": [0x10, ["Array", dict(
                        target="_IMAGE_RESOURCE_DIRECTORY_ENTRY",
                        count=lambda x: x.NumberOfIdEntries + x.NumberOfNamedEntries)]],
            }],

    "_IMAGE_RESOURCE_DIRECTORY_ENTRY": [0x08, {
            "Name": [0x00, ['ResourcePointer', dict(target="PrefixedString")]],
            "Type": [0x00, ["Enumeration", dict(choices={
                            1:    'RT_CURSOR',
                            2:    'RT_BITMAP',
                            3:    'RT_ICON',
                            4:    'RT_MENU',
                            5:    'RT_DIALOG',
                            6:    'RT_STRING',
                            7:    'RT_FONTDIR',
                            8:    'RT_FONT',
                            9:    'RT_ACCELERATOR',
                            10:   'RT_RCDATA',
                            11:   'RT_MESSAGETABLE',
                            12:   'RT_GROUP_CURSOR',
                            14:   'RT_GROUP_ICON',
                            16:   'RT_VERSION',
                            17:   'RT_DLGINCLUDE',
                            19:   'RT_PLUGPLAY',
                            20:   'RT_VXD',
                            21:   'RT_ANICURSOR',
                            22:   'RT_ANIICON',
                            23:   'RT_HTML',
                            24:   'RT_MANIFEST'})]],

            # This is true when we need to use the Name field.
            "NameIsString": [0x00, ['BitField', dict(start_bit=31, end_bit=32)]],
            "OffsetToDataInt": [0x04, ['unsigned int']],
            "OffsetToData": [0x04, ['ResourcePointer', dict(target="_IMAGE_RESOURCE_DATA_ENTRY")]],
            "Entry": [0x04, ['ResourcePointer', dict(target="_IMAGE_RESOURCE_DIRECTORY")]],

            # If this is set the child is another _IMAGE_RESOURCE_DIRECTORY_ENTRY
            "ChildIsEntry": [0x04, ['BitField', dict(start_bit=31, end_bit=32)]],
            }],

    'PrefixedString' : [ 0x02, {
            'Length' : [ 0x0, ['unsigned short']],
            'Buffer' : [ 0x2, ['UnicodeString', dict(length=lambda x: x.Length * 2 + 1)]],
            } ],

    '_IMAGE_RESOURCE_DATA_ENTRY': [0x10, {
            'OffsetToData': [0x00, ['RVAPointer', dict(
                        target="String",
                        target_args=dict(length=lambda x: x.Size))]],
            'Size': [0x04, ['unsigned int']],
            'CodePage': [0x08, ['unsigned int']],
            }],
    }

# _IMAGE_OPTIONAL_HEADER64 is the same as _IMAGE_OPTIONAL_HEADER but offsets are
# different
pe_overlays["_IMAGE_OPTIONAL_HEADER64"] = copy.deepcopy(
    pe_overlays["_IMAGE_OPTIONAL_HEADER"])


def RoundUp(offset):
    """Round up the next word boundary."""
    if offset % 4:
        offset += 4 - offset % 4

    return offset


def AlignAfter(name):
    def get_offset(x):
        x = getattr(x, name)
        end_of_object = x.obj_offset + x.size()

        return RoundUp(end_of_object)

    return get_offset


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
            'Name' : [ 0x0, ['String', {'length': 8, 'term': None}]],
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
            'VirtualAddress' : [ 0x0, ['RVAPointer', dict(target='unsigned int')]],
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

    # Note this is a problematic structure due to the alignment
    # requirements. Its not too much of a problem for the Volatility object
    # system though :-)

    # http://msdn.microsoft.com/en-us/library/windows/desktop/ms647001(v=vs.85).aspx
    'VS_VERSIONINFO': [0x06, {
            "Length": [0x00, ['unsigned short int']],
            "ValueLength": [0x02, ['unsigned short int']],
            "Type": [0x04, ["Enumeration", dict(
                        choices={
                            0: "Binary",
                            1: "Text",
                            },
                        target='unsigned short int')]],

            # Must be VS_VERSION_INFO\x00 in utf16
            "szKey": [0x06, ["UnicodeString", dict(length=32)]],

            # The member is 32bit aligned after the szKey member.
            "Value": [AlignAfter("szKey"), ["VS_FIXEDFILEINFO"]],

            # This member is also aligned after the Value member.
            "Children": [AlignAfter("Value"), ['ListArray', dict(
                        target="StringFileInfo",
                        maximum_offset=lambda x: x.Length + x.obj_offset)]],
            }],

    'VS_FIXEDFILEINFO': [0x34, {
            "Signature": [0x00, ['unsigned int']],
            "StructVersion": [0x04, ['unsigned int']],
            "FileVersionMS": [0x08, ['unsigned int']],
            "FileVersionLS": [0x0c, ['unsigned int']],
            "ProductVersionMS": [0x10, ['unsigned int']],
            "ProductVersionLS": [0x14, ['unsigned int']],
            "FileFlagsMask": [0x18, ['unsigned int']],
            "FileFlags": [0x1c, ['unsigned int']],
            "FileOS": [0x20, ["Flags", dict(
                        maskmap={
                            "VOS_DOS": 0x00010000,
                            "VOS_NT": 0x00040000,
                            "VOS__WINDOWS16": 0x00000001,
                            "VOS__WINDOWS32": 0x00000004,
                            },
                        target='unsigned int')]],
            "FileType": [0x24, ['Enumeration', dict(
                        choices={
                            1: "VFT_APP (Application)",
                            2: "VFT_DLL (DLL)",
                            3: "VFT_DRV (Driver)",
                            4: "VFT_FORT (Font)",
                            5: "VFT_VXD",
                            7: "VFT_STATIC_LIB",
                            },
                        target='unsigned int')]],
            "FileSubtype": [0x28, ['unsigned int']],
            "FileDateMS": [0x2c, ['unsigned int']],
            "FileDateLS": [0x30, ['unsigned int']],
            "FileDate": [0x2c, ['WinTimeStamp', {}]],
            }],

    # The size of this is given by the Length member.
    "StringFileInfo": [lambda x: RoundUp(x.Length), {
            "Length": [0x00, ['unsigned short int']],
            "ValueLength": [0x02, ['unsigned short int']],
            "Type": [0x04, ['unsigned short int']],

            # Must be "StringFileInfo"
            "Key": [0x06, ['UnicodeString', dict(length=28)]],

            "Children": [AlignAfter("Key"), ['ListArray', dict(
                        target='StringTable',
                        maximum_offset=lambda x: x.Length + x.obj_offset)]],
            }],

    # The size of this is given by the Length member.
    "VarFileInfo": [lambda x: RoundUp(x.Length), {
            "Length": [0x00, ['unsigned short int']],
            "ValueLength": [0x02, ['unsigned short int']],
            "Type": [0x04, ['unsigned short int']],

            # Must be "VarFileInfo"
            "Key": [0x06, ['UnicodeString', dict(length=24)]],

            "Children": [AlignAfter("Key"), ['ListArray', dict(
                        target='Var',
                        maximum_offset=lambda x: x.Length + x.obj_offset)]],
            }],

    # Round up the size of the struct to word alignment.
    "Var": [lambda x: RoundUp(x.Length), {
            "Length": [0x00, ['unsigned short int']],
            "ValueLength": [0x02, ['unsigned short int']],
            "Type": [0x04, ['unsigned short int']],

            # This is exactly Translation
            "Key": [0x06, ['UnicodeString', dict(length=24)]],

            "Value": [AlignAfter("Key"), ['String', dict(
                        length=lambda x: x.ValueLength, term=None)]],
            }],

    "StringTable": [lambda x: RoundUp(x.Length), {
            "Length": [0x00, ['unsigned short int']],
            "ValueLength": [0x02, ['unsigned short int']],
            "Type": [0x04, ['unsigned short int']],

            # In MSDN this is called szKey.
            "LangID": [0x06, ['UnicodeString', dict(length=16, term=None)]],

            "Children": [AlignAfter("LangID"), ['ListArray', dict(
                        target='ResourceString',
                        maximum_offset=lambda x: x.Length + x.obj_offset)]],
            }],

    # Round up the size of the struct to word alignment.
    "ResourceString": [lambda x: RoundUp(x.Length), {
            "Length": [0x00, ['unsigned short int']],
            "ValueLength": [0x02, ['unsigned short int']],
            "Type": [0x04, ['unsigned short int']],

            # This is a null terminated unicode string representing the key.
            "Key": [0x06, ['UnicodeString', dict(length=1024)]],

            "Value": [AlignAfter("Key"), ['UnicodeString', dict(
                        length=lambda x: x.ValueLength * 2)]],
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
            target = 'unsigned int', count = self.NumberOfFunctions,
            vm = self.obj_vm)

        # Array of RVAs to function names
        address_of_names = self.obj_profile.Object(
            'Array', offset = mod_base + self.AddressOfNames,
            target = 'unsigned int', count = self.NumberOfNames,
            vm = self.obj_vm)

        # Array of RVAs to function ordinals
        address_of_name_ordinals = self.obj_profile.Object(
            'Array', offset = mod_base + self.AddressOfNameOrdinals,
            target = 'unsigned short', count = self.NumberOfNames,
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
    def PE(self):
        return PE(address_space=self.obj_vm, image_base=self.DllBase)

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

    #Put checks in constructor.

    @property
    def NTHeader(self):
        """Get the NT header"""

        if self.e_magic != 0x5a4d:
            return obj.NoneObject('e_magic {0:04X} is not a valid DOS signature.'.format(
                    self.e_magic))

        nt_header = self.obj_profile.Object(theType="_IMAGE_NT_HEADERS",
                                            offset = self.e_lfanew + self.obj_offset,
                                            vm = self.obj_vm, context=self.obj_context)

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


class _IMAGE_DATA_DIRECTORY(obj.CType):
    """A data directory."""

    def dereference(self):
        """Automatically resolve the data directory according to our name."""
        result = self.m("VirtualAddress")

        if self.obj_name == "IMAGE_DIRECTORY_ENTRY_IMPORT":
            return result.dereference_as(
                "SentinalArray", target="_IMAGE_IMPORT_DESCRIPTOR")

        elif self.obj_name == "IMAGE_DIRECTORY_ENTRY_EXPORT":
            return result.dereference_as("_IMAGE_EXPORT_DIRECTORY")

        elif self.obj_name == "IMAGE_DIRECTORY_ENTRY_RESOURCE":
            return result.dereference_as("_IMAGE_RESOURCE_DIRECTORY")

        return result.dereference()


class _IMAGE_RESOURCE_DIRECTORY(obj.CType):
    """Represents a node in the resource tree."""

    def __iter__(self):
        for entry in self.Entries:
            yield entry

    def Open(self, node_name):
        """Opens a specific node child."""
        for entry in self.Entries:
            if entry.Name == node_name:
                return entry.Entry

        return obj.NoneObject("node %s not found" % node_name)

    def Traverse(self):
        """A generator for _IMAGE_RESOURCE_DATA_ENTRY under this node."""
        for entry in self:
            if entry.ChildIsEntry:
                for subentry in entry.Entry.Traverse():
                    yield subentry
            else:
                yield entry.OffsetToData.dereference()


class _IMAGE_RESOURCE_DIRECTORY_ENTRY(obj.CType):

    @property
    def Name(self):
        if self.NameIsString:
            return utils.SmartUnicode(self.m("Name").Buffer)
        else:
            return utils.SmartUnicode(self.Type)

    @property
    def Entry(self):
        if self.ChildIsEntry:
            return self.m("Entry").dereference()
        else:
            return self.m("OffsetToData")


class ThunkArray(SentinalArray):
    """A sential terminated array of thunks."""

    def __init__(self, parent=None, **kwargs):
        target="_IMAGE_THUNK_DATA"

        # Are we in a 64 bit file?
        for x in parent.parents:
            if x.obj_name.endswith("64"):
                target += "64"
                break

        super(ThunkArray, self).__init__(target=target, parent=parent,
                                         **kwargs)

class VS_VERSIONINFO(obj.CType):

    @property
    def Children(self):
        """The child is either a StringFileInfo or VarFileInfo depending on the key."""
        for child in self.m("Children"):
            if child.Key.startswith("VarFileInfo"):
                yield child.cast("VarFileInfo")
            elif child.Key.startswith("StringFileInfo"):
                yield child
            else:
                break

    def Strings(self, obj=None):
        """Generates all the ResourceString structs by recursively traversing
        the Children tree.
        """
        if obj is None:
            obj = self

        for child in obj.Children:
            try:
                for subchild in self.Strings(child):
                    yield subchild
            except AttributeError:
                yield child



class PE(object):
    """A convenience object to access various things in a PE file."""

    def __init__(self, address_space=None, image_base=0, filename=None):
        """Constructor.

        Args:
          address_space: An address space to examine.

          image_base: The address of the dos header.

          filename: If a filename is provided we open the file as a PE File. In
            this case, image_base and address_space are ignored.
        """
        self.profile = PEProfile()

        if filename is None:
            self.vm = address_space
            self.image_base = image_base
        else:
            file_address_space = PEFileAddressSpace.classes[
                'FileAddressSpace'](filename=filename)
            self.vm = PEFileAddressSpace(base=file_address_space)
            self.image_base = self.vm.image_base

        self.dos_header = self.profile.Object(
            "_IMAGE_DOS_HEADER", vm=self.vm, offset=self.image_base,
            context=dict(image_base=self.image_base))

        self.nt_header = self.dos_header.NTHeader

    def ImportDirectory(self):
        """A generator over the import directory.

        Note that this iterates over the OriginalFirstThunk which still remains
        from the on-disk executable. The IAT is constructed by the linker at
        load time, and is stored in FirstThunk in memory. Hence the IAT() method
        is going to return code objects while this method simply returns names.

        Yields:
           a tuple of (dll, function_name)
        """
        import_directory = self.nt_header.OptionalHeader.DataDirectory[
            'IMAGE_DIRECTORY_ENTRY_IMPORT'].dereference()

        for directory in import_directory:
            dll = directory.Name.dereference()
            for thunk in directory.OriginalFirstThunk.dereference():
                function_name = thunk.AddressOfData.Name

                yield dll, function_name, thunk.AddressOfData.Hint

    def IAT(self):
        """A generator over the IAT.

        Note that this iterates over the FirstThunk imports. In memory, these
        contain the IAT which has been resolved by the loader.

        Yields:
          a tuple of (dll, function_name)
        """
        import_directory = self.nt_header.OptionalHeader.DataDirectory[
            'IMAGE_DIRECTORY_ENTRY_IMPORT'].dereference()

        for directory in import_directory:
            dll = directory.Name.dereference()
            for thunk in directory.FirstThunk.dereference():
                function = thunk.Function

                yield dll, function, thunk.Ordinal

    def ExportDirectory(self):
        """A generator over the export directory."""
        export_directory = self.nt_header.OptionalHeader.DataDirectory[
            'IMAGE_DIRECTORY_ENTRY_EXPORT'].dereference()

        dll = export_directory.Name.dereference()
        function_table = export_directory.AddressOfFunctions.dereference()
        name_table = export_directory.AddressOfNames.dereference()
        ordinal_table = export_directory.AddressOfNameOrdinals.dereference()

        seen_ordinals = set()

        # First do the names.
        for i, name in enumerate(name_table):
            ordinal = int(ordinal_table[i])
            seen_ordinals.add(ordinal)

            yield (dll, function_table[ordinal].dereference(),
                   name.dereference(), ordinal)

        # Now the functions without names
        for i, func in enumerate(function_table):
            ordinal = export_directory.Base + i
            if ordinal in seen_ordinals:
                continue

            yield (dll, function_table[ordinal].dereference(),
                   obj.NoneObject("Name not accessible"), ordinal)

    def GetProcAddress(self, name):
        """Scan the export table for a function of the given name.

        Similar to the GetProcAddress function.
        """
        for dll, function, func_name, ordinal in self.ExportDirectory():
            if func_name == name:
                return function

    def VersionInformation(self):
        """A generator of key, value pairs."""
        resource_directory = self.nt_header.OptionalHeader.DataDirectory[
            'IMAGE_DIRECTORY_ENTRY_RESOURCE'].dereference()

        # Find all the versions and their strings
        for data in resource_directory.Open("RT_VERSION").Traverse():
            version_info = data.OffsetToData.dereference_as("VS_VERSIONINFO")
            for string in version_info.Strings():
                yield string.Key, string.Value

    def Sections(self):
        for section in self.nt_header.Sections:

            execution_flags = "%s%s%s" % (
                "x" if section.Characteristics.IMAGE_SCN_MEM_EXECUTE else "-",
                "r" if section.Characteristics.IMAGE_SCN_MEM_READ else "-",
                "w" if section.Characteristics.IMAGE_SCN_MEM_WRITE else "-")

            yield (execution_flags, section.Name, section.VirtualAddress,
                   section.SizeOfRawData)


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
                '_IMAGE_DATA_DIRECTORY': _IMAGE_DATA_DIRECTORY,
                "IndexedArray": IndexedArray,
                "SentinalArray": SentinalArray,
                "ThunkArray": ThunkArray,
                "RVAPointer": RVAPointer,
                "ResourcePointer": ResourcePointer,
                "_IMAGE_RESOURCE_DIRECTORY": _IMAGE_RESOURCE_DIRECTORY,
                "_IMAGE_RESOURCE_DIRECTORY_ENTRY": _IMAGE_RESOURCE_DIRECTORY_ENTRY,
                "VS_VERSIONINFO": VS_VERSIONINFO,
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
    See http://code.google.com/p/corkami/downloads/detail?name=pe-20110117.pdf

    The PE file is divided into sections, each section is mapped into memory at
    a different place:

    File on Disk                 Memory Image
0-> ------------    image base-> ------------
     Header                      Header
    ------------                 ------------
     Section 1
    ------------                 ------------
     Section 2                    Section 1
    ------------                 ------------

                                 ------------
                                  Section 2
                                 ------------

    This address space expands the file from disk into the memory image view as
    shown. Since all internal pe RVA references are within the virtual space,
    this helps resolution.
    """
    def __init__(self, **kwargs):
        """We layer on top of the file address space."""
        super(PEFileAddressSpace, self).__init__(**kwargs)

        self.as_assert(self.base is not None, "Must layer on another AS.")
        self.as_assert(self.base.read(0, 2) == "MZ", "File does not have a PE signature.")
        self.profile = PEProfile()

        nt_header = self.profile.Object(
            "_IMAGE_DOS_HEADER", vm=self.base, offset=0).NTHeader

        self.image_base = int(nt_header.OptionalHeader.ImageBase)
        # Now map all the sections into a virtual address space.
        self.runs = []

        # The first run maps the file header over the base address
        self.runs.append(
            (self.image_base, nt_header.OptionalHeader.SizeOfHeaders, 0))

        for section in nt_header.Sections:
            virtual_address = section.VirtualAddress.v() + self.image_base
            self.runs.append(
                (virtual_address, section.SizeOfRawData.v(), section.PointerToRawData.v()))

        # TODO: The sections may overlap: What to do then?
        # Make sure that the sections are sorted.
        self.runs.sort()

        self.nt_header = self.profile.Object(
            "_IMAGE_DOS_HEADER", vm=self, offset=self.image_base,
            context=dict(image_base=0)).NTHeader

    def read(self, addr, length):
        # Not a particularly efficient algorithm, but probably fast enough since
        # usually there are not too many sections.
        for virtual_address, run_length, physical_address in self.runs:
            if addr >= virtual_address and addr <= virtual_address + run_length:
                offset = addr - virtual_address
                to_read = min(run_length - offset, length)

                return self.base.read(physical_address + offset, to_read)

        # Otherwise just null pad the results.
        return '\x00' * length
