# Rekall Memory Forensics
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
# Copyright (c) 2010, 2011, 2012 Michael Ligh <michael.ligh@mnin.org>
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

# pylint: disable=protected-access

"""References:
http://msdn.microsoft.com/en-us/magazine/ms809762.aspx
http://msdn.microsoft.com/en-us/magazine/cc301805.aspx
http://code.google.com/p/corkami/downloads/detail?name=pe-20110117.pdf
http://code.google.com/p/pefile/

Version information:
http://msdn.microsoft.com/en-us/library/windows/desktop/ff468916(v=vs.85).aspx
"""
import copy
import re

from rekall import addrspace
from rekall import obj
from rekall import utils

from rekall.plugins.addrspaces import standard
from rekall.plugins.overlays import basic


class SentinelArray(obj.Array):
    """A sential terminated array."""

    def __init__(self, max_count=100000, **kwargs):
        # The size of this array is determined by the sentinel.
        super(SentinelArray, self).__init__(
            count=max_count, max_count=max_count, **kwargs)

    def __iter__(self):
        """Break when the sentinel is reached."""
        for member in super(SentinelArray, self).__iter__():
            data = member.obj_vm.read(member.obj_offset, member.obj_size)
            if data == "\x00" * member.obj_size:
                break

            yield member


class SentinelListArray(SentinelArray, obj.ListArray):
    """A variable sized array with a sentinel termination."""


class RVAPointer(obj.Pointer):
    """A pointer through a relative virtual address."""
    image_base = 0
    def __init__(self, image_base=None, **kwargs):
        super(RVAPointer, self).__init__(**kwargs)
        self.image_base = image_base or self.obj_context.get("image_base", 0)
        if callable(self.image_base):
            self.image_base = self.image_base(self.obj_parent)

        # RVA pointers are always 32 bits - even on 64 bit systems.
        self._proxy = self.obj_profile.Object(
            "unsigned int", offset=self.obj_offset, vm=self.obj_vm,
            context=self.obj_context)

    def v(self, vm=None):
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
        self.resource_base = (resource_base or
                              self.obj_context.get("resource_base"))

        if self.resource_base is None:
            for parent in self.parents:
                if isinstance(parent, _IMAGE_NT_HEADERS):
                    for section in parent.Sections:
                        if section.Name.startswith(".rsrc"):
                            self.resource_base = (
                                section.VirtualAddress +
                                parent.OptionalHeader.ImageBase)
                            self.obj_context[
                                'resource_base'] = self.resource_base
                            break

    def v(self, vm=None):
        # Only the first 31 bits are meaningful.
        resource_pointer = int(
            super(ResourcePointer, self).v()) & ((1 << 31) - 1)
        if resource_pointer:
            resource_pointer += self.resource_base

        return resource_pointer


def RoundUpToWordAlignment(offset):
    """Round up the next word boundary."""
    if offset % 4:
        offset += 4 - offset % 4

    return offset


def AlignAfter(name):
    """Align a Struct's member after another member.

    Produce a callable which returns the next aligned offset after the member of
    the required name in this struct. This callable is suitable to be specified
    in the overlay's offset field.
    """
    def get_offset(x):
        x = getattr(x, name)
        end_of_object = x.obj_offset + x.obj_size

        return RoundUpToWordAlignment(end_of_object)

    return get_offset


pe_overlays = {
    "_IMAGE_OPTIONAL_HEADER": [None, {
        'Subsystem' : [None, ['Enumeration', {
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
        'Machine' : [None, ['Enumeration', {
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

        'Characteristics' : [None, ['Flags', {
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
        'TimeDateStamp' : [None, ['UnixTimeStamp', {}]],
        }],

    "_IMAGE_SECTION_HEADER": [None, {
        'Name' : [None, ['String', {'length': 8, 'term': None}]],
        'Characteristics' : [None, ['Flags', {
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

        'execution_flags': lambda x: "%s%s%s" % (
                "x" if x.Characteristics.IMAGE_SCN_MEM_EXECUTE else "-",
                "r" if x.Characteristics.IMAGE_SCN_MEM_READ else "-",
                "w" if x.Characteristics.IMAGE_SCN_MEM_WRITE else "-")
        }],

    "_IMAGE_IMPORT_DESCRIPTOR": [None, {
        'Name': [None, ['RVAPointer', dict(
            target="String",
            target_args=dict(length=128))]],

        'TimeDateStamp': [None, ['UnixTimeStamp', {}]],

        # This is an RVA pointer to an array of _IMAGE_THUNK_DATA32 structs.
        'FirstThunk': [None, ['RVAPointer', dict(target="ThunkArray")]],

        # This is a copy of the original IAT in memory.
        'OriginalFirstThunk': [None, ['RVAPointer', dict(
            target="ThunkArray"
            )]],
        }],

    "_IMAGE_EXPORT_DIRECTORY": [None, {
        'Name': [None, ['RVAPointer', dict(
            target="String",
            target_args=dict(length=128)
            )]],

        'AddressOfFunctions': [None, ['RVAPointer', dict(
            target="Array",
            target_args=dict(
                target="RVAPointer",
                target_args=dict(target="Function"),
                count=lambda x: x.NumberOfFunctions,
                )
            )]],

        'AddressOfNames': [None, ["RVAPointer", dict(
            target="Array",
            target_args=dict(
                target="RVAPointer",
                target_args=dict(target="String"),
                count=lambda x: x.NumberOfNames,
                )
            )]],

        'AddressOfNameOrdinals': [None, ['RVAPointer', dict(
            target="Array",
            target_args=dict(
                target="unsigned short int",
                count=lambda x: x.NumberOfFunctions)
            )]],
        }],

    "_IMAGE_THUNK_DATA32": [None, {
        'AddressOfData' : [0x0, ['RVAPointer', dict(
            target="_IMAGE_IMPORT_BY_NAME"
            )]],
        }],

    "_IMAGE_NT_HEADERS": [None, {
        # This is a psuedo member to give access to the sections.
        "Sections": [
            # The sections start immediately after the OptionalHeader:
            lambda x: (x.FileHeader.SizeOfOptionalHeader +
                       x.OptionalHeader.obj_offset),

            # The sections are an array of _IMAGE_SECTION_HEADER structs.
            # The number of sections is found in the FileHeader
            ['Array', dict(
                target="_IMAGE_SECTION_HEADER",
                count=lambda x: x.FileHeader.NumberOfSections,
                )]],
        }],

    "_IMAGE_RESOURCE_DIRECTORY": [None, {
        "Entries": [0x10, ["Array", dict(
            target="_IMAGE_RESOURCE_DIRECTORY_ENTRY",
            count=lambda x: (x.NumberOfIdEntries +
                             x.NumberOfNamedEntries),
            )]],
        }],

    "_IMAGE_RESOURCE_DIRECTORY_ENTRY": [None, {
        "Name": [None, ['ResourcePointer', dict(target="PrefixedString")]],
        "Type": [0, ["Enumeration", dict(choices={
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
        "OffsetToDataInt": [0x04, ['unsigned int']],
        "OffsetToData": [0x04, ['ResourcePointer', dict(
            target="_IMAGE_RESOURCE_DATA_ENTRY",
            )]],
        "Entry": [0x04, ['ResourcePointer', dict(
            target="_IMAGE_RESOURCE_DIRECTORY")]],

        # If this is set the child is another
        # _IMAGE_RESOURCE_DIRECTORY_ENTRY
        "ChildIsEntry": [0x04, ['BitField', dict(
            start_bit=31,
            end_bit=32,
            )]],
        }],

    'PrefixedString' : [0x02, {
        'Length' : [0x0, ['unsigned short']],
        'Buffer' : [0x2, ['UnicodeString', dict(
            length=lambda x: x.Length * 2 + 1,
            )]],
        }],

    '_IMAGE_RESOURCE_DATA_ENTRY': [0x10, {
        'OffsetToData': [0x00, ['RVAPointer', dict(
            target="String",
            target_args=dict(length=lambda x: x.Size))]],
        'Size': [0x04, ['unsigned int']],
        'CodePage': [0x08, ['unsigned int']],
        }],

    '_IMAGE_IMPORT_BY_NAME' : [None, {
        'Name' : [None, ['String', dict(length=128)]],
        }],

    '_IMAGE_DATA_DIRECTORY' : [None, {
        'VirtualAddress' : [None, ['RVAPointer', dict(
            target='unsigned int'
            )]],
        }],

    '_IMAGE_DEBUG_DIRECTORY': [None, {
        "AddressOfRawData": [20, ["RVAPointer", dict(
            # We only support CV_RSDS_HEADER for XP+
            target="CV_RSDS_HEADER",
            )]],
        "TimeDateStamp": [0x4, ["UnixTimeStamp"]],
        "Type": [12, ["Enumeration", dict(
            choices={
                0: "IMAGE_DEBUG_TYPE_UNKNOWN",
                1: "IMAGE_DEBUG_TYPE_COFF",
                2: "IMAGE_DEBUG_TYPE_CODEVIEW",
                3: "IMAGE_DEBUG_TYPE_FPO",
                4: "IMAGE_DEBUG_TYPE_MISC",
                5: "IMAGE_DEBUG_TYPE_EXCEPTION",
                6: "IMAGE_DEBUG_TYPE_FIXUP",
                7: "IMAGE_DEBUG_TYPE_OMAP_TO_SRC",
                8: "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC",
                9: "IMAGE_DEBUG_TYPE_BORLAND",
                10: "IMAGE_DEBUG_TYPE_RESERVED",
                },
            target="unsigned int",
            )]],
        }],

    "_GUID": [16, {
        "Data4": [8, ["String", dict(length=8, term=None)]],
        "AsString": lambda x: ("%08x%04x%04x%s" % (
            x.Data1, x.Data2, x.Data3, x.Data4.v().encode('hex'))).upper(),
        }],

    # This struct is reversed.
    'CV_RSDS_HEADER': [None, {
        "Signature": [0, ["String", dict(length=4)]],
        "GUID": [4, ["_GUID"]],
        "GUID_AGE": lambda x: "%s%X" % (x.GUID.AsString, x.Age),
        "Age": [20, ["unsigned int"]],
        "Filename": [24, ["String"]],
        }],

    '_IMAGE_THUNK_DATA64' : [None, {
        'AddressOfData' : [0, ['RVAPointer', dict(
            target="_IMAGE_IMPORT_BY_NAME"
            )]],

        # Fake member for testing if the highest bit is set
        'OrdinalBit' : [0, ['BitField', dict(
            start_bit=63,
            end_bit=64
            )]],

        }],

    'tagVS_FIXEDFILEINFO': [None, {
        "dwFileOS": [None, ["Flags", dict(
            maskmap={
                "VOS_DOS": 0x00010000,
                "VOS_NT": 0x00040000,
                "VOS__WINDOWS16": 0x00000001,
                "VOS__WINDOWS32": 0x00000004,
                },
            target='unsigned int')]],
        "dwFileType": [None, ['Enumeration', dict(
            choices={
                1: "VFT_APP (Application)",
                2: "VFT_DLL (DLL)",
                3: "VFT_DRV (Driver)",
                4: "VFT_FORT (Font)",
                5: "VFT_VXD",
                7: "VFT_STATIC_LIB",
                },
            target='unsigned int')]],
        "dwFileDate": [lambda x: x.m("dwFileDateLS").obj_offset,
                       ['WinFileTime', {}]],
        }],

    # The size of this is given by the Length member.
    "StringFileInfo": [lambda x: RoundUpToWordAlignment(x.Length), {
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
    "VarFileInfo": [lambda x: RoundUpToWordAlignment(x.Length), {
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
    "Var": [lambda x: RoundUpToWordAlignment(x.Length), {
        "Length": [0x00, ['unsigned short int']],
        "ValueLength": [0x02, ['unsigned short int']],
        "Type": [0x04, ['unsigned short int']],

        # This is exactly Translation
        "Key": [0x06, ['UnicodeString', dict(length=24)]],

        "Value": [AlignAfter("Key"), ['String', dict(
            length=lambda x: x.ValueLength, term=None)]],
        }],

    "StringTable": [lambda x: RoundUpToWordAlignment(x.Length), {
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
    "ResourceString": [lambda x: RoundUpToWordAlignment(x.Length), {
        "Length": [0x00, ['unsigned short int']],
        "ValueLength": [0x02, ['unsigned short int']],
        "Type": [0x04, ['unsigned short int']],

        # This is a null terminated unicode string representing the key.
        "Key": [0x06, ['UnicodeString', dict(length=1024)]],

        "Value": [AlignAfter("Key"), ['UnicodeString', dict(
            length=lambda x: x.ValueLength * 2)]],
        }],

    # Note this is a problematic structure due to the alignment
    # requirements. Its not too much of a problem for the Rekall Memory
    # Forensics object system though :-)

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
        "Value": [AlignAfter("szKey"), ["tagVS_FIXEDFILEINFO"]],

        # This member is also aligned after the Value member.
        "Children": [AlignAfter("Value"), ['ListArray', dict(
            target="StringFileInfo",
            maximum_offset=lambda x: x.Length + x.obj_offset)]],
        }],
    }

# _IMAGE_OPTIONAL_HEADER64 is the same as _IMAGE_OPTIONAL_HEADER but offsets are
# different
pe_overlays["_IMAGE_OPTIONAL_HEADER64"] = copy.deepcopy(
    pe_overlays["_IMAGE_OPTIONAL_HEADER"])

class _LDR_DATA_TABLE_ENTRY(obj.Struct):
    """
    Class for PE file / modules

    If these classes are instantiated by _EPROCESS.list_*_modules()
    then its guaranteed to be in the process address space.
    """
    _pe = None

    @utils.safe_property
    def PE(self):
        if self._pe is None:
            self._pe = PE(address_space=self.obj_vm, image_base=self.DllBase,
                          session=self.obj_session)

        return self._pe

    @utils.safe_property
    def NTHeader(self):
        """Return the _IMAGE_NT_HEADERS object"""

        dos_header = self.obj_profile._IMAGE_DOS_HEADER(
            self.DllBase.v(), vm=self.obj_vm)

        return dos_header.NTHeader


class _IMAGE_DOS_HEADER(obj.Struct):
    """DOS header"""

    #Put checks in constructor.

    @utils.safe_property
    def NTHeader(self):
        """Get the NT header"""
        if self.e_magic != 0x5a4d:
            return obj.NoneObject(
                'e_magic {0:04X} is not a valid DOS signature.'.format(
                    self.e_magic or 0))

        nt_header = self.obj_profile._IMAGE_NT_HEADERS(
            offset=self.e_lfanew + self.obj_offset,
            vm=self.obj_vm, context=self.obj_context)

        if nt_header.Signature != 0x4550:
            return obj.NoneObject(
                'NT header signature {0:04X} is not a valid'.format(
                    nt_header.Signature or 0))

        return nt_header


class _IMAGE_NT_HEADERS(obj.Struct):
    """PE header"""

    @utils.safe_property
    def OptionalHeader(self):
        optional_header = self.m("OptionalHeader")
        if optional_header.Magic == 0x20b:
            self.obj_context["mode"] = "AMD64"
            return optional_header.cast("_IMAGE_OPTIONAL_HEADER64")

        self.obj_context["mode"] = "I386"
        return optional_header


class _IMAGE_SECTION_HEADER(obj.Struct):
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


class _IMAGE_DATA_DIRECTORY(obj.Struct):
    """A data directory."""

    def dereference(self, vm=None):
        """Automatically resolve the data directory according to our name."""
        result = self.m("VirtualAddress")

        if self.obj_name == "IMAGE_DIRECTORY_ENTRY_IMPORT":
            return result.dereference_as(
                target="SentinelArray", target_args=dict(
                    target="_IMAGE_IMPORT_DESCRIPTOR"
                    ),
                vm=vm,
                )

        elif self.obj_name == "IMAGE_DIRECTORY_ENTRY_EXPORT":
            return result.dereference_as("_IMAGE_EXPORT_DIRECTORY", vm=vm)

        elif self.obj_name == "IMAGE_DIRECTORY_ENTRY_RESOURCE":
            return result.dereference_as("_IMAGE_RESOURCE_DIRECTORY", vm=vm)

        return result.dereference(vm=vm)


class _IMAGE_RESOURCE_DIRECTORY(obj.Struct):
    """Represents a node in the resource tree."""

    def __iter__(self):
        for entry in self.Entries:
            yield entry

    def Open(self, node_name):
        """Opens a specific node child."""
        for entry in self.Entries:
            if entry.Name == node_name or entry.Type == node_name:
                return entry.Entry

            if entry.Type == 0:
                break

        return obj.NoneObject("node %s not found" % node_name)

    def Traverse(self):
        """A generator for _IMAGE_RESOURCE_DATA_ENTRY under this node."""
        for entry in self:
            if entry.ChildIsEntry:
                for subentry in entry.Entry.Traverse():
                    yield subentry
            else:
                yield entry.OffsetToData.dereference()


class _IMAGE_RESOURCE_DIRECTORY_ENTRY(obj.Struct):

    @utils.safe_property
    def Name(self):
        if self.NameIsString:
            return utils.SmartUnicode(self.m("Name").Buffer)
        else:
            return utils.SmartUnicode(self.Type)

    @utils.safe_property
    def Entry(self):
        if self.ChildIsEntry:
            return self.m("Entry").dereference()
        else:
            return self.m("OffsetToData")


class ThunkArray(SentinelArray):
    """A sential terminated array of thunks."""

    def __init__(self, parent=None, context=None, **kwargs):
        # Are we in a 64 bit file?
        if context.get("mode") == "AMD64":
            target = "_IMAGE_THUNK_DATA64"
        else:
            target = "_IMAGE_THUNK_DATA32"

        super(ThunkArray, self).__init__(
            target=target, parent=parent, context=context, **kwargs)

class VS_VERSIONINFO(obj.Struct):

    @utils.safe_property
    def Children(self):
        """Get all the children of this node.

        The child is either a StringFileInfo or VarFileInfo depending on the
        key."""
        for child in self.m("Children"):
            if child.Key.startswith("VarFileInfo"):
                yield child.cast("VarFileInfo")
            elif child.Key.startswith("StringFileInfo"):
                yield child
            else:
                break

    def Strings(self, item=None):
        """Generates all the ResourceString structs by recursively traversing
        the Children tree.
        """
        if item is None:
            item = self

        for child in item.Children:
            try:
                for subchild in self.Strings(child):
                    yield subchild
            except AttributeError:
                yield child



class PE(object):
    """A convenience object to access PE file information."""

    def __init__(self, address_space=None, image_base=0, filename=None,
                 session=None):
        """Constructor.

        Args:
          address_space: An address space to examine.

          image_base: The address of the dos header in the virtual address
            space.

          filename: If a filename is provided we open the file as a PE File. In
            this case, image_base and address_space are ignored.
        """
        self.session = session
        if session is None:
            raise RuntimeError("Session must be provided.")

        # Use the session to load the pe profile.
        self.profile = self.session.LoadProfile("pe")

        # If neither filename or address_space were provided we just get the
        # session default.
        if filename is None and address_space is None:
            address_space = self.session.GetParameter("default_address_space")
            if address_space == None:
                raise IOError("Filename or address_space not specified.")

            self.vm = address_space
            self.image_base = image_base

        elif address_space:
            # Resolve the correct address space. This allows the address space
            # to be specified from the command line (e.g. "P")
            load_as = self.session.plugins.load_as(session=self.session)
            address_space = load_as.ResolveAddressSpace(address_space)

            self.vm = address_space
            self.image_base = image_base
            if self.image_base == None:
                raise RuntimeError("Image base is invalid.")

        else:
            file_address_space = standard.FileAddressSpace(
                filename=filename, session=self.session)

            self.vm = PEFileAddressSpace(
                base=file_address_space, session=self.session)

            self.image_base = self.vm.image_base

        self.dos_header = self.profile.Object(
            "_IMAGE_DOS_HEADER", vm=self.vm, offset=self.image_base,
            context=dict(image_base=self.image_base))

        self.nt_header = self.dos_header.NTHeader

    @utils.safe_property
    def RSDS(self):
        return self.nt_header.OptionalHeader.DataDirectory[
            "IMAGE_DIRECTORY_ENTRY_DEBUG"].VirtualAddress.dereference_as(
                "_IMAGE_DEBUG_DIRECTORY").AddressOfRawData

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
                function = thunk.u1.Function

                yield dll, function, thunk.u1.Ordinal

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
            func = function_table[ordinal]
            func.obj_name = "%s:%s" % (dll, name.dereference())

            yield (dll, func, name.dereference(), ordinal)

        # Now the functions without names
        for i, func in enumerate(function_table):
            ordinal = export_directory.Base + i
            if ordinal in seen_ordinals:
                continue

            yield (dll, function_table[ordinal],
                   obj.NoneObject("Name not accessible"), ordinal)

    def GetProcAddress(self, name):
        """Scan the export table for a function of the given name.

        Similar to the GetProcAddress function.
        """
        for _, function_pointer, func_name, _ in self.ExportDirectory():
            if func_name == name:
                return function_pointer.dereference()

    def VersionInformation(self):
        """A generator of key, value pairs."""
        resource_directory = self.nt_header.OptionalHeader.DataDirectory[
            'IMAGE_DIRECTORY_ENTRY_RESOURCE'].dereference()

        # Find all the versions and their strings
        for data in resource_directory.Open("RT_VERSION").Traverse():
            version_info = data.OffsetToData.dereference_as(
                "VS_VERSIONINFO")

            for string in version_info.Strings():
                yield unicode(string.Key), unicode(string.Value)

    def VersionInformationDict(self):
        return dict(self.VersionInformation())

    def Sections(self):
        for section in self.nt_header.Sections:
            yield (section.execution_flags, section.Name, section.VirtualAddress,
                   section.SizeOfRawData)


class PEProfile(basic.BasicClasses):
    """A profile for PE files.

    This profile is available from the repository under the name "pe".
    """

    @classmethod
    def Initialize(cls, profile):
        super(PEProfile, cls).Initialize(profile)
        if not profile.has_class("unsigned int"):
            basic.ProfileLLP64.Initialize(profile)

        profile.add_classes({
            '_IMAGE_DOS_HEADER': _IMAGE_DOS_HEADER,
            '_IMAGE_NT_HEADERS': _IMAGE_NT_HEADERS,
            '_IMAGE_SECTION_HEADER': _IMAGE_SECTION_HEADER,
            '_LDR_DATA_TABLE_ENTRY': _LDR_DATA_TABLE_ENTRY,
            '_IMAGE_DATA_DIRECTORY': _IMAGE_DATA_DIRECTORY,
            "SentinelArray": SentinelArray,
            "ThunkArray": ThunkArray,
            "RVAPointer": RVAPointer,
            "ResourcePointer": ResourcePointer,
            "_IMAGE_RESOURCE_DIRECTORY": _IMAGE_RESOURCE_DIRECTORY,
            "_IMAGE_RESOURCE_DIRECTORY_ENTRY": _IMAGE_RESOURCE_DIRECTORY_ENTRY,
            "VS_VERSIONINFO": VS_VERSIONINFO,
            })
        profile.add_overlay(pe_overlays)


class PEFileAddressSpace(addrspace.RunBasedAddressSpace):
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
        self.as_assert(self.base.read(0, 2) == "MZ",
                       "File does not have a valid signature for a PE file.")

        self.profile = self.session.LoadProfile("pe")

        nt_header = self.profile._IMAGE_DOS_HEADER(vm=self.base).NTHeader
        self.image_base = obj.Pointer.integer_to_address(
            nt_header.OptionalHeader.ImageBase)

        # The first run maps the file header over the base address
        self.add_run(self.image_base, 0, nt_header.OptionalHeader.SizeOfHeaders)

        for section in nt_header.Sections:
            length = section.SizeOfRawData.v()
            if length > 0:
                virtual_address = section.VirtualAddress.v() + self.image_base
                file_offset = section.PointerToRawData.v()
                self.add_run(virtual_address, file_offset, length)

        # The real nt header is based at the virtual address of the image.
        self.nt_header = self.profile._IMAGE_DOS_HEADER(
            vm=self, offset=self.image_base,
            context=dict(image_base=self.image_base)).NTHeader

    def __str__(self):
        return "<PEFileAddressSpace @ %#x >" % self.image_base


class Demangler(object):
    """A utility class to demangle VC++ names.

    This is not a complete or accurate demangler, it simply extract the name and
    strips out args etc.

    Ref:
    http://www.kegel.com/mangle.html
    """
    STRING_MANGLE_MAP = {
        "^0": ",",
        "^2": r"\\",
        "^4": ".",
        "^3": ":",
        "^5": "_",  # Really space.
        "^6": ".",  # Really \n.
        r"\$AA": "",
        r"\$AN": "", # Really \r.
        r"\$CF": "%",
        r"\$EA": "@",
        r"\$CD": "#",
        r"\$CG": "&",
        r"\$HO": "~",
        r"\$CI": "(",
        r"\$CJ": ")",
        r"\$DM1": "</",
        r"\$DMO": ">",
        r"\$DN": "=",
        r"\$CK": "*",
        r"\$CB": "!",

        }

    def __init__(self, metadata):
        self._metadata = metadata

    def _UnpackMangledString(self, string):
        string = string.split("@")[3]

        result = []
        for cap in string.split("?"):
            for k, v in self.STRING_MANGLE_MAP.items():
                cap = re.sub(k, v, cap)

            result.append(cap)

        return "str:" + "".join(result).strip()

    SIMPLE_X86_CALL = re.compile(r"[_@]([A-Za-z0-9_]+)@(\d{1,3})$")
    FUNCTION_NAME_RE = re.compile(r"\?([A-Za-z0-9_]+)@")
    def DemangleName(self, mangled_name):
        """Returns the de-mangled name.

        At this stage we don't really do proper demangling since we usually dont
        care about the prototype, nor c++ exports. In the future we should
        though.
        """
        m = self.SIMPLE_X86_CALL.match(mangled_name)
        if m:
            # If we see x86 name mangling (_cdecl, __stdcall) with stack sizes
            # of 4 bytes, this is definitely a 32 bit pdb. Sometimes we dont
            # know the architecture of the pdb file for example if we do not
            # have the original binary, but only the GUID as extracted by
            # version_scan.
            if m.group(2) in ["4", "12"]:
                self._metadata.setdefault("arch", "I386")

            return m.group(1)

        m = self.FUNCTION_NAME_RE.match(mangled_name)
        if m:
            return m.group(1)

        # Strip the first _ from the name. I386 mangled constants have a
        # leading _ but their AMD64 counterparts do not.
        if mangled_name and mangled_name[0] in "_.":
            mangled_name = mangled_name[1:]

        elif mangled_name.startswith("??_C@"):
            return self._UnpackMangledString(mangled_name)

        return mangled_name


class BasicPEProfile(basic.RelativeOffsetMixin, basic.BasicClasses):
    """A basic profile for a pe image.

    This profile deals with Microsoft Oddities like name mangling, and
    correcting global offsets to the base image address.
    """

    image_base = 0

    METADATA = dict(os="windows")

    def GetImageBase(self):
        return self.image_base

    def add_constants(self, constants=None, **opts):
        """Add the demangled constants.

        This allows us to handle 32 bit vs 64 bit constant names easily since
        the mangling rules are different.
        """
        demangler = Demangler(self._metadata)
        result = {}

        for k, v in constants.iteritems():
            result[demangler.DemangleName(k)] = v

        super(BasicPEProfile, self).add_constants(
            constants=result, **opts)

    def copy(self):
        result = super(BasicPEProfile, self).copy()
        result.image_base = self.image_base
        return result

    @classmethod
    def Initialize(cls, profile):
        super(BasicPEProfile, cls).Initialize(profile)

        # If the architecture is not added yet default to 64 bit. NOTE that with
        # PE Profiles we normally guess the architecture based on the name
        # mangling conventions.
        if profile.metadata("arch") is None:
            profile.set_metadata("arch", "AMD64")

        # Add the basic compiler model for windows.
        if profile.metadata("arch") == "AMD64":
            basic.ProfileLLP64.Initialize(profile)

        elif profile.metadata("arch") == "I386":
            basic.Profile32Bits.Initialize(profile)
