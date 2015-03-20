# Rekall Memory Forensics
# Copyright (C) 2012 Michael Cohen <scudette@users.sourceforge.net>
# Copyright (c) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
# Copyright 2014 Google Inc. All Rights Reserved.
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

"""Common windows overlays and classes."""
import logging
import struct
from rekall import addrspace
from rekall import obj
from rekall import utils

from rekall.plugins.overlays.windows import pe_vtypes
from rekall.plugins.overlays.windows import undocumented


MM_PROTECTION_ENUM = utils.EnumerationFromDefines("""
//
00098 // Protection Bits part of the internal memory manager Protection Mask, from:
00099 // http://reactos.org/wiki/Techwiki:Memory_management_in_the_Windows_XP_kernel
00100 // https://www.reactos.org/wiki/Techwiki:Memory_Protection_constants
00101 // and public assertions.
00102 //
00103 #define MM_ZERO_ACCESS         0
00104 #define MM_READONLY            1
00105 #define MM_EXECUTE             2
00106 #define MM_EXECUTE_READ        3
00107 #define MM_READWRITE           4
00108 #define MM_WRITECOPY           5
00109 #define MM_EXECUTE_READWRITE   6
00110 #define MM_EXECUTE_WRITECOPY   7
00111 #define MM_PROTECT_ACCESS      7
00112
00113 //
00114 // These are flags on top of the actual protection mask
00115 //
00116 #define MM_NOCACHE            0x08
00117 #define MM_GUARDPAGE          0x10
00118 #define MM_WRITECOMBINE       0x18
00119 #define MM_PROTECT_SPECIAL    0x18
00120
00121 //
00122 // These are special cases
00123 //
00124 #define MM_DECOMMIT           (MM_ZERO_ACCESS | MM_GUARDPAGE)
00125 #define MM_NOACCESS           (MM_ZERO_ACCESS | MM_WRITECOMBINE)
00126 #define MM_OUTSWAPPED_KSTACK  (MM_EXECUTE_WRITECOPY | MM_WRITECOMBINE)
00127 #define MM_INVALID_PROTECTION  0xFFFFFFFF
""")


windows_overlay = {
    '_UNICODE_STRING': [None, {
        'Buffer': [None, ['Pointer', dict(
            target='UnicodeString',
            target_args=dict(length=lambda x: x.Length)
            )]],
        }],

    '_EPROCESS' : [None, {
        # Some standard fields for windows processes.
        'name': lambda x: x.ImageFileName,
        'pid': lambda x: x.UniqueProcessId,

        'CreateTime' : [None, ['WinFileTime', {}]],
        'ExitTime' : [None, ['WinFileTime', {}]],
        'InheritedFromUniqueProcessId' : [None, ['unsigned int']],
        'ImageFileName' : [None, ['String', dict(length=16)]],
        'UniqueProcessId' : [None, ['unsigned int']],
        'Session': [None, ["Pointer", dict(target="_MM_SESSION_SPACE")]],
        'Token': [None, ["_EX_FAST_REF", dict(target="_TOKEN")]],
        }],

    '_ETHREAD' : [None, {
        'CreateTime' : [None, ['ThreadCreateTimeStamp', {}]],
        'ExitTime' : [None, ['WinFileTime', {}]],
        }],

    '_OBJECT_SYMBOLIC_LINK' : [None, {
        'CreationTime' : [None, ['WinFileTime', {}]],
        }],

    '_KUSER_SHARED_DATA' : [None, {
        'SystemTime' : [None, ['WinFileTime', dict(is_utc=True)]],

        # When the system license activation must occur.
        'SystemExpirationDate': [None, ['WinFileTime', {}]],

        "NtSystemRoot": [None, ["UnicodeString"]],
    }],

    '_KPCR': [None, {
        # The processor block has varying names between windows versions so
        # we just make them synonyms.
        'ProcessorBlock': lambda x: x.m("Prcb") or x.m("PrcbData"),
        'IDT': lambda x: x.m("IDT") or x.m("IdtBase"),
        'GDT': lambda x: x.m("GDT") or x.m("GdtBase"),
        'KdVersionBlock': [None, ['Pointer', dict(
            target='_DBGKD_GET_VERSION64')]],
        }],

    '_KPRCB': [None, {
        'CurrentThread': [None, ['Pointer', dict(
            target='_ETHREAD')]],
        'IdleThread': [None, ['Pointer', dict(
            target='_ETHREAD')]],
        'NextThread': [None, ['Pointer', dict(
            target='_ETHREAD')]],
        'VendorString': [None, ['String', dict(length=13)]],

        }],

    # The DTB is really an array of 2 ULONG_PTR but we only need the first one
    # which is the value loaded into CR3. The second one, according to procobj.c
    # of the wrk-v1.2, contains the PTE that maps something called hyper space.
    '_KPROCESS' : [None, {
        'DirectoryTableBase' : [None, ['unsigned long']],
    }],

    '_HANDLE_TABLE_ENTRY' : [None, {
        'Object' : [None, ['_EX_FAST_REF']],
        }],

    '_OBJECT_HEADER': [None, {
        'GrantedAccess': lambda x: x.obj_parent.GrantedAccess
        }],

    '_IMAGE_SECTION_HEADER' : [None, {
        'Name' : [0x0, ['String', dict(length=8)]],
        }],

    'PO_MEMORY_IMAGE' : [None, {
        'Signature':   [None, ['String', dict(length=4)]],
        'SystemTime' : [None, ['WinFileTime', {}]],
        }],

    '_DBGKD_GET_VERSION64' : [None, {
        'DebuggerDataList' : [None, ['pointer', ['unsigned long']]],
        }],

    '_TOKEN' : [None, {
        'UserAndGroups' : [None, ['Pointer', dict(
            target='Array',
            target_args=dict(
                count=lambda x: x.UserAndGroupCount,
                target='_SID_AND_ATTRIBUTES'
                )
            )]],
        }],

    '_SID_AND_ATTRIBUTES': [None, {
        'Sid': [None, ['Pointer', dict(
            target='_SID'
            )]],
        }],

    '_SID' : [None, {
        'SubAuthority' : [None, ['Array', dict(
            count=lambda x: x.SubAuthorityCount,
            target='unsigned long')]],
        }],

    '_CLIENT_ID': [None, {
        'UniqueProcess' : [None, ['unsigned int']],
        'UniqueThread' : [None, ['unsigned int']],
        }],

    '_MMVAD': [None, {
        'FirstPrototypePte': [None, ["Pointer", dict(
            target="Array",
            target_args=dict(
                target="_MMPTE"
                )
            )]],
        }],

    "_GUID": [16, {
        "Data4": [8, ["String", dict(length=8, term=None)]],
        "AsString": lambda x: ("%08x-%04x-%04x-%s" % (
            x.Data1, x.Data2, x.Data3, x.Data4.v().encode('hex'))).upper(),
        }],

    '_MMVAD_LONG': [None, {
        'FirstPrototypePte': [None, ["Pointer", dict(
            target="Array",
            target_args=dict(
                target="_MMPTE"
                )
            )]],
        }],

    '_MMVAD_FLAGS': [None, {
        # Vad Protections. Also known as page protections. The
        # _MMVAD_FLAGS.Protection, 3-bits, is an index into
        # nt!MmProtectToValue (the following list).
        'ProtectionEnum': lambda x: x.cast(
            "Enumeration",
            choices={
                0: 'NOACCESS',
                1: 'READONLY',
                2: 'EXECUTE',
                3: 'EXECUTE_READ',
                4: 'READWRITE',
                5: 'WRITECOPY',
                6: 'EXECUTE_READWRITE',
                7: 'EXECUTE_WRITECOPY',
                8: 'NOACCESS',
                9: 'NOCACHE | READONLY',
                10:'NOCACHE | EXECUTE',
                11:'NOCACHE | EXECUTE_READ',
                12:'NOCACHE | READWRITE',
                13:'NOCACHE | WRITECOPY',
                14:'NOCACHE | EXECUTE_READWRITE',
                15:'NOCACHE | EXECUTE_WRITECOPY',
                16:'NOACCESS',
                17:'GUARD | READONLY',
                18:'GUARD | EXECUTE',
                19:'GUARD | EXECUTE_READ',
                20:'GUARD | READWRITE',
                21:'GUARD | WRITECOPY',
                22:'GUARD | EXECUTE_READWRITE',
                23:'GUARD | EXECUTE_WRITECOPY',
                24:'NOACCESS',
                25:'WRITECOMBINE | READONLY',
                26:'WRITECOMBINE | EXECUTE',
                27:'WRITECOMBINE | EXECUTE_READ',
                28:'WRITECOMBINE | READWRITE',
                29:'WRITECOMBINE | WRITECOPY',
                30:'WRITECOMBINE | EXECUTE_READWRITE',
                31:'WRITECOMBINE | EXECUTE_WRITECOPY',
                },
            value=x.m("Protection")),

        # Vad Types. The _MMVAD_SHORT.u.VadFlags (_MMVAD_FLAGS) struct on XP
        # has individual flags, 1-bit each, for these types. The
        # _MMVAD_FLAGS for all OS after XP has a member of the
        # _MMVAD_FLAGS.VadType, 3-bits, which is an index into the following
        # enumeration.
        "VadTypeEnum": lambda x: x.cast(
            "Enumeration",
            choices={
                0: 'VadNone',
                1: 'VadDevicePhysicalMemory',
                2: 'VadImageMap',
                3: 'VadAwe',
                4: 'VadWriteWatch',
                5: 'VadLargePages',
                6: 'VadRotatePhysical',
                7: 'VadLargePageSection',
                },
            value=x.m("VadType")),
        }],

    # The environment is a null termionated _UNICODE_STRING array. Print with
    # list(eprocess.Peb.ProcessParameters.Environment)
    '_RTL_USER_PROCESS_PARAMETERS': [None, {
        'Environment': [None, ['Pointer', dict(
            target='SentinelListArray',
            target_args=dict(
                target="UnicodeString",
                )
            )]],
        }],

    '_DEVICE_OBJECT': [None, {
        'DeviceType': [None, ['Enumeration', dict(choices={
            0x00000027 : 'FILE_DEVICE_8042_PORT',
            0x00000032 : 'FILE_DEVICE_ACPI',
            0x00000029 : 'FILE_DEVICE_BATTERY',
            0x00000001 : 'FILE_DEVICE_BEEP',
            0x0000002a : 'FILE_DEVICE_BUS_EXTENDER',
            0x00000002 : 'FILE_DEVICE_CD_ROM',
            0x00000003 : 'FILE_DEVICE_CD_ROM_FILE_SYSTEM',
            0x00000030 : 'FILE_DEVICE_CHANGER',
            0x00000004 : 'FILE_DEVICE_CONTROLLER',
            0x00000005 : 'FILE_DEVICE_DATALINK',
            0x00000006 : 'FILE_DEVICE_DFS',
            0x00000035 : 'FILE_DEVICE_DFS_FILE_SYSTEM',
            0x00000036 : 'FILE_DEVICE_DFS_VOLUME',
            0x00000007 : 'FILE_DEVICE_DISK',
            0x00000008 : 'FILE_DEVICE_DISK_FILE_SYSTEM',
            0x00000033 : 'FILE_DEVICE_DVD',
            0x00000009 : 'FILE_DEVICE_FILE_SYSTEM',
            0x0000003a : 'FILE_DEVICE_FIPS',
            0x00000034 : 'FILE_DEVICE_FULLSCREEN_VIDEO',
            0x0000000a : 'FILE_DEVICE_INPORT_PORT',
            0x0000000b : 'FILE_DEVICE_KEYBOARD',
            0x0000002f : 'FILE_DEVICE_KS',
            0x00000039 : 'FILE_DEVICE_KSEC',
            0x0000000c : 'FILE_DEVICE_MAILSLOT',
            0x0000002d : 'FILE_DEVICE_MASS_STORAGE',
            0x0000000d : 'FILE_DEVICE_MIDI_IN',
            0x0000000e : 'FILE_DEVICE_MIDI_OUT',
            0x0000002b : 'FILE_DEVICE_MODEM',
            0x0000000f : 'FILE_DEVICE_MOUSE',
            0x00000010 : 'FILE_DEVICE_MULTI_UNC_PROVIDER',
            0x00000011 : 'FILE_DEVICE_NAMED_PIPE',
            0x00000012 : 'FILE_DEVICE_NETWORK',
            0x00000013 : 'FILE_DEVICE_NETWORK_BROWSER',
            0x00000014 : 'FILE_DEVICE_NETWORK_FILE_SYSTEM',
            0x00000028 : 'FILE_DEVICE_NETWORK_REDIRECTOR',
            0x00000015 : 'FILE_DEVICE_NULL',
            0x00000016 : 'FILE_DEVICE_PARALLEL_PORT',
            0x00000017 : 'FILE_DEVICE_PHYSICAL_NETCARD',
            0x00000018 : 'FILE_DEVICE_PRINTER',
            0x00000019 : 'FILE_DEVICE_SCANNER',
            0x0000001c : 'FILE_DEVICE_SCREEN',
            0x00000037 : 'FILE_DEVICE_SERENUM',
            0x0000001a : 'FILE_DEVICE_SERIAL_MOUSE_PORT',
            0x0000001b : 'FILE_DEVICE_SERIAL_PORT',
            0x00000031 : 'FILE_DEVICE_SMARTCARD',
            0x0000002e : 'FILE_DEVICE_SMB',
            0x0000001d : 'FILE_DEVICE_SOUND',
            0x0000001e : 'FILE_DEVICE_STREAMS',
            0x0000001f : 'FILE_DEVICE_TAPE',
            0x00000020 : 'FILE_DEVICE_TAPE_FILE_SYSTEM',
            0x00000038 : 'FILE_DEVICE_TERMSRV',
            0x00000021 : 'FILE_DEVICE_TRANSPORT',
            0x00000022 : 'FILE_DEVICE_UNKNOWN',
            0x0000002c : 'FILE_DEVICE_VDM',
            0x00000023 : 'FILE_DEVICE_VIDEO',
            0x00000024 : 'FILE_DEVICE_VIRTUAL_DISK',
            0x00000025 : 'FILE_DEVICE_WAVE_IN',
            0x00000026 : 'FILE_DEVICE_WAVE_OUT',
            })]],
        }],
    '_DRIVER_OBJECT': [None, {
        'MajorFunction': [None, ['IndexedArray', dict(
            index_table={
                'IRP_MJ_CREATE': 0,
                'IRP_MJ_CREATE_NAMED_PIPE': 1,
                'IRP_MJ_CLOSE': 2,
                'IRP_MJ_READ': 3,
                'IRP_MJ_WRITE': 4,
                'IRP_MJ_QUERY_INFORMATION': 5,
                'IRP_MJ_SET_INFORMATION': 6,
                'IRP_MJ_QUERY_EA': 7,
                'IRP_MJ_SET_EA': 8,
                'IRP_MJ_FLUSH_BUFFERS': 9,
                'IRP_MJ_QUERY_VOLUME_INFORMATION': 10,
                'IRP_MJ_SET_VOLUME_INFORMATION': 11,
                'IRP_MJ_DIRECTORY_CONTROL': 12,
                'IRP_MJ_FILE_SYSTEM_CONTROL': 13,
                'IRP_MJ_DEVICE_CONTROL': 14,
                'IRP_MJ_INTERNAL_DEVICE_CONTROL': 15,
                'IRP_MJ_SHUTDOWN': 16,
                'IRP_MJ_LOCK_CONTROL': 17,
                'IRP_MJ_CLEANUP': 18,
                'IRP_MJ_CREATE_MAILSLOT': 19,
                'IRP_MJ_QUERY_SECURITY': 20,
                'IRP_MJ_SET_SECURITY': 21,
                'IRP_MJ_POWER': 22,
                'IRP_MJ_SYSTEM_CONTROL': 23,
                'IRP_MJ_DEVICE_CHANGE': 24,
                'IRP_MJ_QUERY_QUOTA': 25,
                'IRP_MJ_SET_QUOTA': 26,
                'IRP_MJ_PNP': 27
                },
            target="Pointer",
            target_args=dict(target="Function"),
            )]],
        }],

    # This defines _PSP_CID_TABLE as an alias for _HANDLE_TABLE.
    "_PSP_CID_TABLE": "_HANDLE_TABLE",

    "_LDR_DATA_TABLE_ENTRY": [None, {
        "TimeDateStamp": [None, ["WinFileTime"]],
        "LoadReason": lambda x: x.m("LoadReason") or x.m("LoadCount")
        }],

    '_PHYSICAL_MEMORY_DESCRIPTOR' : [None, {
        'Run' : [None, ['Array', dict(
            count=lambda x: x.NumberOfRuns,
            max_count=100,
            target='_PHYSICAL_MEMORY_RUN')]],
        }],

    '_POOL_HEADER': [None, {
        # Wrap the pool type in an enumeration.
        'PoolType': lambda x: x.cast("Enumeration",
                                     enum_name="_POOL_TYPE",
                                     value=x.m("PoolType")),
        'Tag': lambda x: str(x.PoolTag.cast("String", length=4)),
        }],

    '_DISPATCHER_HEADER': [None, {
        "Type": [None, ["Enumeration", dict(
            choices=undocumented.ENUMS["_KOBJECTS"],
            target="unsigned char",
            )]],
        }],

    '_CM_NAME_CONTROL_BLOCK' : [None, {
        'Name' : [None, ['String', dict(length=lambda x: x.NameLength)]],
        }],

    # Memory manager enums.
    '_MMPTE_SOFTWARE': [None, {
        "Protection": lambda x: x.cast(
            "Enumeration",
            choices=MM_PROTECTION_ENUM,
            value=x.m("Protection")),
        }],

    '_MMPTE_PROTOTYPE': [None, {
        "Protection": lambda x: x.cast(
            "Enumeration",
            choices=MM_PROTECTION_ENUM,
            value=x.m("Protection")),

        "Proto": lambda x: x.cast(
            "Pointer",
            target="_MMPTE",
            value=x.m("ProtoAddress"),
            vm=x.obj_session.GetParameter("default_address_space"),
            ),
        }],

    '_MMPTE_SUBSECTION': [None, {
        "Protection": lambda x: x.cast(
            "Enumeration",
            choices=MM_PROTECTION_ENUM,
            value=x.m("Protection")),

        "Subsection": lambda x: x.cast(
            "Pointer",
            target="_SUBSECTION",
            value=x.m("SubsectionAddress"),
            ),
        }],

    '_MMPTE_TRANSITION': [None, {
        "Protection": lambda x: x.cast(
            "Enumeration",
            choices=MM_PROTECTION_ENUM,
            value=x.m("Protection")),
        }],

    '_SECTION_OBJECT_POINTERS': [None, {
        'DataSectionObject': [None, ['Pointer', dict(
            target="_CONTROL_AREA"
            )]],

        'SharedCacheMap': [None, ['Pointer', dict(
            target="_SHARED_CACHE_MAP"
            )]],

        'ImageSectionObject': [None, ['Pointer', dict(
            target="_CONTROL_AREA"
            )]],

        }],

    '_CONTROL_AREA': [None, {
        'FilePointer': lambda x: x.m('FilePointer').dereference_as(
            "_FILE_OBJECT"),

        # The first subsection immediately follows the control area.
        'FirstSubsection': lambda x: x.cast(
            "_SUBSECTION", offset=x.obj_end),
    }],

    '_SUBSECTION': [None, {
        'SubsectionBase': [None, ['Pointer', dict(
            target='Array',
            target_args=dict(
                count=lambda x: x.PtesInSubsection.v(),
                target='_MMPTE'
            )
        )]],
    }],

    '_SHARED_CACHE_MAP': [None, {
        'FileObjectFastRef': lambda x: x.m('FileObjectFastRef').dereference_as(
            "_FILE_OBJECT"),

        'Vacbs': [None, ['Pointer', dict(
            target="Array",
            target_args=dict(
                target="Pointer",
                target_args=dict(
                    target="_VACB"
                )
            )
        )]],
    }],

    '_VACB_ARRAY_HEADER': [None, {
        'VACBs': lambda x: x.cast(
            "Array",
            offset=x.obj_end,
            target="_VACB",
            count=4095
        ),
    }],
}


class _LDR_DATA_TABLE_ENTRY(obj.Struct):

    @property
    def name(self):
        return unicode(self.BaseDllName)

    @property
    def base(self):
        return int(self.DllBase)

    @property
    def end(self):
        """The end address of this module's code in memory."""
        return int(self.DllBase) + int(self.SizeOfImage)

    @property
    def RSDS(self):
        helper = pe_vtypes.PE(address_space=self.obj_vm,
                              image_base=self.DllBase,
                              session=self.obj_session)

        return helper.RSDS


class _UNICODE_STRING(obj.Struct):
    """Class representing a _UNICODE_STRING

    Adds the following behavior:
      * The Buffer attribute is presented as a Python string rather
        than a pointer to an unsigned short.
      * The __unicode__ method returns the value of the Buffer.
    """

    def v(self, vm=None):
        length = self.Length.v(vm=vm)
        if length > 0 and length <= 1024:
            data = self.Buffer.dereference_as(
                'UnicodeString',
                target_args=dict(
                    length=length),
                vm=vm)
            return data.v()
        else:
            return ''

    def __nonzero__(self):
        ## Unicode strings are valid if they point at a valid memory
        return bool(self.Buffer)

    def __eq__(self, other):
        return unicode(self) == utils.SmartUnicode(other)

    def __unicode__(self):
        return self.v().strip("\x00") or u""

    def __repr__(self):
        value = utils.SmartStr(self)
        elide = ""
        if len(value) > 50:
            elide = "..."
            value = value[:50]

        return "%s (%s%s)" % (super(_UNICODE_STRING, self).__repr__(),
                              value, elide)

    def write(self, string):
        self.Buffer.dereference().write(string)
        self.Length = len(string) * 2


class _SID(obj.Struct):
    """SID Structure.

    Ref:
    http://searchwindowsserver.techtarget.com/feature/The-structure-of-a-SID
    """



    def __unicode__(self):
        """
        Ref: RtlConvertSidToUnicodeString
        http://doxygen.reactos.org/d9/d9b/lib_2rtl_2sid_8c_source.html
        """
        wcs = "S-1-"

        if (self.IdentifierAuthority.Value[0] == 0 and
                self.IdentifierAuthority.Value[1] == 0):
            wcs += "%lu" % (
                self.IdentifierAuthority.Value[2] << 24 |
                self.IdentifierAuthority.Value[3] << 16 |
                self.IdentifierAuthority.Value[4] << 8 |
                self.IdentifierAuthority.Value[5])
        else:
            wcs += "0x%02hx%02hx%02hx%02hx%02hx%02hx" % (
                self.IdentifierAuthority.Value[0],
                self.IdentifierAuthority.Value[1],
                self.IdentifierAuthority.Value[2],
                self.IdentifierAuthority.Value[3],
                self.IdentifierAuthority.Value[4],
                self.IdentifierAuthority.Value[5])

        for i in self.SubAuthority:
            wcs += "-%u" % i

        return wcs

class _EPROCESS(obj.Struct):
    """ An extensive _EPROCESS with bells and whistles """

    def is_valid(self):
        """Validate the _EPROCESS."""
        pid = self.pid

        # PID must be in a reasonable range.
        if pid < 0 or pid > 0xFFFF:
            return False

        # Since we're not validating memory pages anymore it's important
        # to weed out zero'd structs.
        if ((pid == 0 or self.CreateTime == 0) and
                self.ImageFileName not in ("Idle", "System")):
            return False

        # Dispatch header must be for a process object.
        if self.Pcb.Header.Type != "ProcessObject":
            return False

        return True

    @property
    def Peb(self):
        """ Returns a _PEB object which is using the process address space.

        The PEB structure is referencing back into the process address
        space so we need to switch address spaces when we look at
        it. This method ensure this happens automatically.
        """
        return self.m("Peb").cast("Pointer", target="_PEB",
                                  vm=self.get_process_address_space())

    @property
    def IsWow64(self):
        """Returns True if this is a wow64 process"""
        return hasattr(self, 'Wow64Process') and self.Wow64Process.v() != 0

    @property
    def SessionId(self):
        """Returns the Session ID of the process"""

        if self.Session.is_valid():
            process_space = self.get_process_address_space()
            if process_space:
                return self.obj_profile._MM_SESSION_SPACE(
                    offset=self.Session, vm=process_space).SessionId

        return obj.NoneObject("Cannot find process session")

    def __repr__(self):
        return "%s (pid=%s)" % (super(_EPROCESS, self).__repr__(), self.pid)

    def get_process_address_space(self):
        """ Gets a process address space for a task given in _EPROCESS """
        directory_table_base = self.Pcb.DirectoryTableBase.v()

        try:
            process_as = self.obj_vm.__class__(
                base=self.obj_vm.base, session=self.obj_vm.session,
                dtb=directory_table_base)
        except addrspace.ASAssertionError, e:
            return obj.NoneObject("Unable to get process AS: %s" % e)

        process_as.name = "Process {0}".format(self.UniqueProcessId)

        return process_as

    def _get_modules(self, the_list, the_type):
        """Generator for DLLs in one of the 3 PEB lists"""
        if self.UniqueProcessId and the_list:
            for l in the_list.list_of_type("_LDR_DATA_TABLE_ENTRY", the_type):
                yield l

    def get_init_modules(self):
        return self._get_modules(self.Peb.Ldr.InInitializationOrderModuleList,
                                 "InInitializationOrderLinks")

    def get_mem_modules(self):
        return self._get_modules(self.Peb.Ldr.InMemoryOrderModuleList,
                                 "InMemoryOrderLinks")

    def get_load_modules(self):
        return self._get_modules(
            self.Peb.Ldr.InLoadOrderModuleList, "InLoadOrderLinks")

    def get_token(self):
        """Return the process's TOKEN object if its valid"""

        # The dereference checks if the address is valid
        # and returns obj.NoneObject if it fails
        token = self.Token.dereference_as("_TOKEN")

        # This check fails if the above dereference failed
        # or if any of the _TOKEN specific validity tests failed.
        if token.is_valid():
            return token

        return obj.NoneObject("Cannot get process Token")

    def ObReferenceObjectByHandle(self, handle, type=None):
        """Search the object table and retrieve the object by handle.

        Args:
          handle: The handle we search for.
          type: The object will be cast to this type.
        """
        for h in self.ObjectTable.handles():
            if h.HandleValue == handle:
                if type is None:
                    return h
                else:
                    return h.dereference_as(type)

        return obj.NoneObject("Could not find handle in ObjectTable")


class _MM_SESSION_SPACE(obj.Struct):
    """Windows separates processes into Sessions.

    Sessions are logically similar groups of processes (e.g. all created as part
    of the same RDP login). The virtual address space is divided into three main
    parts:

    - The process range - This memory is unique to each process.

    - The kernel space - all regular kernel memory is mapped into all processes.

    - The session space - This part of the address space is different for each
      session, but is shared by all processes in the same session.
    """

    def processes(self):
        """Generator for processes in this session.

        A process is always associated with exactly
        one session.
        """
        for p in self.ProcessList.list_of_type(
                "_EPROCESS", "SessionProcessLinks"):
            yield p


class _POOL_HEADER(obj.Struct):
    """Extension to support retrieving allocations inside the pool.

    Ref for windows memory management:
    http://illmatics.com/Windows%208%20Heap%20Internals.pdf
    """

    def get_rounded_size(self, object_name):
        """Returns the size of the object accounting for pool alignment."""
        size_of_obj = self.obj_profile.get_obj_size(object_name)
        pool_align = self.obj_profile.get_constant("PoolAlignment")

        # Size is rounded to pool alignment
        extra = size_of_obj % pool_align
        if extra:
            size_of_obj += pool_align - extra

        return size_of_obj

    def end(self):
        return self.obj_offset + self.obj_size

    def GetObject(self, type=None):
        """Return the first object header found."""
        for item in self.IterObject(type=type):
            return item

        return obj.NoneObject("No object found.")

    def IterObject(self, type=None):
        """Gets the _OBJECT_HEADER considering optional headers."""
        pool_align = self.obj_profile.get_constant("PoolAlignment")
        allocation_size = self.BlockSize * pool_align

        # Operate on a cached version of the next page.
        # We use a temporary buffer for the object to save reads of the image.
        cached_data = self.obj_vm.read(self.obj_offset + self.obj_size,
                                       allocation_size)
        cached_vm = addrspace.BufferAddressSpace(
            data=cached_data, session=self.obj_session)

        # We search for the _OBJECT_HEADER.InfoMask in close proximity to our
        # object. We build a lookup table between the values in the InfoMask and
        # the minimum distance there is between the start of _OBJECT_HEADER and
        # the end of _POOL_HEADER. This way we can quickly skip unreasonable
        # values.

        for i in range(0, allocation_size, pool_align):
            # Create a test object header from the cached vm to test for
            # validity.
            test_object = self.obj_profile._OBJECT_HEADER(
                offset=i, vm=cached_vm)

            optional_preamble = max(test_object.NameInfoOffset,
                                    test_object.HandleInfoOffset,
                                    test_object.QuotaInfoOffset)

            # Obviously wrong because we need more space than we have.
            if optional_preamble > i:
                continue

            if test_object.is_valid():
                if type is not None and test_object.get_object_type() != type:
                    continue

                yield self.obj_profile._OBJECT_HEADER(
                    offset=i + self.obj_offset + self.obj_size,
                    vm=self.obj_vm, parent=self)

    @property
    def FreePool(self):
        return self.PoolType.v() == 0

    @property
    def NonPagedPool(self):
        return self.PoolType.v() % 2 == 1

    @property
    def PagedPool(self):
        return self.PoolType.v() % 2 == 0 and self.PoolType.v() > 0


class _TOKEN(obj.Struct):
    """A class for Tokens"""

    def is_valid(self):
        """Override BaseObject.is_valid with some additional
        checks specific to _TOKEN objects."""
        return (super(_TOKEN, self).is_valid() and
                self.TokenInUse in (0, 1) and self.SessionId < 10)

    def get_sids(self):
        """Generator for process SID strings"""
        if self.UserAndGroupCount < 0xFFFF:
            for sa in self.UserAndGroups.dereference():
                sid = sa.Sid.dereference_as('_SID')
                for i in sid.IdentifierAuthority.Value:
                    id_auth = i
                yield "S-" + "-".join(str(i) for i in (sid.Revision, id_auth) +
                                      tuple(sid.SubAuthority))


class _ETHREAD(obj.Struct):
    """ A class for threads """

    def owning_process(self):
        """Return the EPROCESS that owns this thread"""
        return self.Tcb.ApcState.Process.dereference_as("_EPROCESS")

    def attached_process(self):
        """Return the EPROCESS that this thread is currently
        attached to."""
        return self.Tcb.ApcState.Process.dereference_as("_EPROCESS")


class _HANDLE_TABLE(obj.Struct):
    """ A class for _HANDLE_TABLE.

    This used to be a member of _EPROCESS but it was isolated per issue
    91 so that it could be subclassed and used to service other handle
    tables, such as the _KDDEBUGGER_DATA64.PspCidTable.
    """

    def get_item(self, entry):
        """Returns the OBJECT_HEADER of the associated handle. The parent
        is the _HANDLE_TABLE_ENTRY so that an object can be linked to its
        GrantedAccess.
        """
        return entry.Object.dereference_as("_OBJECT_HEADER", parent=entry)

    def _make_handle_array(self, table_offset, level):
        """ Returns an array of _HANDLE_TABLE_ENTRY rooted at offset,
        and iterates over them.
        """
        # level == 0 means we are at the bottom level and this is a table of
        # _HANDLE_TABLE_ENTRY, otherwise, it means we are a table of pointers to
        # lower tables.
        if level == 0:
            table = self.obj_profile.Array(
                offset=table_offset,
                target="_HANDLE_TABLE_ENTRY",
                size=0x1000)

            for entry in table:
                yield self.get_item(entry)

        else:
            table = self.obj_profile.PointerArray(
                offset=table_offset, size=0x1000)

            for entry in table:
                if entry:
                    for item in self._make_handle_array(entry, level-1):
                        yield item

    def handles(self):
        """ A generator which yields this process's handles

        _HANDLE_TABLE tables are multi-level tables at the first level
        they are pointers to second level table, which might be
        pointers to third level tables etc, until the final table
        contains the real _OBJECT_HEADER table.

        This generator iterates over all the handles recursively
        yielding all handles. We take care of recursing into the
        nested tables automatically.

        Reference:
        http://forum.sysinternals.com/hiding-a-process-pspcidtable_topic15362.html
        """
        # This should work equally for 32 and 64 bit systems
        LEVEL_MASK = 7

        table = self.TableCode & ~LEVEL_MASK
        level = self.TableCode & LEVEL_MASK

        for i, handle in enumerate(self._make_handle_array(table, level)):
            # New object header uses TypeIndex.
            if handle.m("TypeIndex") > 0x0 or handle.m("Type").Name:
                handle.HandleValue = i * 4

                yield handle


class _PSP_CID_TABLE(_HANDLE_TABLE):
    """Subclass the Windows handle table object for parsing PspCidTable"""

    def get_item(self, entry):
        p = self.obj_profile.Object("address", entry.Object.v(), self.obj_vm)

        handle = self.obj_profile.Object(
            "_OBJECT_HEADER",
            offset=(p & ~7) - self.obj_profile.get_obj_offset(
                '_OBJECT_HEADER', 'Body'),
            vm=self.obj_vm)

        return handle


class ObjectMixin(object):
    """A mixin to be applied on Object Manager Objects."""

    @property
    def ObjectHeader(self):
        return self.obj_profile._OBJECT_HEADER(
            self.obj_offset - self.obj_profile.get_obj_size(
                "_OBJECT_HEADER"))


class _OBJECT_HEADER(obj.Struct):
    """A Rekall Memory Forensics object to handle Windows object headers.

    This object applies only to versions below windows 7. (old version
    objects). See:
    http://codemachine.com/article_objectheader.html
    """

    # A mapping between the object type name and the struct name for it.
    type_lookup = dict(
        File="_FILE_OBJECT",
        Driver="_DRIVER_OBJECT",
        Directory="_OBJECT_DIRECTORY",
        SymbolicLink="_OBJECT_SYMBOLIC_LINK",
        Mutant="_KMUTANT",
        Process="_EPROCESS",
        Key="_CM_KEY_BODY",
        Token="_TOKEN",
        Thread="_ETHREAD",
        )


    optional_headers = [
        ('NameInfo', '_OBJECT_HEADER_NAME_INFO', 'NameInfoOffset'),
        ('HandleInfo', '_OBJECT_HEADER_HANDLE_INFO', 'HandleInfoOffset'),
        ('QuotaInfo', '_OBJECT_HEADER_QUOTA_INFO', 'QuotaInfoOffset')]

    def __init__(self, handle_value=0, **kwargs):
        self.HandleValue = handle_value
        self._preamble_size = 0
        super(_OBJECT_HEADER, self).__init__(**kwargs)

    def _GetOptionalHeader(self, struct_name, member):
        header_offset = self.m(member).v()
        if header_offset == 0:
            return obj.NoneObject("Header not set")

        return self.obj_profile.Object(
            struct_name, offset=self.obj_offset - header_offset,
            vm=self.obj_vm, parent=self)

    @property
    def obj_size(self):
        """The size of the object header is actually the position of the Body
        element."""
        return self.obj_profile.get_obj_offset("_OBJECT_HEADER", "Body")

    def dereference_as(self, type_name, vm=None):
        """Instantiate an object from the _OBJECT_HEADER.Body"""
        return self.obj_profile.Object(
            type_name=type_name, offset=self.Body.obj_offset,
            vm=vm or self.obj_vm, parent=self)

    def get_object_type(self, vm=None):
        """Return the object's type as a string"""
        type_obj = self.obj_profile._OBJECT_TYPE(
            vm=vm or self.obj_session.kernel_address_space,
            offset=self.Type)

        return type_obj.Name.v()

    @property
    def Object(self):
        """Return the object following this header."""
        required_type = self.type_lookup.get(self.get_object_type())
        if required_type:
            return self.Body.cast(required_type)

        return obj.NoneObject("Unknown object type")


# Build properties for the optional headers.
for _name, _y, _z in _OBJECT_HEADER.optional_headers:
    setattr(_OBJECT_HEADER, _name, property(
        lambda x, y=_y, z=_z: x._GetOptionalHeader(y, z)))


class _DEVICE_OBJECT(ObjectMixin, obj.Struct):
    """A Device Object."""


class _FILE_OBJECT(ObjectMixin, obj.Struct):
    """Class for file objects"""

    @property
    def AccessString(self):
        """Make a nicely formatted ACL string."""
        return (((self.ReadAccess > 0 and "R") or '-') +
                ((self.WriteAccess > 0  and "W") or '-') +
                ((self.DeleteAccess > 0 and "D") or '-') +
                ((self.SharedRead > 0 and "r") or '-') +
                ((self.SharedWrite > 0 and "w") or '-') +
                ((self.SharedDelete > 0 and "d") or '-'))

    def file_name_with_device(self):
        """Return the name of the file, prefixed with the name
        of the device object to which the file belongs"""
        name = ""
        if self.DeviceObject:
            device_name = self.DeviceObject.ObjectHeader.NameInfo.Name
            if device_name:
                name = u"\\Device\\{0}".format(device_name)

        if self.FileName:
            name += unicode(self.FileName)

        return name


class _OBJECT_DIRECTORY(ObjectMixin, obj.Struct):
    """Object directories hold other objects.

    http://msdn.microsoft.com/en-us/library/windows/hardware/ff557755(v=vs.85).aspx
    """

    def list(self):
        for bucket in self.HashBuckets:
            for entry in bucket.walk_list("ChainLink"):
                target_obj_header = self.obj_profile._OBJECT_HEADER(
                    entry.Object.v() - self.obj_profile.get_obj_size(
                        "_OBJECT_HEADER"))

                if target_obj_header:
                    yield target_obj_header


class _EX_FAST_REF(obj.Struct):
    """This type allows instantiating an object from its .Object member."""

    def __init__(self, target=None, **kwargs):
        self.target = target
        super(_EX_FAST_REF, self).__init__(**kwargs)
        end_bit = self.RefCnt.end_bit
        self.mask = ~ (2 ** end_bit - 1)
        self._object = None

    def is_valid(self):
        if self.Object.v() == 0:
            return False

        return True

    @property
    def Object(self):
        if self._object is None:
            result = self.m("Object")
            self._object = result.cast(value=result.v() & self.mask)

        return self._object

    def dereference(self, vm=None):
        if self.target is None:
            raise AttributeError(
                "No target specified for dereferencing an _EX_FAST_REF.")

        if not self.is_valid():
            return obj.NoneObject("_EX_FAST_REF not valid")

        return self.Object.dereference_as(self.target)

    def dereference_as(self, type_name, parent=None, **kwargs):
        """Use the _EX_FAST_REF.Object pointer to resolve an object of the
        specified type.
        """
        if not self.is_valid():
            return obj.NoneObject("_EX_FAST_REF not valid")

        parent = parent or self.obj_parent or self
        return self.Object.dereference_as(type_name, parent=parent, **kwargs)

    def __getattr__(self, attr):
        return getattr(self.dereference(), attr)


class _CM_KEY_BODY(obj.Struct):
    """Registry key"""

    def full_key_name(self):
        output = []
        kcb = self.KeyControlBlock
        while kcb.ParentKcb:
            if kcb.NameBlock.Name == None:
                break
            output.append(str(kcb.NameBlock.Name))
            kcb = kcb.ParentKcb
        return "\\".join(reversed(output))


class VadTraverser(obj.Struct):
    """The windows Vad tree is basically the same in all versions of windows,
    but the exact name of the stucts vary with version. This is the base class
    for all Vad traversor.
    """
    ## The actual type depends on this tag value.
    tag_map = {'Vadl': '_MMVAD_LONG',
               'VadS': '_MMVAD_SHORT',
               'Vad ': '_MMVAD',
               'VadF': '_MMVAD_SHORT',
               'Vadm': '_MMVAD_LONG',
              }

    left = "LeftChild"
    right = "RightChild"

    def traverse(self, visited=None, depth=0):
        """ Traverse the VAD tree by generating all the left items,
        then the right items.

        We try to be tolerant of cycles by storing all offsets visited.
        """
        if depth > 100:
            logging.error("Vad tree too deep - something went wrong!")
            return

        if visited == None:
            visited = set()

        ## We try to prevent loops here
        if self.obj_offset in visited:
            return

        self.obj_context['depth'] = depth

        # Find out which Vad type we need to be:
        if self.Tag in self.tag_map:
            yield self.cast(self.tag_map[self.Tag])

        # This tag is valid for the Root.
        elif depth and self.Tag.v() != "\x00":
            return

        for c in self.m(self.left).traverse(visited=visited, depth=depth+1):
            visited.add(self.obj_offset)
            yield c

        for c in self.m(self.right).traverse(visited=visited, depth=depth+1):
            visited.add(self.obj_offset)
            yield c


class _KTIMER(obj.Struct):
    @property
    def Dpc(self):
        # On Windows 7 Patch guard obfuscates the DPC address.
        self.KiWaitNever = self.obj_profile.get_constant_object(
            "KiWaitNever", "unsigned long long")
        if not self.KiWaitNever:
            return self.m("Dpc")

        self.KiWaitAlways = self.obj_profile.get_constant_object(
            "KiWaitAlways", "unsigned long long")

        return self._DeobfuscateDpc()

    def _byteswap(self, value):
        return struct.unpack(">Q", struct.pack("<Q", value))[0]

    def _Rol64(self, value, bits):
        return ((value << bits % 64) & (2**64-1) |
                ((value & (2**64-1)) >> (64-(bits % 64))))

    def _DeobfuscateDpc(self):
        # Reference:
        # http://uninformed.org/index.cgi?v=8&a=5&p=10

        # ------ nt!KiSetTimerEx ------
        # MOV RAX, [RIP+0x229bf0]        0x6D7CFFA404933FBB nt!KiWaitNever
        # MOV RBX, [RIP+0x229cc1]        0x933DD660CFFF8004 nt!KiWaitAlways
        # MOV R14, [RSP+0xb0]    <----- DPC
        # XOR RBX, R14
        # ...
        # BSWAP RBX
        # ...
        # XOR RBX, RCX  <---- Timer object.
        # MOV ECX, EAX
        # ROR RBX, CL
        # XOR RBX, RAX  <--- Obfuscated DPC
        Obfuscated = self.m("Dpc").cast("unsigned long long")

        Deobfuscated = Obfuscated ^ self.KiWaitNever
        Deobfuscated = self._Rol64(Deobfuscated, 0xFF & self.KiWaitNever)
        Deobfuscated = Deobfuscated ^ (self.obj_offset | 0xffff000000000000)
        Deobfuscated = self._byteswap(Deobfuscated)
        Deobfuscated = Deobfuscated ^ int(self.KiWaitAlways)

        return self.obj_profile._KDPC(Deobfuscated, parent=self,
                                      vm=self.obj_vm)


def InitializeWindowsProfile(profile):
    """Install the basic windows overlays."""
    profile.add_classes({
        '_UNICODE_STRING': _UNICODE_STRING,
        '_EPROCESS': _EPROCESS,
        '_ETHREAD': _ETHREAD,
        '_HANDLE_TABLE': _HANDLE_TABLE,
        '_POOL_HEADER': _POOL_HEADER,
        '_OBJECT_HEADER': _OBJECT_HEADER,
        '_PSP_CID_TABLE': _PSP_CID_TABLE,
        '_FILE_OBJECT': _FILE_OBJECT,
        '_DEVICE_OBJECT': _DEVICE_OBJECT,
        '_OBJECT_DIRECTORY': _OBJECT_DIRECTORY,
        '_EX_FAST_REF': _EX_FAST_REF,
        '_CM_KEY_BODY': _CM_KEY_BODY,
        '_LDR_DATA_TABLE_ENTRY': _LDR_DATA_TABLE_ENTRY,
        "_MM_SESSION_SPACE": _MM_SESSION_SPACE,
        "_SID": _SID,
        "_KTIMER": _KTIMER,
        "RVAPointer": pe_vtypes.RVAPointer,
        "SentinelArray": pe_vtypes.SentinelArray,
        "SentinelListArray": pe_vtypes.SentinelListArray,
        })

    profile.add_overlay(windows_overlay)

    # Pooltags for common objects (These are different in Win8).
    profile.add_constants(
        DRIVER_POOLTAG="Dri\xf6",
        EPROCESS_POOLTAG="Pro\xe3",
        FILE_POOLTAG="Fil\xe5",
        SYMLINK_POOLTAG="Sym\xe2",
        MODULE_POOLTAG="MmLd",
        MUTANT_POOLTAG="Mut\xe1",
        THREAD_POOLTAG='\x54\x68\x72\xe5',
        )

    # These constants are always the same in all versions of Windows.
    if profile.metadata("arch") == "AMD64":
        # Ref:
        # reactos/include/xdk/amd64/ke.h:17
        profile.add_constants(KI_USER_SHARED_DATA=0xFFFFF78000000000)
    else:
        # reactos/include/xdk/x86/ke.h:19
        profile.add_constants(KI_USER_SHARED_DATA=0xffdf0000)
