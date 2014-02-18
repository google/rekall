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


from rekall import obj
from rekall import utils

from rekall.plugins.overlays.windows import pe_vtypes
from rekall.plugins.overlays import basic


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
            'TimeZoneBias' : [None, ['WinFileTime', {}]],
            }],

    '_KPCR': [None, {
            # The processor block has varying names between windows versions so
            # we just make them synonyms.
            'ProcessorBlock': lambda x: x.m("Prcb") or x.m("PrcbData"),
            '_IDT': lambda x: x.m("IDT") or x.m("IdtBase"),
            '_GDT': lambda x: x.m("GDT") or x.m("GdtBase"),
            'KdVersionBlock': [None, ['Pointer', dict(
                        target='_KDDEBUGGER_DATA64')]],
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

    '_CM_KEY_NODE' : [None, {
            'Signature' : [None, ['String', dict(length=2)]],
            'LastWriteTime' : [None, ['WinFileTime', {}]],
            'Name' : [None, ['String', dict(length=lambda x: x.NameLength)]],
            }],

    '_CM_NAME_CONTROL_BLOCK' : [None, {
            'Name' : [None, ['String', dict(length=lambda x: x.NameLength)]],
            }],

    '_CHILD_LIST' : [None, {
            'List' : [None, ['pointer', ['array', lambda x: x.Count,
                                          ['pointer', ['_CM_KEY_VALUE']]]]],
            }],

    '_CM_KEY_VALUE' : [None, {
            'Signature' : [None, ['String', dict(length=2)]],
            'Name' : [None, ['String', dict(length=lambda x: x.NameLength)]],
            }],

    '_CM_KEY_INDEX' : [None, {
            'Signature' : [None, ['String', dict(length=2)]],
            'List' : [None, ["Array", dict(
                        count=lambda x: x.Count.v() * 2,
                        target="Pointer",
                        target_args=dict(
                            target='_CM_KEY_NODE'
                            )
                        )]],
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

    '_SID' : [None, {
            'SubAuthority' : [None, ['Array', dict(
                        count=lambda x: x.SubAuthorityCount,
                        target='unsigned long')]],
            }],

    '_CLIENT_ID': [None, {
            'UniqueProcess' : [None, ['unsigned int']],
            'UniqueThread' : [None, ['unsigned int']],
            }],

    '_MMVAD_FLAGS': [None, {
            # Vad Protections. Also known as page protections. The
            # _MMVAD_FLAGS.Protection, 3-bits, is an index into
            # nt!MmProtectToValue (the following list).
            'ProtectionEnum': lambda x: basic.Enumeration(
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
                value=x.m("Protection"), name=x.obj_name, type_name=x.obj_type),

            # Vad Types. The _MMVAD_SHORT.u.VadFlags (_MMVAD_FLAGS) struct on XP
            # has individual flags, 1-bit each, for these types. The
            # _MMVAD_FLAGS for all OS after XP has a member of the
            # _MMVAD_FLAGS.VadType, 3-bits, which is an index into the following
            # enumeration.
            "VadTypeEnum": lambda x: basic.Enumeration(
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
                value=x.m("VadType"), name=x.obj_name, type_name=x.obj_type),
            }],

    # The environment is a null termionated _UNICODE_STRING array. Print with
    # list(eprocess.Peb.ProcessParameters.Environment)
    '_RTL_USER_PROCESS_PARAMETERS': [None, {
            'Environment': [None, ['Pointer', {
                        'target': 'ListArray',
                        'target_args': {
                            'target': "UnicodeString"
                            }
                        }]],
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
      * The __str__ method returns the value of the Buffer.
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

    def __str__(self):
        return self.v() or ""

    def __repr__(self):
        value = str(self)
        elide = ""
        if len(value) > 50:
            elide = "..."
            value = value[:50]

        return "%s (%s%s)" % (super(_UNICODE_STRING, self).__repr__(),
                              value, elide)

    def write(self, string):
        self.Buffer.dereference().write(string)
        self.Length = len(string) * 2


class _EPROCESS(obj.Struct):
    """ An extensive _EPROCESS with bells and whistles """

    @property
    def Peb(self):
        """ Returns a _PEB object which is using the process address space.

        The PEB structure is referencing back into the process address
        space so we need to switch address spaces when we look at
        it. This method ensure this happens automatically.
        """
        return self.m("Peb").dereference_as(
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

    def get_process_address_space(self):
        """ Gets a process address space for a task given in _EPROCESS """
        directory_table_base = self.Pcb.DirectoryTableBase.v()

        try:
            process_as = self.obj_vm.__class__(
                base=self.obj_vm.base, session=self.obj_vm.session,
                dtb=directory_table_base)
        except AssertionError, e:
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



class _POOL_HEADER(obj.Struct):
    """Extension to support retrieving allocations inside the pool."""

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
        return self.obj_offset + self.size()

    def get_object(self, object_name, allocations):
        """This implements retrieving an object from the pool allocation using
        the "Bottom Up" method.  NOTE: This method does not work on windows 8
        since allocations are rounded up to a fixed size. Newer versions of
        windows have different _POOL_HEADER implementations.

        The following is provided by MHL:

        For example, let's assume the following object has no preamble, then
        we'd take the base of pool header and add the size of pool header to
        reach the base of the object. Layout in memory looks like this:


        _POOL_HEADER
        <TheObject>

        Now let's assume the object has a preamble - an _OBJECT_HEADER with no
        optional headers.

        _POOL_HEADER
        _OBJECT_HEADER
        <TheObject>

        Its easy to calculate the offset of the object, because you always know
        the size of _POOL_HEADER and _OBJECT_HEADER. However, one situation
        complicates this calculation. There may be optional headers between the
        pool header and object header like this:

        _POOL_HEADER
        <SomeHeaderA>
        <SomeHeaderB>
        _OBJECT_HEADER
        <TheObject>

        The _OBJECT_HEADER itself is the "map" which tell us how many optional
        headers there are. The question becomes - how do we find the
        _OBJECT_HEADER when the very information we need (distance between pool
        header and object header) is stored in the _OBJECT_HEADER? Furthermore,
        we can't statically set preambles, because not only do they differ
        between objects (i.e. mutants may have different optional headers than
        file objects), but they sometimes differ between objects of the same
        type (for example one process may have 2 optional headers and another
        process may only have 1). That flexibility is not really possible with
        the preambles - at least how they were implemented at the time of these
        changes.

        So the "bottom up" approach takes into account two values which *are*
        reliable:

        1. The size of the pool (_POOL_HEADER.BlockSize)
        2. The size of the object you expect to find in the pool
           (i.e. get_obj_size("_EPROCESS"))

        So with that information, you can find the end of the pool
        (i.e. starting from the bottom), subtract the size of the object
        (working our way up), and then you've got the offset of the
        object. Always, the _OBJECT_HEADER (if there is one) directly precedes
        the object, so once you've got the object's offset, you can find the
        _OBJECT_HEADER. And from there, since _OBJECT_HEADER is the "map" you
        can find any optional headers.

        Args:
          name: The name of the object type to retrieve. Note: name must be
            allocations.

          allocations: The list of objects which form this allocation.
        """
        pool_align = self.obj_profile.get_constant("PoolAlignment")

        # We start at the end of the allocation, and go backwards for each
        # object.
        offset = self.obj_offset + self.BlockSize * pool_align

        for name in reversed(allocations):
            # Rewind to the start of this object.
            offset -= self.get_rounded_size(name)

            # Make a new object instance.
            obj = self.obj_profile.Object(
                name, vm=self.obj_vm, offset=offset)
            if name == object_name:
                return obj

            # Rewind past the object's preamble
            offset -= obj.preamble_size()

        raise KeyError("object not present in preamble.")

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

    def get_item(self, entry, handle_value=0):
        """Returns the OBJECT_HEADER of the associated handle. The parent
        is the _HANDLE_TABLE_ENTRY so that an object can be linked to its
        GrantedAccess.
        """
        return entry.Object.dereference_as("_OBJECT_HEADER", parent=entry,
                                           handle_value=handle_value)

    def _make_handle_array(self, offset, level, depth=0):
        """ Returns an array of _HANDLE_TABLE_ENTRY rooted at offset,
        and iterates over them.
        """
        # The counts below are calculated by taking the size of a page and
        # dividing by the size of the data type contained within the page. For
        # more information see
        # http://blogs.technet.com/b/markrussinovich/archive/2009/09/29/3283844.aspx
        if level > 0:
            count = 0x1000 / self.obj_profile.get_obj_size("address")
            target = "address"
        else:
            count = 0x1000 / self.obj_profile.get_obj_size(
                "_HANDLE_TABLE_ENTRY")

            target = "_HANDLE_TABLE_ENTRY"

        table = self.obj_profile.Array(
            offset=offset, vm=self.obj_vm,
            count=count, target=target, parent=self)

        if table:
            for entry in table:
                if not entry.is_valid():
                    break

                if level > 0:
                    ## We need to go deeper:
                    for h in self._make_handle_array(entry, level - 1, depth):
                        yield h
                    depth += 1
                else:
                    # All handle values are multiples of four, on both x86 and
                    # x64.
                    handle_multiplier = 4

                    # Calculate the starting handle value for this level.
                    handle_level_base = depth * count * handle_multiplier

                    # The size of a handle table entry.
                    handle_entry_size = self.obj_profile.get_obj_size(
                        "_HANDLE_TABLE_ENTRY")

                    # Finally, compute the handle value for this object.
                    handle_value = (
                        (entry.obj_offset - table[0].obj_offset) /
                        (handle_entry_size / handle_multiplier)
                        ) + handle_level_base

                    ## OK We got to the bottom table, we just resolve
                    ## objects here:
                    item = self.get_item(entry, handle_value)

                    if item == None:
                        continue

                    try:
                        # New object header
                        if item.TypeIndex != 0x0:
                            yield item
                    except AttributeError:
                        if item.Type.Name:
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
        """
        # This should work equally for 32 and 64 bit systems
        LEVEL_MASK = 7

        TableCode = self.TableCode.v() & ~LEVEL_MASK
        table_levels = self.TableCode.v() & LEVEL_MASK
        offset = TableCode

        for h in self._make_handle_array(offset, table_levels):
            yield h


class _PSP_CID_TABLE(_HANDLE_TABLE):
    """Subclass the Windows handle table object for parsing PspCidTable"""

    def get_item(self, entry, handle_value=0):
        p = self.obj_profile.Object("address", entry.Object.v(), self.obj_vm)

        handle = self.obj_profile.Object(
            "_OBJECT_HEADER",
            offset=(p & ~7) - self.obj_profile.get_obj_offset(
                '_OBJECT_HEADER', 'Body'),
            vm=self.obj_vm)

        return handle


class _OBJECT_HEADER(obj.Struct):
    """A Rekall Memory Forensics object to handle Windows object headers.

    This object applies only to versions below windows 7.
    """

    optional_headers = [
        ('NameInfo', 'NameInfoOffset', '_OBJECT_HEADER_NAME_INFO'),
        ('HandleInfo', 'HandleInfoOffset', '_OBJECT_HEADER_HANDLE_INFO'),
        ('HandleInfo', 'QuotaInfoOffset', '_OBJECT_HEADER_QUOTA_INFO')]

    def __init__(self, handle_value=0, **kwargs):
        self.HandleValue = handle_value
        self._preamble_size = 0
        super(_OBJECT_HEADER, self).__init__(**kwargs)

        # Create accessors for optional headers
        self.find_optional_headers()

    def find_optional_headers(self):
        """Find this object's optional headers."""
        offset = self.obj_offset

        for name, name_offset, objtype in self.optional_headers:
            if self.obj_profile.has_type(objtype):
                header_offset = self.m(name_offset).v()
                if header_offset:
                    o = self.obj_profile.Object(type_name=objtype,
                                                offset=offset - header_offset,
                                                vm=self.obj_vm)
                else:
                    o = obj.NoneObject("Header not set")

                setattr(self, name, o)

                # Optional headers stack before this _OBJECT_HEADER.
                if o:
                    self._preamble_size += o.size()

    def preamble_size(self):
        return self._preamble_size

    def size(self):
        """The size of the object header is actually the position of the Body
        element."""
        return self.obj_profile.get_obj_offset("_OBJECT_HEADER", "Body")

    @property
    def GrantedAccess(self):
        if self.obj_parent:
            return self.obj_parent.GrantedAccess
        return obj.NoneObject("No parent known")

    def dereference_as(self, type_name, vm=None):
        """Instantiate an object from the _OBJECT_HEADER.Body"""
        return self.obj_profile.Object(
            type_name=type_name, offset=self.Body.obj_offset,
            vm=vm or self.obj_vm, parent=self)

    def get_object_type(self, vm=None):
        """Return the object's type as a string"""
        type_obj = self.obj_profile._OBJECT_TYPE(vm=vm or self.obj_vm,
                                                 offset=self.Type)

        return type_obj.Name.v()



class _FILE_OBJECT(obj.Struct):
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
            object_hdr = self.obj_profile._OBJECT_HEADER(
                offset=(self.DeviceObject.v() - self.obj_profile.get_obj_offset(
                        "_OBJECT_HEADER", "Body")),
                vm=self.obj_vm)

            if object_hdr.NameInfo:
                name = u"\\Device\\{0}".format(object_hdr.NameInfo.Name)

        if self.FileName:
            name += self.FileName.v()

        return name


class _EX_FAST_REF(obj.Struct):
    """This type allows instantiating an object from its .Object member."""

    def __init__(self, target=None, **kwargs):
        self.target = target
        super(_EX_FAST_REF, self).__init__(**kwargs)

    def dereference(self, vm=None):
        if self.target is None:
            raise TypeError(
                "No target specified for dereferencing an _EX_FAST_REF.")

        return self.dereference_as(self.target)

    def dereference_as(self, type_name, parent=None, vm=None, **kwargs):
        """Use the _EX_FAST_REF.Object pointer to resolve an object of the
        specified type.
        """
        MAX_FAST_REF = self.obj_profile.constants['MAX_FAST_REF']
        return self.obj_profile.Object(
            type_name=type_name, offset=self.m("Object").v() & ~MAX_FAST_REF,
            vm=vm or self.obj_vm, parent=parent or self, **kwargs)

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

class _MMVAD_FLAGS(obj.Struct):
    """This is for _MMVAD_SHORT.u.VadFlags"""

    def __str__(self):
        result = []
        for name in sorted(self.members):
            if name.endswith("Enum"):
                continue

            try:
                attribute = getattr(self, name)
                if attribute.v():
                    result.append("%s: %s" % (name, attribute))
            except AttributeError:
                pass

        return ", ".join(result)

class _MMVAD_FLAGS2(_MMVAD_FLAGS):
    """This is for _MMVAD_LONG.u2.VadFlags2"""
    pass

class _MMSECTION_FLAGS(_MMVAD_FLAGS):
    """This is for _CONTROL_AREA.u.Flags"""
    pass


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

    def traverse(self, visited=None, depth=0):
        """ Traverse the VAD tree by generating all the left items,
        then the right items.

        We try to be tolerant of cycles by storing all offsets visited.
        """
        if depth > 100:
            raise RuntimeError("Vad tree too deep - something went wrong!")

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

        for c in self.LeftChild.traverse(visited=visited, depth=depth+1):
            visited.add(self.obj_offset)
            yield c

        for c in self.RightChild.traverse(visited=visited, depth=depth+1):
            visited.add(self.obj_offset)
            yield c



def InitializeWindowsProfile(profile):
    """Install the basic windows overlays."""
    profile.add_types({
            'pointer64': ['NativeType', dict(format_string='<Q')]
            })

    profile.add_classes({
            '_UNICODE_STRING': _UNICODE_STRING,
            '_EPROCESS': _EPROCESS,
            '_ETHREAD': _ETHREAD,
            '_HANDLE_TABLE': _HANDLE_TABLE,
            '_POOL_HEADER': _POOL_HEADER,
            '_OBJECT_HEADER': _OBJECT_HEADER,
            '_PSP_CID_TABLE': _PSP_CID_TABLE,
            '_FILE_OBJECT': _FILE_OBJECT,
            '_EX_FAST_REF': _EX_FAST_REF,
            '_CM_KEY_BODY': _CM_KEY_BODY,
            '_MMVAD_FLAGS': _MMVAD_FLAGS,
            '_MMVAD_FLAGS2': _MMVAD_FLAGS2,
            '_MMSECTION_FLAGS': _MMSECTION_FLAGS,
            '_LDR_DATA_TABLE_ENTRY': _LDR_DATA_TABLE_ENTRY,
            })

    profile.add_overlay(windows_overlay)

    # Pooltags for common objects (These are different in Win8).
    profile.add_constants(DRIVER_POOLTAG="Dri\xf6",
                          EPROCESS_POOLTAG="Pro\xe3",
                          FILE_POOLTAG="Fil\xe5",
                          SYMLINK_POOLTAG="Sym\xe2",
                          MODULE_POOLTAG="MmLd",
                          MUTANT_POOLTAG="Mut\xe1",
                          THREAD_POOLTAG='\x54\x68\x72\xe5',
                          )
