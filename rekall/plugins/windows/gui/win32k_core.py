# Rekall Memory Forensics
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
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

import logging
from rekall import utils
from rekall import obj
from rekall.plugins.overlays import basic
from rekall.plugins.overlays.windows import common
from rekall.plugins.windows.gui import constants


class _MM_SESSION_SPACE(obj.Struct):
    """A class for session spaces"""

    def processes(self):
        """Generator for processes in this session.

        A process is always associated with exactly
        one session.
        """
        for p in self.ProcessList.list_of_type(
            "_EPROCESS", "SessionProcessLinks"):
            yield p

    @property
    def Win32KBase(self):
        """Get the base address of the win32k.sys as mapped
        into this session's memory.

        Since win32k.sys is always the first image to be
        mapped, we can just grab the first list entry."""

        ## An exception may be generated when a process from a terminated
        ## session still exists in the active process list.
        try:
            return list(self.images())[0].Address
        except IndexError:
            return obj.NoneObject("No images mapped in this session")

    def images(self):
        """Generator for images (modules) loaded into
        this session's space"""
        for i in self.ImageList.list_of_type("_IMAGE_ENTRY_IN_SESSION", "Link"):
            yield i

    def _section_chunks(self, sec_name):
        """Get the win32k.sys section as an array of
        32-bit unsigned longs.

        @param sec_name: name of the PE section in win32k.sys
        to search for.

        @returns all chunks on a 4-byte boundary.
        """
        ## In the rare case when win32k.sys PE header is paged or corrupted
        ## thus preventing us from parsing the sections, use the fallback
        ## mechanism of just reading 5 MB (max size of win32k.sys) from the
        ## base of the kernel module.
        section_base = self.Win32KBase
        section_size = 0x500000

        dos_header = self.obj_profile._IMAGE_DOS_HEADER(
            offset=self.Win32KBase, vm=self.obj_vm)

        for section in dos_header.NTHeader.Sections:
            if section.Name == sec_name:
                section_base = section.VirtualAddress
                section_size = section.Misc.VirtualSize / 4
                break


        return self.obj_profile.Array(targetType="unsigned long",
                                      offset=section_base,
                                      count=section_size, vm=self.obj_vm)

    def find_gahti(self):
        """Find this session's gahti.

        This can potentially be much faster by searching for
        '\0' * sizeof(tagHANDLETYPEINFO) instead
        of moving on a dword aligned boundary through
        the section.
        """

        for chunk in self._section_chunks(".rdata"):
            if not chunk.is_valid():
                continue

            gahti = obj.Object("gahti", offset=chunk.obj_offset,
                               vm=self.obj_vm)

            ## The sanity check here is based on the fact that the first entry
            ## in the gahti is always for TYPE_FREE. The fnDestroy pointer will
            ## be NULL, the alloc tag will be an empty string, and the creation
            ## flags will be zero. We also then check the alloc tag of the first
            ## USER handle type which should be Uswd (TYPE_WINDOW).
            if (gahti.types[0].fnDestroy == 0 and
                    str(gahti.types[0].dwAllocTag) == '' and
                    gahti.types[0].bObjectCreateFlags == 0 and
                    str(gahti.types[1].dwAllocTag) == "Uswd"):
                return gahti

        return obj.NoneObject("Cannot find win32k!_gahti")

    def find_shared_info(self):
        """Find this session's tagSHAREDINFO structure.

        This structure is embedded in win32k's .data section,
        (i.e. not in dynamically allocated memory). Thus we
        iterate over each DWORD-aligned possibility and treat
        it as a tagSHAREDINFO until the sanity checks are met.
        """
        for chunk in self._section_chunks(".data"):
            # If the base of the value is paged
            if not chunk.is_valid():
                continue

            # Treat it as a shared info struct
            shared_info = obj.tagSHAREDINFO(
                offset=chunk.obj_offset, vm=self.obj_vm)

            # Sanity check it
            try:
                if shared_info.is_valid():
                    return shared_info
            except obj.InvalidOffsetError:
                pass

        return obj.NoneObject("Cannot find win32k!gSharedInfo")

class tagSHAREDINFO(obj.Struct):
    """A class for shared info blocks"""

    def is_valid(self):
        """The sanity checks for tagSHAREDINFO structures"""

        if not super(tagSHAREDINFO, self).is_valid():
            return False

        # The kernel's version of tagSHAREDINFO should always have
        # a zeroed-out shared delta member.
        if self.ulSharedDelta != 0:
            return False

        # The pointer to our server information structure must be valid
        if not self.psi.is_valid():
            return False

        # Annoying check, but required for some samples
        # whose psi is a valid pointer, but cbHandleTable
        # cannot be read due to objects that cross page
        # boundaries.
        if self.psi.cbHandleTable == None:
            return False

        if self.psi.cbHandleTable < 0x1000:
            return False

        # The final check is that the total size in bytes of the handle
        # table is equal to the size of a _HANDLEENTRY multiplied by the
        # number of _HANDLEENTRY structures.
        return (self.psi.cbHandleTable /
                    self.obj_vm.profile.get_obj_size("_HANDLEENTRY")
                == self.psi.cHandleEntries)

    def handles(self, filters=None):
        """Carve handles from the shared info block.

        @param filters: a list of callables that perform
        checks and return True if the handle should be
        included in output.
        """

        if filters == None:
            filters = []

        hnds = obj.Array(target="_HANDLEENTRY",
                         offset=self.aheList,
                         vm=self.obj_vm,
                         count=self.psi.cHandleEntries)

        for i, h in enumerate(hnds):

            # Sanity check the handle value if the handle Object
            # has not been freed.
            if not h.Free:
                if h.phead.h != (h.wUniq << 16) | (0xFFFF & i):
                    continue

            b = False

            # Run the filters and break if any tests fail
            for filt in filters:
                if not filt(h):
                    b = True
                    break

            if not b:
                yield h

class _HANDLEENTRY(obj.Struct):
    """A for USER handle entries"""

    def reference_object(self):
        """Reference the object this handle represents.

        If the object's type is not in our map, we don't know
        what type of object to instantiate so its filled with
        obj.NoneObject() instead.
        """

        object_map = dict(
            TYPE_WINDOW="tagWND",
            TYPE_HOOK="tagHOOK",
            TYPE_CLIPDATA="tagCLIPDATA",
            TYPE_WINEVENTHOOK="tagEVENTHOOK",
            TYPE_TIMER="tagTIMER",
            )

        object_type = object_map.get(str(self.bType), None)

        if not object_type:
            return obj.NoneObject("Cannot reference object type")

        return obj.Object(
            object_type, offset=self.phead, vm=self.obj_vm)

    @property
    def Free(self):
        """Check if the handle has been freed"""
        return str(self.bType) == "TYPE_FREE"

    @property
    def ThreadOwned(self):
        """Handles of these types are always thread owned"""
        return str(self.bType) in [
            'TYPE_WINDOW', 'TYPE_SETWINDOWPOS', 'TYPE_HOOK',
            'TYPE_DDEACCESS', 'TYPE_DDECONV', 'TYPE_DDEXACT',
            'TYPE_WINEVENTHOOK', 'TYPE_INPUTCONTEXT', 'TYPE_HIDDATA',
            'TYPE_TOUCH', 'TYPE_GESTURE']
    @property
    def ProcessOwned(self):
        """Handles of these types are always process owned"""
        return str(self.bType) in [
                                'TYPE_MENU', 'TYPE_CURSOR', 'TYPE_TIMER',
                                'TYPE_CALLPROC', 'TYPE_ACCELTABLE']
    @property
    def Thread(self):
        """Return the ETHREAD if its thread owned"""
        if self.ThreadOwned:
            return self.pOwner.\
                        dereference_as("tagTHREADINFO").\
                        pEThread.dereference()
        return obj.NoneObject("Cannot find thread")

    @property
    def Process(self):
        """Return the _EPROCESS if its process or thread owned"""
        if self.ProcessOwned:
            return self.pOwner.\
                        dereference_as("tagPROCESSINFO").\
                        Process.dereference()
        elif self.ThreadOwned:
            return self.pOwner.\
                        dereference_as("tagTHREADINFO").\
                        ppi.Process.dereference()
        return obj.NoneObject("Cannot find process")

class tagWINDOWSTATION(obj.Struct):
    """A class for Windowstation objects"""

    def is_valid(self):
        return (super(tagWINDOWSTATION, self).is_valid() and
                self.dwSessionId < 0xFF)

    @property
    def LastRegisteredViewer(self):
        """The EPROCESS of the last registered clipboard viewer"""
        return self.spwndClipViewer.head.pti.ppi.Process

    def AtomTable(self, vm=None):
        """This atom table belonging to this window
        station object"""
        return self.pGlobalAtomTable.dereference_as("_RTL_ATOM_TABLE",
                                                    vm=vm)

    @property
    def Interactive(self):
        """Check if a window station is interactive"""
        return not self.dwWSF_Flags & 4 # WSF_NOIO

    @property
    def Name(self):
        """Get the window station name.

        Since window stations are securable objects,
        and are managed by the same object manager as
        processes, threads, etc, there is an object
        header which stores the name.
        """
        object_hdr = self.obj_profile._OBJECT_HEADER(
            vm=self.obj_vm,
            offset=self.obj_offset - self.obj_profile.get_obj_offset(
                '_OBJECT_HEADER', 'Body')
            )

        return object_hdr.NameInfo.Name

    def traverse(self, vm=None):
        """A generator that yields window station objects"""

        # Include this object in the results.
        yield self

        # Now walk the singly-linked list.
        nextwinsta = self.rpwinstaNext.dereference(vm=vm)
        while nextwinsta.is_valid() and nextwinsta.v(vm=vm) != 0:
            yield nextwinsta
            nextwinsta = nextwinsta.rpwinstaNext.dereference(vm=vm)

    def desktops(self, vm=None):
        """A generator that yields the window station's desktops"""
        desk = self.rpdeskList.dereference(vm=vm)
        while desk.is_valid() and desk.v(vm=vm) != 0:
            yield desk
            desk = desk.rpdeskNext.dereference(vm=vm)

class tagDESKTOP(tagWINDOWSTATION):
    """A class for Desktop objects"""

    def is_valid(self):
        return  obj.Struct.is_valid(self) and self.dwSessionId < 0xFF

    @property
    def WindowStation(self):
        """Returns this desktop's parent window station"""
        return self.rpwinstaParent.dereference()

    @property
    def DeskInfo(self):
        """Returns the desktop info object"""
        return self.pDeskInfo.dereference()

    def threads(self):
        """Generator for _EPROCESS objects attached to this desktop"""
        for ti in self.PtiList.list_of_type("tagTHREADINFO", "PtiLink"):
            yield ti

    def hook_params(self):
        """ Parameters for the hooks() method.

        These are split out into a function so it can be
        subclassed by tagTHREADINFO.
        """
        return (self.DeskInfo.fsHooks, self.DeskInfo.aphkStart)

    def hooks(self):
        """Generator for tagHOOK info.

        Hooks are carved using the same algorithm, but different
        starting points for desktop hooks and thread hooks. Thus
        the algorithm is presented in this function and the starting
        point is acquired by calling hook_params (which is then sub-
        classed by tagTHREADINFO.
        """

        (fshooks, aphkstart) = self.hook_params()

        # Convert the WH_* index into a bit position for the fsHooks fields
        WHF_FROM_WH = lambda x: (1 << x + 1)

        for pos, (name, value) in enumerate(constants.MESSAGE_TYPES):
            # Is the bit for this WH_* value set ?
            if fshooks & WHF_FROM_WH(value):
                hook = aphkstart[pos].dereference()
                for hook in hook.traverse():
                    yield name, hook

    def windows(self, win, filter=lambda x: True, level=0):
        """Traverses windows in their Z order, bottom to top.

        @param win: an HWND to start. Usually this is the desktop
        window currently in focus.

        @param filter: a callable (usually lambda) to use for filtering
        the results. See below for examples:

        # only print subclassed windows
        filter = lambda x : x.lpfnWndProc == x.pcls.lpfnWndProc

        # only print processes named csrss.exe
        filter = lambda x : str(x.head.pti.ppi.Process.ImageFileName).lower() \
                                == "csrss.exe" if x.head.pti.ppi else False

        # only print processes by pid
        filter = lambda x : x.head.pti.pEThread.Cid.UniqueThread == 0x1020

        # only print visible windows
        filter = lambda x : 'WS_VISIBLE' not in x.get_flags()
        """
        seen = set()
        wins = []
        cur = win
        while cur.is_valid() and cur.v() != 0:
            if cur in seen:
                break
            seen.add(cur)
            wins.append(cur)
            cur = cur.spwndNext.dereference()
        while wins:
            cur = wins.pop()
            if not filter(cur):
                continue

            yield cur, level

            if cur.spwndChild.is_valid() and cur.spwndChild.v() != 0:
                for info in self.windows(
                    cur.spwndChild, filter=filter, level=level+1):
                    yield info

    def heaps(self):
        """Generator for the desktop heaps"""
        for segment in self.pheapDesktop.Heap.segments():
            for entry in segment.heap_entries():
                yield entry

    def traverse(self, vm=None):
        """Generator for next desktops in the list"""

        # Include this object in the results
        yield self
        # Now walk the singly-linked list
        nextdesk = self.rpdeskNext.dereference(vm=vm)
        while nextdesk.is_valid() and nextdesk.v() != 0:
            yield nextdesk
            nextdesk = nextdesk.rpdeskNext.dereference(vm=vm)

class tagWND(obj.Struct):
    """A class for window structures"""

    @property
    def IsClipListener(self):
        """Check if this window listens to clipboard changes"""
        return self.bClipboardListener.v()

    @property
    def ClassAtom(self):
        """The class atom for this window"""
        return self.pcls.atomClassName

    @property
    def SuperClassAtom(self):
        """The window's super class"""
        return self.pcls.atomNVClassName

    @property
    def Process(self):
        """The EPROCESS that owns the window"""
        return self.head.pti.ppi.Process.dereference()

    @property
    def Thread(self):
        """The ETHREAD that owns the window"""
        return self.head.pti.pEThread.dereference()

    @property
    def Visible(self):
        """Is this window visible on the desktop"""
        return 'WS_VISIBLE' in self.style

    def _get_flags(self, member, flags):

        if flags.has_key(member):
            return flags[member]

        return ','.join([n for (n, v) in flags.items() if member & v == v])

    @property
    def style(self):
        """The basic style flags as a string"""
        return self._get_flags(self.m('style').v(), constants.WINDOW_STYLES)

    @property
    def ExStyle(self):
        """The extended style flags as a string"""
        return self._get_flags(
            self.m('ExStyle').v(), constants.WINDOW_STYLES_EX)

class tagRECT(obj.Struct):
    """A class for window rects"""

    def get_tup(self):
        """Return a tuple of the rect's coordinates"""
        return (self.left, self.top, self.right, self.bottom)

class tagCLIPDATA(obj.Struct):
    """A class for clipboard objects"""

    def as_string(self, fmt):
        """Format the clipboard data as a string.

        @param fmt: the clipboard format.

        Note: we cannot simply override __str__ for this
        purpose, because the clipboard format is not a member
        of (or in a parent-child relationship with) the
        tagCLIPDATA structure, so we must pass it in as
        an argument.
        """

        if fmt == "CF_UNICODETEXT":
            encoding = "utf16"
        else:
            encoding = "utf8"

        return obj.String(
            offset=self.abData.obj_offset,
            vm=self.obj_vm, encoding=encoding,
            length=self.cbData)

    def as_hex(self):
        """Format the clipboard contents as a hexdump"""
        data = ''.join([chr(c) for c in self.abData])
        return "".join(["{0:#x}  {1:<48}  {2}\n".format(
                    self.abData.obj_offset + o, h, ''.join(c))
                        for o, h, c in utils.Hexdump(data)])

class tagTHREADINFO(tagDESKTOP):
    """A class for thread information objects"""

    def get_params(self):
        """Parameters for the _hooks() function"""
        return (self.fsHooks, self.aphkStart)

class tagHOOK(obj.Struct):
    """A class for message hooks"""

    def traverse(self):
        """Find the next hook in a chain"""
        hook = self
        while hook.is_valid() and hook.v() != 0:
            yield hook
            hook = hook.phkNext.dereference()

class tagEVENTHOOK(obj.Struct):
    """A class for event hooks"""

    @property
    def dwFlags(self):
        """Event hook flags need special handling so we can't use vtypes"""

        # First we shift the value
        f = self.m('dwFlags') >> 1

        flags = [
            name for (val, name) in constants.EVENT_FLAGS.items() if f & val]

        return '|'.join(flags)

class _RTL_ATOM_TABLE(obj.Struct):
    """A class for atom tables"""

    def __init__(self, **kwargs):
        """Give ourselves an atom cache for quick lookups"""
        self.atom_cache = {}
        super(_RTL_ATOM_TABLE, self).__init__(**kwargs)

    def is_valid(self):
        """Check for validity based on the atom table signature
        and the maximum allowed number of buckets"""
        return (super(_RTL_ATOM_TABLE, self).is_valid() and
                self.Signature == 0x6d6f7441 and
                self.NumBuckets < 0xFFFF)

    def atoms(self, vm=None):
        """Carve all atoms out of this atom table"""
        # The default hash buckets should be 0x25
        for bkt in self.Buckets:
            cur = bkt.dereference(vm=vm)
            while cur.is_valid() and cur.v(vm=vm) != 0:
                yield cur
                cur = cur.HashLink.dereference(vm=vm)

    def find_atom(self, atom_to_find):
        """Find an atom by its ID.

        @param atom_to_find: the atom ID (ushort) to find

        @returns an _RTL_ATOM_TALE_ENTRY object
        """

        # Use the cached results if they exist
        if self.atom_cache:
            return self.atom_cache.get(atom_to_find.v(), None)

        # Build the atom cache
        self.atom_cache = dict(
                (atom.Atom.v(), atom) for atom in self.atoms())

        return self.atom_cache.get(atom_to_find.v(), None)


class _RTL_ATOM_TABLE_ENTRY(obj.Struct):
    """A class for atom table entries"""

    @property
    def Pinned(self):
        """Returns True if the atom is pinned"""
        return self.Flags == 1

    def is_string_atom(self):
        """Returns True if the atom is a string atom
        based on its atom ID.

        A string atom has ID 0xC000 - 0xFFFF
        """
        return self.Atom >= 0xC000 and self.Atom <= 0xFFFF

    def is_valid(self):
        """Perform some sanity checks on the Atom"""
        if not super(_RTL_ATOM_TABLE_ENTRY, self).is_valid():
            return False

        # There is only one flag (and zero)
        if self.Flags not in (0, 1):
            return False
        # There is a maximum name length enforced
        return self.NameLength <= 255


class Win32GUIProfile(obj.ProfileModification):
    """Install win32 gui specific modifications."""

    @classmethod
    def modify(cls, profile):
        pass


class Win32kPluginMixin(object):
    """A mixin which loads the relevant win32k profile."""

    @classmethod
    def args(cls, parser):
        super(Win32kPluginMixin, cls).args(parser)
        parser.add_argument("--win32k_guid", default=None,
                            help="Force this profile to be used for Win32k.")

    def __init__(self, win32k_guid=None, **kwargs):
        super(Win32kPluginMixin, self).__init__(**kwargs)
        if self.session.win32k_profile:
            # Get the profile from the session cache.
            self.profile = self.session.win32k_profile

        else:
            # Find the proper win32k profile and merge in with this kernel
            # profile.
            if win32k_guid is None:
                scanner = self.session.plugins.version_scan(name_regex="win32k")
                for _, guid in scanner.ScanVersions():
                    try:
                        win32k_profile = self.session.LoadProfile(
                            "GUID/%s" % guid)
                        break

                    except IOError:
                        logging.info(
                            "Unable to find profile for win32k.sys: %s.", guid)

                        raise RuntimeError("No profile")

            else:
                win32k_profile = self.session.LoadProfile(win32k_guid)

            # The win32k types and kernel types interact with each other, so we
            # merge them here into a single profile.
            self.profile.merge(win32k_profile)
            self.session.win32k_profile = self.profile


class Win32k(basic.BasicClasses):
    """A profile for the Win32 GUI system."""

    METADATA = dict(os="windows")

    @classmethod
    def Initialize(cls, profile):
        super(Win32k, cls).Initialize(profile)

        # Select basic compiler model type.
        if profile.metadata("arch") == "AMD64":
            basic.ProfileLLP64.Initialize(profile)

        elif profile.metadata("arch") == "I386":
            basic.Profile32Bits.Initialize(profile)

        # Some constants - These will probably change in win8 which does not
        # allow non ascii tags.
        profile.add_constants(PoolTag_WindowStation="Win\xe4",
                              PoolTag_Atom="AtmT")

        profile.add_classes({
            'tagWINDOWSTATION': tagWINDOWSTATION,
            'tagDESKTOP': tagDESKTOP,
            '_RTL_ATOM_TABLE': _RTL_ATOM_TABLE,
            '_RTL_ATOM_TABLE_ENTRY': _RTL_ATOM_TABLE_ENTRY,
            'tagTHREADINFO': tagTHREADINFO,
            'tagHOOK': tagHOOK,
            '_LARGE_UNICODE_STRING': common._UNICODE_STRING,
            'tagWND': tagWND,
            'tagSHAREDINFO': tagSHAREDINFO,
            '_HANDLEENTRY': _HANDLEENTRY,
            'tagEVENTHOOK': tagEVENTHOOK,
            'tagRECT': tagRECT,
            'tagCLIPDATA': tagCLIPDATA,
            })

        version = ".".join(profile.metadatas('major', 'minor'))
        architecture = profile.metadata("arch")

        ## Windows 7 and above
        if version >= "6.1":
            num_handles = len(constants.HANDLE_TYPE_ENUM_SEVEN)
        else:
            num_handles = len(constants.HANDLE_TYPE_ENUM)

        # Add autogenerated vtypes for the different versions.
        if version.startswith("6.1"):  # Windows 7
            from rekall.plugins.windows.gui.vtypes import win7

            profile = win7.Win32GUIWin7.modify(profile)
        else:
            from rekall.plugins.windows.gui.vtypes import xp

            profile = xp.XP2003x86BaseVTypes.modify(profile)

        # The type we want to use is not the same as the one already defined
        # see http://code.google.com/p/volatility/issues/detail?id=131
        profile.add_overlay({
                'gahti': [None, {
                        'types': [0, ['Array', dict(
                                    count=num_handles,
                                    target='tagHANDLETYPEINFO')]],
                        }],

                '_RTL_ATOM_TABLE': [None, {
                        'Signature': [0x0, ['unsigned long']],
                        'NumBuckets': [0xC, ['unsigned long']],
                        'Buckets': [0x10, ['Array', dict(
                                    count=lambda x: x.NumBuckets,
                                    target="Pointer",
                                    target_args=dict(
                                        target='_RTL_ATOM_TABLE_ENTRY')
                                    )]],
                        }],
                '_RTL_ATOM_TABLE_ENTRY': [None, {
                        'Name': [None, ['UnicodeString', dict(
                                    encoding='utf16',
                                    length=lambda x: x.NameLength * 2)]],
                        }],
                'tagWIN32HEAP': [None, {
                        'Heap': [0, ['_HEAP']],
                        }],
                'tagCLIPDATA' : [None, {
                        'cbData' : [0x08, ['unsigned int']],
                        'abData' : [0x0C, ['Array', dict(
                                    count=lambda x: x.cbData,
                                    target='unsigned char')]],
                        }],
                'tagEVENTHOOK' : [0x30, {
                        'phkNext' : [0xC, ['pointer', ['tagEVENTHOOK']]],
                        'eventMin' : [0x10, ['Enumeration', dict(
                                    target='unsigned long',
                                    choices=constants.EVENT_ID_ENUM)]],

                        'eventMax' : [0x14, ['Enumeration', dict(
                                    target='unsigned long',
                                    choices=constants.EVENT_ID_ENUM)]],

                        'dwFlags' : [0x18, ['unsigned long']],
                        'idProcess' : [0x1C, ['unsigned long']],
                        'idThread' : [0x20, ['unsigned long']],
                        'offPfn' : [0x24, ['Pointer', dict(target="Void")]],
                        'ihmod' : [0x28, ['long']],
                        }],

                'tagHANDLETYPEINFO' : [12, {
                        'fnDestroy' : [0, ['pointer', ['void']]],
                        'dwAllocTag' : [4, ['String', dict(length=4)]],
                        'bObjectCreateFlags' : [8, ['Flags', dict(
                                    target='unsigned char',
                                    bitmap={
                                        'OCF_THREADOWNED': 0,
                                        'OCF_PROCESSOWNED': 1,
                                        'OCF_MARKPROCESS': 2,
                                        'OCF_USEPOOLQUOTA': 3,
                                        'OCF_DESKTOPHEAP': 4,
                                        'OCF_USEPOOLIFNODESKTOP': 5,
                                        'OCF_SHAREDHEAP': 6,
                                        'OCF_VARIABLESIZE': 7}
                                    )]],
                        }],
                })

        # The 64 bit versions of these structs just have their members in
        # different offsets.
        if architecture == "AMD64":
            profile.add_overlay({
                    '_RTL_ATOM_TABLE': [None, {
                            'NumBuckets': [0x18, ['unsigned long']],
                            'Buckets': [0x20, ['Array', dict(
                                        count=lambda x: x.NumBuckets,
                                        target="Pointer",
                                        target_args=dict(
                                            target='_RTL_ATOM_TABLE_ENTRY')
                                        )]],
                            }],

                    'tagCLIPDATA' : [None, {
                            'cbData' : [0x10, None],
                            'abData' : [0x14, None],
                            }],
                    'tagEVENTHOOK' : [0x60, {
                            'phkNext' : [0x18, None],
                            'eventMin' : [0x20, None],
                            'eventMax' : [0x24, None],
                            'dwFlags' : [0x28, None],
                            'idProcess' : [0x2C, None],
                            'idThread' : [0x30, None],
                            'offPfn' : [0x40, None],
                            'ihmod' : [0x48, None],
                            }],
                    'tagHANDLETYPEINFO' : [16, {
                            'dwAllocTag' : [8, None],
                            'bObjectCreateFlags' : [12, None],
                            }],
                    })

        # This field appears in the auto-generated vtypes for all OS except XP
        if architecture == "I386" and version[:2] == (5, 1):
            profile.add_overlay({
                    '_MM_SESSION_SPACE': [None, {
                            # nt!MiDereferenceSession
                            'ResidentProcessCount': [0x248, ['long']],
                            }]})

        return profile
