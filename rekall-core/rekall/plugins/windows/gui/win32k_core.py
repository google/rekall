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
from rekall import kb
from rekall import utils
from rekall import obj
from rekall.plugins.overlays.windows import pe_vtypes
from rekall.plugins.windows.gui import constants
from rekall.plugins.windows.gui.vtypes import xp


win32k_overlay = {
    '_RTL_ATOM_TABLE_ENTRY': [None, {
        'Name': [None, ['UnicodeString', dict(
            encoding='utf16',
            length=lambda x: x.NameLength * 2)]],

        'ReferenceCount': lambda x: (x.m("ReferenceCount") or
                                     x.m("Reference.ReferenceCount")),

        'Pinned': lambda x: x.m("Flags") == 1 or x.m("Reference.Flags") == 1,
        }],

    'tagWINDOWSTATION': [None, {
        'pGlobalAtomTable': [None, ['Pointer', dict(
            target="_RTL_ATOM_TABLE"
        )]],

        'pClipBase': [None, ["Pointer", dict(
            target="Array",
            target_args=dict(
                target='tagCLIP',
                count=lambda x: x.cNumClipFormats
            )
        )]],
    }],

    'tagDESKTOP': [None, {
        'pheapDesktop': [None, ['Pointer', dict(
            target="_HEAP"
        )]],
    }],

    'tagSHAREDINFO': [None, {
        'aheList': [None, ['Pointer', dict(
            target='Array',
            target_args=dict(
                target="_HANDLEENTRY",
                count=lambda x: x.psi.cHandleEntries,
                )
            )]],
        }],

    '_HEAD': [None, {
        'h': [None, ['unsigned int']],
    }],

    "tagTHREADINFO": [None, {
        "pEThread": [None, ["Pointer", dict(
            target="_ETHREAD")]],
        }],

    "tagHOOK": [None, {
        "flags": [None, ["Flags", dict(
            bitmap=utils.MaskMapFromDefines(
                """
// 9/18/2011
// http://forum.sysinternals.com/enumerate-windows-hooks_topic23877.html#122641
#define HF_GLOBAL   0x0001
#define HF_ANSI   0x0002
#define HF_NEEDHC_SKIP   0x0004
#define HF_HUNG   0x0008
#define HF_HOOKFAULTED   0x0010
#define HF_NOPLAYBACKDELAY   0x0020
#define HF_WX86KNOWINDOWLL   0x0040
#define HF_DESTROYED   0x0080
// mask for valid flags
#define HF_VALID   0x00FF
"""))
                     ]],
    }],

    "_HANDLEENTRY": [None, {
        "pOwner": [None, ["Pointer", dict(
            target="tagTHREADINFO")]],

        "bFlags": [None, ["Flags", dict(
            target="byte",
            bitmap=utils.MaskMapFromDefines("""
// 8/17/2011
// http://www.reactos.org/wiki/Techwiki:Win32k/HANDLEENTRY
// HANDLEENTRY.bFlags
#define HANDLEF_DESTROY        0x01
#define HANDLEF_INDESTROY      0x02
#define HANDLEF_INWAITFORDEATH 0x04
#define HANDLEF_FINALDESTROY   0x08
#define HANDLEF_MARKED_OK      0x10
#define HANDLEF_GRANTED        0x20
// mask for valid flags
#define HANDLEF_VALID   0x3F
"""),
            )]],

        'bType': [None, ['Enumeration', dict(
            target='unsigned char',
            choices=constants.HANDLE_TYPE_ENUM,
            )]],
        }],

    '_THRDESKHEAD': [None, {
        "h": [None, ["unsigned int"]],
        }],
}

# Reference:
# http://reactos.org/wiki/Techwiki:Win32k/structures

win32k_undocumented_AMD64 = {
    # TODO: This is a hack! I do not really understand why this struct is
    # sometimes very different. I have an image with the Buckets field at offset
    # 0x220. This needs to be implemented using generate_types.

    # win32k defines NTOS_MODE_USER which makes this struct different from the
    # nt kernel one.
    # http://doxygen.reactos.org/d5/df7/ndk_2rtltypes_8h_source.html
    '_RTL_ATOM_TABLE': [None, {
        # Technically the number of buckets is specified by this field, but this
        # field varies a lot between operating systems:

        # - Win7: 0x18
        # - Win8.1: 0x1c (like the kernel _RTL_ATOM_TABLE)

        # It is usually around 25 - if we overestimate we just work through more
        # buckets - it does not matter. If we underestimate however, we will
        # miss some atoms. We just set it to a large enough value here.

        'NumberOfBuckets': lambda x: 0x35,  # Usually this is 0x25.

        # 'NumberOfBuckets': [0x18, ["unsigned long", {}]],
        'Buckets': [0x20, ['Array', dict(
            count=lambda x: x.NumberOfBuckets,
            max_count=100,
            target="Pointer",
            target_args=dict(
                target='_RTL_ATOM_TABLE_ENTRY')
            )]],
        }],

    'tagEVENTHOOK' : [0x60, {
        'phkNext' : [0x18, ['Pointer', dict(
            target='tagEVENTHOOK'
            )]],
        'eventMin' : [0x20, ['Enumeration', dict(
            target='unsigned long',
            choices=constants.EVENT_ID_ENUM)]],

        'eventMax' : [0x24, ['Enumeration', dict(
            target='unsigned long',
            choices=constants.EVENT_ID_ENUM)]],

        'dwFlags' : [0x28, ['unsigned long']],
        'idProcess' : [0x2C, ['unsigned long']],
        'idThread' : [0x30, ['unsigned long']],
        'offPfn' : [0x40, ['Pointer', dict(target="Void")]],
        'ihmod' : [0x48, ['long']],
        }],

    'tagHANDLETYPEINFO' : [16, {
        'fnDestroy' : [0, ['Pointer', dict(
            target="Function"
        )]],
        'dwAllocTag' : [8, ['String', dict(length=4)]],
        'bObjectCreateFlags' : [12, ['Flags', dict(
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
}

win32k_undocumented_I386 = {
    '_RTL_ATOM_TABLE': [None, {
        'NumberOfBuckets': [0xC, ['unsigned long']],
        'Buckets': [0x10, ['Array', dict(
            count=lambda x: x.NumberOfBuckets,
            max_count=100,
            target="Pointer",
            target_args=dict(
                target='_RTL_ATOM_TABLE_ENTRY')
            )]],
        }],

    'tagEVENTHOOK' : [0x30, {
        'phkNext' : [0xC, ['Pointer', dict(
            target='tagEVENTHOOK'
            )]],
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
        'fnDestroy' : [0, ['Pointer', dict(
            target="Function"
        )]],
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
    }


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

    @utils.safe_property
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

        object_type = object_map.get(str(self.bType))
        if object_type is None:
            return obj.NoneObject("Cannot reference object type")

        return self.obj_profile.Object(
            object_type, offset=self.phead, vm=self.obj_vm)

    @utils.safe_property
    def Free(self):
        """Check if the handle has been freed"""
        return str(self.bType) == "TYPE_FREE"

    @utils.safe_property
    def ThreadOwned(self):
        """Handles of these types are always thread owned"""
        return str(self.bType) in [
            'TYPE_WINDOW', 'TYPE_SETWINDOWPOS', 'TYPE_HOOK',
            'TYPE_DDEACCESS', 'TYPE_DDECONV', 'TYPE_DDEXACT',
            'TYPE_WINEVENTHOOK', 'TYPE_INPUTCONTEXT', 'TYPE_HIDDATA',
            'TYPE_TOUCH', 'TYPE_GESTURE']
    @utils.safe_property
    def ProcessOwned(self):
        """Handles of these types are always process owned"""
        return str(self.bType) in [
            'TYPE_MENU', 'TYPE_CURSOR', 'TYPE_TIMER',
            'TYPE_CALLPROC', 'TYPE_ACCELTABLE']

    @utils.safe_property
    def Thread(self):
        """Return the ETHREAD if its thread owned"""
        if self.ThreadOwned:
            return self.pOwner.\
                        dereference_as("tagTHREADINFO").\
                        pEThread.dereference()
        return obj.NoneObject("Cannot find thread")

    @utils.safe_property
    def Process(self):
        """Return the _EPROCESS if its process or thread owned"""
        if self.ProcessOwned:
            return (self.pOwner.
                    dereference_as("tagPROCESSINFO").
                    Process.dereference())

        elif self.ThreadOwned:
            return (self.m("pOwner.pEThread.ThreadsProcess") or
                    self.pOwner.ppi.Process.dereference() or
                    self.pOwner.pEThread.Tcb.Process.dereference_as(
                        "_EPROCESS"))

        return obj.NoneObject("Cannot find process")


class tagWINDOWSTATION(obj.Struct):
    """A class for Windowstation objects"""

    def is_valid(self):
        return (super(tagWINDOWSTATION, self).is_valid() and
                self.dwSessionId < 0xFF)

    @utils.safe_property
    def LastRegisteredViewer(self):
        """The EPROCESS of the last registered clipboard viewer"""
        return self.m("spwndClipViewer.head.pti.ppi.Process")

    @utils.safe_property
    def Interactive(self):
        """Check if a window station is interactive"""
        return not self.dwWSF_Flags & 4 # WSF_NOIO

    @utils.safe_property
    def Name(self):
        """Get the window station name.

        Since window stations are securable objects, and are managed by the same
        object manager as processes, threads, etc, there is an object header
        which stores the name.
        """
        object_hdr = self.obj_session.profile._OBJECT_HEADER(
            vm=self.obj_vm,
            offset=self.obj_offset - self.obj_session.profile.get_obj_offset(
                '_OBJECT_HEADER', 'Body')
            )

        return object_hdr.NameInfo.Name

    def desktops(self):
        """A generator that yields the window station's desktops"""
        return self.rpdeskList.walk_list("rpdeskNext")


class tagDESKTOP(tagWINDOWSTATION):
    """A class for Desktop objects"""

    def is_valid(self):
        return  obj.Struct.is_valid(self) and self.dwSessionId < 0xFF

    @utils.safe_property
    def WindowStation(self):
        """Returns this desktop's parent window station"""
        return self.rpwinstaParent.dereference()

    @utils.safe_property
    def DeskInfo(self):
        """Returns the desktop info object"""
        return self.pDeskInfo.dereference()

    def threads(self):
        """Generator for _EPROCESS objects attached to this desktop"""
        for ti in self.PtiList.list_of_type("tagTHREADINFO", "PtiLink"):
            yield ti

    def hooks(self):
        """Generator for tagHOOK info."""
        fsHooks = self.DeskInfo.fsHooks

        for pos, (name, value) in enumerate(constants.MESSAGE_TYPES):
            # Is the bit for this message type WH_* value set ?
            if fsHooks & (1 << value + 1):
                for hook in self.DeskInfo.aphkStart[pos].walk_list("phkNext"):
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

    @utils.safe_property
    def IsClipListener(self):
        """Check if this window listens to clipboard changes"""
        return self.bClipboardListener.v()

    @utils.safe_property
    def ClassAtom(self):
        """The class atom for this window"""
        return self.pcls.atomClassName

    @utils.safe_property
    def SuperClassAtom(self):
        """The window's super class"""
        return self.pcls.atomNVClassName

    @utils.safe_property
    def Process(self):
        """The EPROCESS that owns the window"""
        return self.head.pti.ppi.Process.dereference()

    @utils.safe_property
    def Thread(self):
        """The ETHREAD that owns the window"""
        return self.head.pti.pEThread.dereference()

    @utils.safe_property
    def Visible(self):
        """Is this window visible on the desktop"""
        return 'WS_VISIBLE' in self.style

    def _get_flags(self, member, flags):

        if flags.has_key(member):
            return flags[member]

        return ','.join([n for (n, v) in flags.items() if member & v == v])

    @utils.safe_property
    def style(self):
        """The basic style flags as a string"""
        return self._get_flags(self.m('style').v(), constants.WINDOW_STYLES)

    @utils.safe_property
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


class tagTHREADINFO(obj.Struct):
    """A class for thread information objects"""

    def hooks(self):
        """Generator for tagHOOK info."""
        fsHooks = self.fsHooks

        for pos, (name, value) in enumerate(constants.MESSAGE_TYPES):
            # Is the bit for this message type WH_* value set ?
            if fsHooks & (1 << value + 1):
                for hook in self.aphkStart[pos].walk_list("phkNext"):
                    yield name, hook


class tagEVENTHOOK(obj.Struct):
    """A class for event hooks"""

    @utils.safe_property
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
                self.NumberOfBuckets < 0xFFFF)

    def atoms(self, vm=None):
        """Carve all atoms out of this atom table"""
        for bucket in self.Buckets:
            for entry in bucket.deref(vm=vm).walk_list("HashLink"):
                if entry.Atom < 0xf000:
                    yield entry

    def find_atom(self, atom_to_find, use_cache=False):
        """Find an atom by its ID.

        @param atom_to_find: the atom ID (ushort) to find

        @returns an _RTL_ATOM_TALE_ENTRY object
        """
        atom_to_find = int(atom_to_find)
        not_found = obj.NoneObject("Atom not found")

        # Use the cached results if they exist
        if use_cache:
            if self.atom_cache:
                return self.atom_cache.get(atom_to_find, not_found)

            # Build the atom cache
            self.atom_cache = dict(
                (int(atom.Atom), atom) for atom in self.atoms())

            return self.atom_cache.get(atom_to_find, not_found)
        else:
            # We often instantiate this atom table once - in this case its not
            # worth caching it.
            for atom in self.atoms():
                if atom.Atom == atom_to_find:
                    return atom

        return not_found


class _RTL_ATOM_TABLE_ENTRY(obj.Struct):
    """A class for atom table entries"""

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


class Win32kPluginMixin(object):
    """A mixin which loads the relevant win32k profile."""

    @classmethod
    def args(cls, parser):
        super(Win32kPluginMixin, cls).args(parser)
        parser.add_argument("--win32k_profile", default=None,
                            help="Force this profile to be used for Win32k.")

    def _is_valid(self, profile):
        """Returns true if the profile is a valid win32k one."""
        return profile.get_constant("grpWinStaList")

    def __init__(self, win32k_profile=None, **kwargs):
        super(Win32kPluginMixin, self).__init__(**kwargs)

        # For the address resolver to load this GUID.
        if win32k_profile:
            self.session.SetCache("win32k_profile", win32k_profile)

        # Ask the address resolver to load this profile.
        module = self.session.address_resolver.GetModuleByName("win32k")
        self.win32k_profile = module.profile

        # If the resolver loads the dummy profile this is not good enough.
        if not self._is_valid(self.win32k_profile):
            raise RuntimeError("Unable to load the profile for Win32k.sys")


class Win32k(pe_vtypes.BasicPEProfile):
    """A profile for the Win32 GUI system."""

    guessed_types = False

    @staticmethod
    def _LoadExempler(profile):
        # Prior to Windows 7, Microsoft did not release symbols for win32k
        # structs. However, we know that these are basically the same across
        # different versions. Here we just copy them from the windows 7
        # profiles.
        arch = profile.metadata("arch")
        if arch == "AMD64":
            exempler = ("win32k/GUID/"
                        "99227A2085CE41969CD5A06F7CC20F522")
        else:
            exempler = ("win32k/GUID/"
                        "18EB20F5448A47F5B850023FEE0B24D62")

        result = profile.session.LoadProfile(exempler)
        if result == None:
            raise RuntimeError("Unable to load exempler profile %s" % exempler)

        return result

    @classmethod
    def Initialize(cls, profile):
        super(Win32k, cls).Initialize(profile)

        # Merge the kernel's symbols for _RTL_ATOM_TABLE etc.
        profile.merge(profile.session.profile)

        # Some constants - These will probably change in win8 which does not
        # allow non ascii tags.
        profile.add_constants(dict(PoolTag_WindowStation="Win\xe4",
                                   PoolTag_Atom="AtmT"))

        profile.add_classes({
            'tagWINDOWSTATION': tagWINDOWSTATION,
            'tagDESKTOP': tagDESKTOP,
            '_RTL_ATOM_TABLE': _RTL_ATOM_TABLE,
            '_RTL_ATOM_TABLE_ENTRY': _RTL_ATOM_TABLE_ENTRY,
            'tagTHREADINFO': tagTHREADINFO,
            'tagWND': tagWND,
            '_HANDLEENTRY': _HANDLEENTRY,
            'tagEVENTHOOK': tagEVENTHOOK,
            'tagRECT': tagRECT,
            'tagCLIPDATA': tagCLIPDATA,
            })

        profile.add_overlay(win32k_overlay)
        if profile.metadata("arch") == "AMD64":
            profile.add_overlay(win32k_undocumented_AMD64)
        else:
            profile.add_overlay(win32k_undocumented_I386)

        exempler = None
        required_types = ["tagWINDOWSTATION", "tagDESKTOP", "tagTHREADINFO",
                          "tagWND", "tagDESKTOPINFO", "tagPROCESSINFO",
                          "tagSHAREDINFO", "_HANDLEENTRY", "_HEAD", "tagHOOK",
                          "_THRDESKHEAD", "_WNDMSG", "tagSERVERINFO"]
        for item in required_types:
            if not profile.has_type(item):
                # Mark the profile as guessed - its not as good as the real
                # thing, but its a starting point where win32k_autodetect can
                # start with.
                profile.guessed_types = True
                if exempler is None:
                    win7_profile = cls._LoadExempler(profile)

                profile.vtypes[item] = win7_profile.vtypes[item]

        # Specific support for xp types.
        version = profile.metadata('version')
        arch = profile.metadata("arch")

        if version < 6.0:
            if arch == "I386":
                profile.add_types(xp.vtypes_xp_32)
            else:
                profile.add_types(xp.vtypes_xp_64)

        if profile.guessed_types:
            profile.session.logging.debug(
                "Win32k profile is incomplete - attempting autodetection.")

            profile.add_overlay(
                profile.session.plugins.win32k_autodetect().GetWin32kOverlay(
                    profile))

        # The below code needs refactoring.
        return profile

        # Add autogenerated vtypes for the different versions.
        if version.startswith("6.1"):  # Windows 7
            from rekall.plugins.windows.gui.vtypes import win7

            profile = win7.Win32GUIWin7.modify(profile)
        else:
            profile = xp.XP2003x86BaseVTypes.modify(profile)

        # The type we want to use is not the same as the one already defined
        # see http://code.google.com/p/volatility/issues/detail?id=131
        profile.add_overlay({
                'gahti': [None, {
                        'types': [0, ['Array', dict(
                                    count=num_handles,
                                    target='tagHANDLETYPEINFO')]],
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
                })

        # The 64 bit versions of these structs just have their members in
        # different offsets.
        if architecture == "AMD64":
            profile.add_overlay({
                    '_RTL_ATOM_TABLE': [None, {
                            'NumberOfBuckets': [0x18, ['unsigned long']],
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


class Win32kHook(kb.ParameterHook):
    """Guess the version of win32k.sys from the index.

    NOTE: Win32k needs special attention because it is often not easily
    detected.
    """
    name = "win32k_profile"

    def calculate(self):
        # Require at least 3 comparison points to be matched.
        for _, guess in self.session.plugins.guess_guid(
                module="win32k", minimal_match=3).GuessProfiles():
            return guess
