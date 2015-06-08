# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
# Copyright 2014 Google Inc. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License
# along with Rekall.  If not, see <http://www.gnu.org/licenses/>.
#

"""Analyzes User handles registered with the Win32k Subsystem.

Windows allows user applications to register handles with the GUI subsystem. The
GUI subsystem can then call back into the user code for various purposes. The
Win32k allocates tag* structures for each user object that is registered. These
allocations exist on the win32k heap.

In this module we enumerate the heap and extract the tag* objects which
correspond to each heap allocation. This allows us to examine these allocations
in more detail.

One of the user handles is tagEVENTHOOK. A user application can register a hook
callback with SetWindowsHookEx(). This invokes a callback when an event is seen
(e.g. keyboard press - for a key logger) or desktop switch. Since tagEVENTHOOK
is just another user object, we can leverage the yser handles plugin to retrieve
all hooks.

References:
http://mista.nu/research/mandt-win32k-paper.pdf

http://volatility-labs.blogspot.de/2012/09/movp-31-detecting-malware-hooks-in.html
"""

import re
from rekall import obj
from rekall.plugins.windows import common
from rekall.plugins.windows.gui import constants
from rekall.plugins.windows.gui import win32k_core


class UserHandles(win32k_core.Win32kPluginMixin,
                  common.WinProcessFilter):
    """Dump the USER handle tables"""

    name = "userhandles"

    @classmethod
    def args(cls, parser):
        super(UserHandles, cls).args(parser)
        parser.add_argument(
            "--type", default=None,
            help="Filter handle type by this Regular Expression.")

        parser.add_argument("--free", default=False, type="Boolean",
                            help="Also include free handles.")

    def __init__(self, type=None, free=False, **kwargs):
        super(UserHandles, self).__init__(**kwargs)
        if type:
            type = re.compile(type, re.I)
        self.type = type
        self.free = free

    def handles(self):
        """A Generator of filtered handles."""
        for session in self.session.plugins.sessions().session_spaces():
            pids = set()
            if self.filtering_requested:
                pids = set([x.pid for x in self.filter_processes()])

            shared_info = self.win32k_profile.get_constant_object(
                "gSharedInfo",
                target="tagSHAREDINFO",
                vm=session.obj_vm)

            for handle in shared_info.aheList:
                # Do not show free handles if requested.
                if handle.bType == "TYPE_FREE" and not self.free:
                    continue

                # Skip pids that do not match.
                if (self.filtering_requested and
                        handle.Process.UniqueProcessId not in pids):
                    continue

                # Allow the user to match of handle type.
                if self.type and not self.type.search(str(handle.bType)):
                    continue

                yield session, shared_info, handle

    def render(self, renderer):
        current_session = None

        for session, shared_info, handle in self.handles():
            if current_session != session.SessionId:
                current_session = session.SessionId

                renderer.section()
                renderer.format(
                    "SharedInfo: {0:#x}, SessionId: {1} Shared delta: {2}\n",
                    shared_info, session.SessionId,
                    shared_info.ulSharedDelta,
                )

                renderer.format(
                    "aheList: {0:#x}, Table size: {1:#x}, Entry size: {2:#x}\n",
                    shared_info.aheList,
                    shared_info.psi.cbHandleTable,
                    shared_info.m("HeEntrySize") or
                    shared_info.obj_vm.profile.get_obj_size("_HANDLEENTRY")
                    )

                renderer.table_header(
                    [("_HANDLEENTRY", "handle_entry", "[addrpad]"),
                     ("_HEAD", "object", "[addrpad]"),
                     ("Handle", "handle", "[addr]"),
                     ("bType", "type", "20"),
                     ("Flags", "flags", "^8"),
                     ("Thread", "thread", "^8"),
                     ("Process", "process", "5"),
                     ("Process Name", "process_name", ""),
                    ])

            renderer.table_row(
                handle,
                handle.phead.deref(),
                handle.phead.h or 0,
                handle.bType,
                handle.bFlags,
                handle.Thread.Cid.UniqueThread,
                handle.Process.pid,
                handle.Process.name)


class WinEventHooks(win32k_core.Win32kPluginMixin,
                    common.WinProcessFilter):
    """Print details on windows event hooks"""

    name = "eventhooks"

    def render(self, renderer):
        handle_plugin = self.session.plugins.userhandles(type="WINEVENTHOOK")
        for session, _, handle in handle_plugin.handles():
            renderer.section()

            renderer.format(
                "Handle: {0:#x}, Object: {1:#x}, Session: {2}\n",
                handle.phead.h,
                handle.phead,
                session.SessionId)

            renderer.format(
                "Type: {0}, Flags: {1}, Thread: {2}, Process: {3} ({4})\n",
                handle.bType,
                handle.bFlags,
                handle.Thread.Cid.UniqueThread,
                handle.Process.UniqueProcessId,
                handle.Process.name,
                )

            event_hook = handle.reference_object()
            renderer.format(
                "eventMin: {0:#x} {1}\neventMax: {2:#x} {3}\n",
                event_hook.eventMin,
                event_hook.eventMin,
                event_hook.eventMax,
                event_hook.eventMax,
                )

            renderer.format(
                "Flags: {0}, offPfn: {1:#x}, idProcess: {2}, idThread: {3}\n",
                event_hook.dwFlags,
                event_hook.offPfn,
                event_hook.idProcess,
                event_hook.idThread,
                )

            ## Work out the WindowStation\Desktop path by the handle
            ## owner (thread or process)

            renderer.format("ihmod: {0}\n", event_hook.ihmod)


class Gahti(win32k_core.Win32kPluginMixin,
            common.WindowsCommandPlugin):
    """Dump the USER handle type information."""

    name = "gahti"

    def gahti(self, session):
        return self.win32k_profile.get_constant_object(
            "gahti",
            target="IndexedArray",
            target_args=dict(
                index_table=constants.HANDLE_TYPE_ENUM_SEVEN,
                target="tagHANDLETYPEINFO",
                count=20 if self.profile.metadata("version") < 6.1 else 22
                ),
            vm=session.obj_vm,
            )

    def render(self, renderer):
        renderer.table_header(
            [("Session", "session", ">8"),
             ("Type", "type", "20"),
             ("Tag", "tag", "8"),
             ("fnDestroy", "fnDestroy", "[addrpad]"),
             ("Flags", "flags", ""),
            ])

        for session in self.session.plugins.sessions().session_spaces():
            for handle in self.gahti(session):
                renderer.table_row(
                    session.SessionId,
                    handle.obj_name,
                    handle.dwAllocTag,
                    handle.fnDestroy,
                    handle.bObjectCreateFlags)



class WinMessageHooks(win32k_core.Win32kPluginMixin,
                      common.WindowsCommandPlugin):
    """List desktop and thread window message hooks."""

    name = "messagehooks"

    def __init__(self, **kwargs):
        super(WinMessageHooks, self).__init__(**kwargs)
        self.handles = {}
        self.cc = self.session.plugins.cc()

    def atom_number_from_ihmod(self, session, ihmod):
        """Resolve the module name from the ihmod field.

        The ihmod is an index into the array located at
        "win32k!aatomSysLoaded". This array contains the atom number. We need to
        use the atom number to resolve the string which is the module name.
        """
        atom_list = self.win32k_profile.get_constant_object(
            "aatomSysLoaded",
            target="Array",
            target_args=dict(
                target="unsigned short",
                ),
            vm=session.obj_vm
            )

        return atom_list[ihmod]

    def module_name_from_hook(self, global_atom_table, session, hook):
        ihmod = hook.ihmod
        if ihmod == -1:
            # Return the owner process.
            process = self.get_owner(session, hook)
            if process:
                # We need to resolve the address using the process AS.
                self.cc.SwitchProcessContext(process)
                return self.session.address_resolver.format_address(
                    hook.offPfn, max_distance=1e6)

            return obj.NoneObject()

        atom_num = self.atom_number_from_ihmod(session, ihmod)
        module_name = global_atom_table.get(atom_num)
        if module_name:
            module_name = module_name.Name
        else:
            module_name = ihmod

        return module_name

    def get_owner(self, session, hook):
        owner = hook.m("head.pti.pEThread.Tcb.Process").dereference_as(
            "_EPROCESS")
        if owner:
            return owner

        session_id = session.SessionId.v()
        self._build_handle_cache()
        handle = hook.head.h.v()
        handle_entry = self.handles.get(
            (session_id, handle), obj.NoneObject(
                "Unknown handle %s", handle))

        return handle_entry.pOwner.ppi.Process

    def get_owner_string(self, session, hook):
        owner = self.get_owner(session, hook)
        if owner:
            return "%s (%s)" % (owner.name, owner.pid)

    def _build_handle_cache(self):
        """Builds a cache of user handles for hooks."""
        if not self.handles:
            userhandles = self.session.plugins.userhandles()
            for s, _, handle in userhandles.handles():
                key = (s.SessionId.v(), handle.phead.h.v())
                self.handles[key] = handle

    def render(self, renderer):
        renderer.table_header(
            [dict(name="tagHOOK(V)", cname="offset", style="address"),
             ("Sess", "session", ""),
             ("Owner", "owner", "30"),
             ("Thread", "thread", "30"),
             ("Filter", "filter", "15"),
             ("Flags", "flags", "10"),
             dict(name="Function", cname="function", style="address"),
             ("Module", "module", ""),
            ])

        atoms_plugin = self.session.plugins.atoms()
        for session in self.session.plugins.sessions().session_spaces():

            global_atom_table = dict(
                (x.Atom, x) for _, x in atoms_plugin.session_atoms(session))

            # Find the hooks in each desktop.
            windows_stations_plugin = self.session.plugins.windows_stations()
            for station in windows_stations_plugin.stations_in_session(session):
                for desktop in station.desktops():

                    # First report all global hooks in the desktop.
                    for hook_name, hook in desktop.hooks():
                        module_name = self.module_name_from_hook(
                            global_atom_table, session, hook)

                        renderer.table_row(
                            hook,
                            station.dwSessionId,
                            self.get_owner_string(session, hook),
                            "<any>", hook_name,
                            hook.flags,
                            hook.offPfn,
                            module_name,
                            )

                    # Now report all thread hooks in this desktop.
                    for thrd in desktop.threads():
                        info = "{0} ({1} {2})".format(
                            thrd.pEThread.Cid.UniqueThread,
                            thrd.ppi.Process.ImageFileName,
                            thrd.ppi.Process.UniqueProcessId
                            )

                        for name, hook in thrd.hooks():
                            module_name = self.module_name_from_hook(
                                global_atom_table, session, hook)

                            renderer.table_row(
                                hook,
                                session.SessionId,
                                self.get_owner_string(session, hook),
                                info, name,
                                hook.flags,
                                hook.offPfn,
                                module_name,
                                )
