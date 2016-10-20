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
from rekall import obj
from rekall.plugins.windows import common
from rekall.plugins.windows.gui import win32k_core
from rekall.plugins.windows.gui import constants



class Clipboard(win32k_core.Win32kPluginMixin,
                common.WinProcessFilter):
    """Extract the contents of the windows clipboard"""

    __name = "clipboard"

    table_header = [
        dict(name="session", width=10),
        dict(name="window_station", width=12),
        dict(name="format", width=18),
        dict(name="handle", style="address"),
        dict(name="object", style="address"),
        dict(name="data", width=50),
        dict(name="hexdump", hidden=True),
    ]

    def calculate(self):
        session_plugin = self.session.plugins.sessions()

        # Dictionary of MM_SESSION_SPACEs by ID
        sessions = dict((int(session.SessionId), session)
                        for session in session_plugin.session_spaces())

        # Dictionary of session USER objects by handle
        session_handles = {}

        # If various objects cannot be found or associated,
        # we'll return none objects
        e0 = obj.NoneObject("Unknown tagCLIPDATA")
        e1 = obj.NoneObject("Unknown tagWINDOWSTATION")
        e2 = obj.NoneObject("Unknown tagCLIP")

        # Load tagCLIPDATA handles from all sessions
        for sid, session in sessions.items():
            handles = {}
            shared_info = self.win32k_profile.get_constant_object(
                "gSharedInfo",
                target="tagSHAREDINFO",
                vm=session.obj_vm)
            if not shared_info:
                self.session.logging.debug(
                    "No shared info for session {0}".format(sid))
                continue

            for handle in shared_info.aheList:
                if handle.bType != "TYPE_CLIPDATA":
                    continue

                handles[int(handle.phead.h)] = handle

            session_handles[sid] = handles

        # Scan for Each WindowStation
        windowstations_plugin = self.session.plugins.wndscan()

        for wndsta, station_as in windowstations_plugin.generate_hits():
            session = sessions.get(int(wndsta.dwSessionId), None)
            # The session is unknown
            if not session:
                continue

            handles = session_handles.get(int(session.SessionId), None)
            # No handles in the session
            if not handles:
                continue

            clip_array = wndsta.pClipBase.dereference(vm=station_as)
            # The tagCLIP array is empty or the pointer is invalid
            if not clip_array:
                continue

            # Resolve tagCLIPDATA from tagCLIP.hData
            for clip in clip_array:
                handle = handles.get(int(clip.hData), e0)
                # Remove this handle from the list
                if handle:
                    handles.pop(int(clip.hData))

                yield session, wndsta, clip, handle

        # Any remaining tagCLIPDATA not matched. This allows us
        # to still find clipboard data if a window station is not
        # found or if pClipData or cNumClipFormats were corrupt
        for sid in sessions.keys():
            handles = session_handles.get(sid, None)
            # No handles in the session
            if not handles:
                continue

            for handle in handles.values():
                yield sessions[sid], e1, e2, handle

    def collect(self):
        for session, wndsta, clip, handle in self.calculate():
            # If no tagCLIP is provided, we do not know the format
            if not clip:
                fmt = obj.NoneObject("Format unknown")
            else:
                # Try to get the format name, but failing that, print
                # the format number in hex instead.
                if clip.fmt.v() in constants.CLIPBOARD_FORMAT_ENUM:
                    fmt = str(clip.fmt)
                else:
                    fmt = hex(clip.fmt.v())

            # Try to get the handle from tagCLIP first, but
            # fall back to using _HANDLEENTRY.phead. Note: this can
            # be a value like DUMMY_TEXT_HANDLE (1) etc.
            handle_value = clip.hData or handle.phead.h

            clip_data = ""
            if handle and "TEXT" in fmt:
                clip_data = handle.reference_object().as_string(fmt)

            print handle

            yield dict(session=session.SessionId,
                       window_station=wndsta.Name,
                       format=fmt,
                       handle=handle_value,
                       object=handle.phead.v(),
                       data=clip_data,
                       hexdump=handle.reference_object().as_hex())
