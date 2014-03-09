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

"""The following is a description of windows stations from MSDN:

http://msdn.microsoft.com/en-us/library/windows/desktop/ms687096(v=vs.85).aspx

A window station contains a clipboard, an atom table, and one or more desktop
objects. Each window station object is a securable object. When a window station
is created, it is associated with the calling process and assigned to the
current session.

The interactive window station is the only window station that can display a
user interface or receive user input. It is assigned to the logon session of the
interactive user, and contains the keyboard, mouse, and display device. It is
always named "WinSta0". All other window stations are noninteractive, which
means they cannot display a user interface or receive user input.


Ref:
http://volatility-labs.blogspot.de/2012/09/movp-13-desktops-heaps-and-ransomware.html
"""
from rekall import plugin
from rekall.plugins.windows import common
from rekall.plugins.windows.gui import win32k_core


class WindowsStations(win32k_core.Win32kPluginMixin,
                      common.WindowsCommandPlugin):
    """Displays all the windows stations by following lists."""

    __name = "windows_stations"

    def stations(self):
        """A generator of tagWINDOWSTATION objects."""
        # Each windows session has a unique set of windows stations.
        for session in self.session.plugins.sessions().session_spaces():
            # Get the start of the Window station list from
            # win32k.sys. These are all the Windows stations that exist in
            # this Windows session.
            station_list = self.win32k_profile.get_constant_object(
                "grpWinStaList",
                target="Pointer",
                target_args=dict(
                    target="tagWINDOWSTATION"
                    ),
                vm=session.obj_vm,
                )

            for station in station_list.walk_list("rpwinstaNext"):
                yield station

    def render(self, renderer):
        for window_station in self.stations():
            renderer.section()
            renderer.format(
                "WindowStation: {0:#x}, Name: {1}, Next: {2:#x}\n",
                window_station,
                window_station.Name,
                window_station.rpwinstaNext)

            renderer.format(
                "SessionId: {0}, AtomTable: {1:#x}, "
                "Interactive: {2}\n",
                window_station.dwSessionId,
                window_station.pGlobalAtomTable,
                window_station.Interactive)

            renderer.format(
                "Desktops: {0:L}\n",
                [desk.Name for desk in window_station.desktops()])

            ethread = window_station.ptiDrawingClipboard.pEThread

            renderer.format(
                "ptiDrawingClipboard: pid {0} tid {1}\n",
                ethread.Cid.UniqueProcess, ethread.Cid.UniqueThread)

            last_registered_viewer = window_station.LastRegisteredViewer
            renderer.format("spwndClipOpen: {0:#x}, spwndClipViewer: {1:#x} "
                            "{2} {3}\n",
                            window_station.spwndClipOpen,
                            window_station.spwndClipViewer,
                            last_registered_viewer.UniqueProcessId,
                            last_registered_viewer.ImageFileName)

            renderer.format("cNumClipFormats: {0}, iClipSerialNumber: {1}\n",
                            window_station.cNumClipFormats,
                            window_station.iClipSerialNumber)

            renderer.format(
                "pClipBase: {0:#x}, Formats: {1:L}\n",
                window_station.pClipBase,
                [clip.fmt for clip in window_station.pClipBase.dereference()])



class WinDesktops(plugin.VerbosityMixIn, WindowsStations):
    """Print information on each desktop."""

    __name = "desktops"

    def render(self, renderer):
        for window_station in self.stations():
            for desktop in window_station.desktops():
                renderer.section()

                renderer.format(
                    "Desktop: {0:#x}, Name: {1}\\{2}, Next: {3:#x}\n",
                    desktop,
                    desktop.WindowStation.Name,
                    desktop.Name,
                    desktop.rpdeskNext.v(),
                    )

                renderer.format(
                    "SessionId: {0}, DesktopInfo: {1:#x}, fsHooks: {2}\n",
                    desktop.dwSessionId,
                    desktop.pDeskInfo.v(),
                    desktop.DeskInfo.fsHooks,
                    )

                renderer.format(
                    "spwnd: {0:#x}, Windows: {1}\n",
                    desktop.DeskInfo.spwnd,
                    len(list(desktop.windows(desktop.DeskInfo.spwnd)))
                    )
                renderer.format(
                    "Heap: {0:#x}, Size: {1:#x}, Base: {2:#x}, Limit: {3:#x}\n",
                    desktop.pheapDesktop.v(),
                    (desktop.DeskInfo.pvDesktopLimit.v() -
                     desktop.DeskInfo.pvDesktopBase.v()),
                    desktop.DeskInfo.pvDesktopBase,
                    desktop.DeskInfo.pvDesktopLimit,
                    )

                # Print heap allocations.
                if self.verbosity > 1:
                    for entry in desktop.pheapDesktop.Entries:
                        renderer.format(
                            "   Alloc: {0:#x}, Size: {1:#x} Previous: {2:#x}\n",
                            entry,
                            entry.Size,
                            entry.PreviousSize
                            )

                for thrd in desktop.threads():
                    renderer.format(
                        " {0} ({1} {2} parent {3})\n",
                        thrd.pEThread.Cid.UniqueThread,
                        thrd.ppi.Process.ImageFileName,
                        thrd.ppi.Process.UniqueProcessId,
                        thrd.ppi.Process.InheritedFromUniqueProcessId,
                        )
