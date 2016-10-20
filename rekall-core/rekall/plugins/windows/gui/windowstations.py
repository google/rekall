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

NOTE: Windows 8 does not have a global atom table any more.
http://mista.nu/research/smashing_the_atom.pdf

"""
from rekall.plugins.windows import common
from rekall.plugins.windows.gui import win32k_core


class WindowsStations(win32k_core.Win32kPluginMixin,
                      common.WindowsCommandPlugin):
    """Displays all the windows stations by following lists."""

    __name = "windows_stations"

    table_header = [
        dict(name="WindowStation", style="address"),
        dict(name="Name", width=20),
        dict(name="SesId", width=5),
        dict(name="AtomTable", style="address"),
        dict(name="Interactive", width=11),
        dict(name="Desktops")
    ]

    def stations_in_session(self, session):
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

    def stations(self):
        """A generator of tagWINDOWSTATION objects."""
        # Each windows session has a unique set of windows stations.
        for session in self.session.plugins.sessions().session_spaces():
            for station in self.stations_in_session(session):
                yield station

    def collect(self):
        for window_station in self.stations():
            desktops = [desk.Name for desk in window_station.desktops()]
            yield dict(WindowStation=window_station,
                       Name=window_station.Name,
                       SesId=window_station.dwSessionId,
                       AtomTable=window_station.pGlobalAtomTable,
                       Interactive=window_station.Interactive,
                       Desktops=desktops)


class WinDesktops(WindowsStations):
    """Print information on each desktop."""

    __name = "desktops"

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="tagDESKTOP", style="address"),
        dict(name="Name", width=20),
        dict(name="Sid", width=3),
        dict(name="Hooks", width=5),
        dict(name="tagWND", style="address"),
        dict(name="Winds", width=5),
        dict(name="Thrd", width=5),
        dict(name="_EPROCESS"),
    ]

    def collect(self):
        for window_station in self.stations():
            for desktop in window_station.desktops():
                divider = "Desktop: {0:#x}, Name: {1}\\{2}\n".format(
                    desktop,
                    window_station.Name,
                    desktop.Name)

                divider += ("Heap: {0:#x}, Size: {1:#x}, Base: {2:#x}, "
                            "Limit: {3:#x}\n").format(
                                desktop.pheapDesktop.v(),
                                (desktop.DeskInfo.pvDesktopLimit.v() -
                                 desktop.DeskInfo.pvDesktopBase.v()),
                                desktop.DeskInfo.pvDesktopBase,
                                desktop.DeskInfo.pvDesktopLimit,
                            )

                yield dict(divider=divider)

                window_count = len(list(desktop.windows(
                    desktop.DeskInfo.spwnd)))

                for thrd in desktop.threads():
                    yield dict(
                        tagDESKTOP=desktop,
                        Name=desktop.Name,
                        Sid=desktop.dwSessionId,
                        Hooks=desktop.DeskInfo.fsHooks,
                        tagWND=desktop.DeskInfo.spwnd.deref(),
                        Winds=window_count,
                        Thrd=thrd.pEThread.Cid.UniqueThread,
                        _EPROCESS=thrd.ppi.Process.deref())
