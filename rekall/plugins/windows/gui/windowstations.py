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

from rekall.plugins.windows import common
from rekall.plugins.windows.gui import win32k_core


class PoolScanWind(common.PoolScanner):
    """PoolScanner for window station objects"""

    def __init__(self, **kwargs):
        super(PoolScanWind, self).__init__(**kwargs)

        self.checks = [
            ('PoolTagCheck', dict(
                    tag=self.profile.get_constant("PoolTag_WindowStation"))),

            ('CheckPoolSize', dict(
                    min_size=self.profile.get_obj_size("tagWINDOWSTATION"))),

            # only look in non-paged or free pools
            ('CheckPoolType', dict(paged=False, non_paged=True,
                                   free=True)),

            ('CheckPoolIndex', dict(value=0)),
            ]


class WndScan(win32k_core.Win32kPluginMixin, common.PoolScannerPlugin):
    """Pool scanner for tagWINDOWSTATION (window stations)"""

    __name = "wndscan"

    allocation = ['_POOL_HEADER', '_OBJECT_HEADER', 'tagWINDOWSTATION']

    def generate_hits(self):
        sessions_plugin = self.session.plugins.sessions()
        scanner = PoolScanWind(profile=self.profile,
                               session=self.session,
                               address_space=self.address_space)

        for pool_obj in scanner.scan():
            window_station = pool_obj.get_object(
                "tagWINDOWSTATION", self.allocation)

            # Basic sanity checks are included here
            if not window_station.is_valid():
                continue

            # Find an address space for this window station's session
            session_space = sessions_plugin.find_session_space(
                window_station.dwSessionId)

            if not session_space:
                continue

            # Traverse the tagWINDOWSTATION list in the session address space.
            for winsta in window_station.traverse(session_space.obj_vm):
                if winsta.is_valid():
                    yield winsta, session_space.obj_vm

    def render(self, renderer):
        seen = []
        for window_station, session_address_space in self.generate_hits():
            if window_station.obj_vm == self.physical_address_space:
                phys_offset = window_station.obj_offset
            else:
                phys_offset = window_station.obj_vm.vtop(
                    window_station.obj_offset)

            # Always store the physical addresses to prevent duplicates.
            if phys_offset in seen:
                continue

            seen.append(phys_offset)
            renderer.section()

            renderer.format("WindowStation: {0:#x}, Name: {1}, Next: {2:#x}\n",
                            phys_offset,
                            window_station.Name.v(vm=session_address_space),
                            window_station.rpwinstaNext)

            renderer.format("SessionId: {0}, AtomTable: {1:#x}, "
                            "Interactive: {2}\n",
                            window_station.dwSessionId,
                            window_station.pGlobalAtomTable,
                            window_station.Interactive)

            renderer.format(
                "Desktops: {0:L}\n",
                [desk.Name.v(vm=session_address_space)
                 for desk in window_station.desktops(vm=session_address_space)])

            ethread = window_station.ptiDrawingClipboard.pEThread.deref(
                vm=session_address_space)

            renderer.format(
                "ptiDrawingClipboard: pid {0} tid {1}\n",
                ethread.Cid.UniqueProcess, ethread.Cid.UniqueThread)

            last_registered_viewer = window_station.LastRegisteredViewer.deref(
                vm=session_address_space)

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
