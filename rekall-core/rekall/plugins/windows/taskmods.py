# Rekall Memory Forensics
# Copyright (C) 2007-2011 Volatile Systems
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Additional Authors:
# Michael Cohen <scudette@users.sourceforge.net>
# Mike Auty <mike.auty@gmail.com>
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

from rekall import testlib
from rekall import utils

from rekall.plugins.common import memmap
from rekall.plugins.windows import common


class WinPsList(common.WinProcessFilter):
    """List processes for windows."""

    __name = "pslist"

    eprocess = None

    table_header = [
        dict(type="_EPROCESS", cname="_EPROCESS"),
        dict(name="PPID", cname="ppid", width=6, align="r"),
        dict(name="Thds", cname="thread_count", width=6, align="r"),
        dict(name="Hnds", cname="handle_count", width=8, align="r"),
        dict(name="Sess", cname="session_id", width=6, align="r"),
        dict(name="Wow64", cname="wow64", width=6),
        dict(name="Start", cname="process_create_time", width=24),
        dict(name="Exit", cname="process_exit_time", width=24)
    ]

    def collect(self):
        for task in self.filter_processes():
            yield (task,
                   task.InheritedFromUniqueProcessId,
                   task.ActiveThreads,
                   task.ObjectTable.m("HandleCount"),
                   task.SessionId,
                   task.IsWow64,
                   task.CreateTime,
                   task.ExitTime)


class WinDllList(common.WinProcessFilter):
    """Prints a list of dll modules mapped into each process."""

    __name = "dlllist"

    def render(self, renderer):
        for task in self.filter_processes():
            pid = task.UniqueProcessId

            renderer.section()
            renderer.format(u"{0} pid: {1:6}\n", task.ImageFileName, pid)

            if task.Peb:
                renderer.format(u"Command line : {0}\n",
                                task.Peb.ProcessParameters.CommandLine)

                renderer.format(u"{0}\n\n", task.Peb.CSDVersion)
                renderer.table_header([("Base", "module_base", "[addrpad]"),
                                       ("Size", "module_size", "[addr]"),
                                       ("Load Reason/Count", "reason", "30"),
                                       ("Path", "loaded_dll_path", ""),
                                      ])

                for m in task.get_load_modules():
                    renderer.table_row(m.DllBase, m.SizeOfImage,
                                       m.LoadReason, m.FullDllName)
            else:
                renderer.format("Unable to read PEB for task.\n")


class WinMemMap(memmap.MemmapMixIn, common.WinProcessFilter):
    """Calculates the memory regions mapped by a process."""
    __name = "memmap"

    def _get_highest_user_address(self):
        return self.profile.get_constant_object(
            "MmHighestUserAddress", "Pointer").v()


class Threads(common.WinProcessFilter):
    """Enumerate threads."""
    name = "threads"

    table_header = [
        dict(name="_ETHREAD", cname="offset", style="address"),
        dict(name="PID", cname="pid", align="r", width=6),
        dict(name="TID", cname="tid", align="r", width=6),
        dict(name="Start Address", cname="start", style="address"),
        dict(name="Start Symbol", width=30),
        dict(name="Process", cname="name", width=16),
        dict(name="Win32 Start", cname="win32_start", style="address"),
        dict(name="Win32 Symbol")
    ]

    def collect(self):
        cc = self.session.plugins.cc()
        with cc:
            for task in self.filter_processes():
                # Resolve names in the process context.
                cc.SwitchProcessContext(process=task)

                for thread in task.ThreadListHead.list_of_type(
                        "_ETHREAD", "ThreadListEntry"):

                    yield (thread,
                           thread.Cid.UniqueProcess,
                           thread.Cid.UniqueThread,
                           thread.StartAddress,
                           utils.FormattedAddress(self.session.address_resolver,
                                                  thread.StartAddress),
                           task.ImageFileName,
                           thread.Win32StartAddress,
                           utils.FormattedAddress(self.session.address_resolver,
                                                  thread.Win32StartAddress))


class WinMemDump(memmap.MemDumpMixin, common.WinProcessFilter):
    """Dump windows processes."""


class TestWinMemDump(testlib.HashChecker):
    """Test the pslist module."""

    PARAMETERS = dict(
        commandline="memdump %(pids)s --dump_dir %(tempdir)s",
        pid=2624)


class TestMemmap(testlib.SimpleTestCase):
    """Test the pslist module."""

    PARAMETERS = dict(
        commandline="memmap %(pids)s",
        pid=2624)


class TestMemmapCoalesce(testlib.SimpleTestCase):
    """Make sure that memmaps are coalesced properly."""

    PARAMETERS = dict(commandline="memmap %(pids)s --coalesce",
                      pid=2624)
