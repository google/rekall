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

from rekall.plugins import core
from rekall.plugins.windows import common
from rekall import plugin
from rekall.ui import text


class WinPsList(common.WinProcessFilter):
    """List processes for windows."""

    __name = "pslist"

    eprocess = None

    @classmethod
    def args(cls, metadata):
        super(WinPsList, cls).args(metadata)
        metadata.set_description("""
        Lists the processes by following the _EPROCESS.PsActiveList.

        In the windows operating system, processes are linked together through a
        doubly linked list. This plugin follows the list around, printing
        information about each process.

        To begin, we need to find any element on the list. This can be done by:

        1) Obtaining the _KDDEBUGGER_DATA64.PsActiveProcessHead - debug
           information.

        2) Finding any _EPROCESS in memory (e.g. through psscan) and following
           its list.

        This plugin supports both approaches.
        """)

    def render(self, renderer):

        renderer.table_header([
            dict(type="_EPROCESS", cname="_EPROCESS"),
            dict(name="PPID", cname="ppid", width=6, align="r"),
            dict(name="Thds", cname="thread_count", width=6, align="r"),
            dict(name="Hnds", cname="handle_count", width=8, align="r"),
            dict(name="Sess", cname="session_id", width=6, align="r"),
            dict(name="Wow64", cname="wow64", width=6),
            dict(name="Start", cname="process_create_time", width=24),
            dict(name="Exit", cname="process_exit_time", width=24)])

        for task in self.filter_processes():
            renderer.table_row(task,
                               task.InheritedFromUniqueProcessId,
                               task.ActiveThreads,
                               task.ObjectTable.m("HandleCount"),
                               task.SessionId,
                               task.IsWow64,
                               task.CreateTime,
                               task.ExitTime,
                               )


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

                if task.IsWow64:
                    renderer.format(u"Note: use ldrmodules for listing DLLs "
                                    "in Wow64 processes\n")

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


class WinMemMap(core.MemmapMixIn, common.WinProcessFilter):
    """Calculates the memory regions mapped by a process."""
    __name = "memmap"

    def HighestAddress(self):
        return self.profile.get_constant_object(
            "MmHighestUserAddress", "unsigned long long")


class WinMemDump(core.DirectoryDumperMixin, WinMemMap):
    """Dump the addressable memory for a process"""

    __name = "memdump"

    def dump_process(self, eprocess, fd, index_fd):
        task_as = eprocess.get_process_address_space()
        highest_address = self.HighestAddress()

        temp_renderer = text.TextRenderer(session=self.session,
                                          fd=index_fd)
        with temp_renderer.start():
            temp_renderer.table_header([
                ("File Address", "file_addr", "[addrpad]"),
                ("Length", "length", "[addrpad]"),
                ("Virtual Addr", "virtual", "[addrpad]")])

            for _ in task_as.get_available_addresses():
                virt_address, phys_address, length = _
                if not self.all and virt_address > highest_address:
                    break

                data = self.physical_address_space.read(phys_address, length)

                temp_renderer.table_row(fd.tell(), length, virt_address)
                fd.write(data)

    def render(self, renderer):
        if self.dump_dir is None:
            raise plugin.PluginError("Dump directory not specified.")

        for task in self.filter_processes():
            renderer.section()
            filename = u"{0}_{1:d}.dmp".format(
                task.ImageFileName, task.UniqueProcessId)

            renderer.format(u"Writing {0} {1:#x} to {2}\n",
                            task.ImageFileName, task, filename)

            with renderer.open(directory=self.dump_dir,
                               filename=filename,
                               mode='wb') as fd:
                with renderer.open(directory=self.dump_dir,
                                   filename=filename + ".idx",
                                   mode='wb') as index_fd:
                    self.dump_process(task, fd, index_fd)


class Threads(common.WinProcessFilter):
    """Enumerate threads."""
    name = "threads"

    def render(self, renderer):
        renderer.table_header(
            [("_ETHREAD", "offset", "[addrpad]"),
             ("PID", "pid", ">6"),
             ("TID", "tid", ">6"),
             ("Start Address", "start", "[addrpad]"),
             ("Process", "name", "16"),
             ("Symbol", "symbol", "")])

        cc = self.session.plugins.cc()
        with cc:
            for task in self.filter_processes():
                # Resolve names in the process context.
                cc.SwitchProcessContext(process=task)

                for thread in task.ThreadListHead.list_of_type(
                        "_ETHREAD", "ThreadListEntry"):

                    renderer.table_row(
                        thread,
                        thread.Cid.UniqueProcess,
                        thread.Cid.UniqueThread,
                        thread.StartAddress,
                        task.ImageFileName,
                        self.session.address_resolver.format_address(
                            thread.Win32StartAddress,
                            max_distance=0xffffffff),
                    )




class TestWinMemDump(testlib.HashChecker):
    """Test the pslist module."""

    PARAMETERS = dict(
        commandline="memdump --pid=%(pid)s --dump_dir %(tempdir)s",
        pid=2624)


class TestMemmap(testlib.SimpleTestCase):
    """Test the pslist module."""

    PARAMETERS = dict(
        commandline="memmap --pid=%(pid)s",
        pid=2624)


class TestMemmapCoalesce(testlib.SimpleTestCase):
    """Make sure that memmaps are coalesced properly."""

    PARAMETERS = dict(commandline="memmap --pid=%(pid)s --coalesce",
                      pid=2624)
