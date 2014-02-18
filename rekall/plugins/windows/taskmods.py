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

import logging
import os

from rekall.plugins import core
from rekall.plugins.windows import common
from rekall import plugin


class WinPsList(common.WinProcessFilter):
    """List processes for windows."""

    __name = "pslist"

    eprocess = None

    def __init__(self, **kwargs):
        """Lists the processes by following the _EPROCESS.PsActiveList.

        In the windows operating system, processes are linked together through a
        doubly linked list. This plugin follows the list around, printing
        information about each process.

        To begin, we need to find any element on the list. This can be done by:

        1) Obtaining the _KDDEBUGGER_DATA64.PsActiveProcessHead - debug
           information.

        2) Finding any _EPROCESS in memory (e.g. through psscan) and following
           its list.

        This plugin supports both approaches.
        """
        super(WinPsList, self).__init__(**kwargs)

    def list_eprocess_from_kdbg(self, kdbg):
        """List the eprocess using the kdbg method."""
        return self.list_eprocess_from_PsActiveProcessHead(
            kdbg.PsActiveProcessHead)

    def list_eprocess_from_eprocess(self, eprocess_offset):
        eprocess = self.profile._EPROCESS(
            offset=eprocess_offset, vm=self.kernel_address_space)

        for task in eprocess.ActiveProcessLinks:
            # TODO: Need to filter out the PsActiveProcessHead (which is not
            # really an _EPROCESS)
            yield task

    def list_eprocess_from_PsActiveProcessHead(self, PsActiveProcessHead):
        return iter(PsActiveProcessHead.list_of_type(
                "_EPROCESS", "ActiveProcessLinks"))

    def list_eprocess(self):
        if self.eprocess_head:
            return self.list_eprocess_from_eprocess(self.eprocess_head)

        PsActiveProcessHead = self.session.GetParameter("PsActiveProcessHead")
        if PsActiveProcessHead:
            return self.list_eprocess_from_PsActiveProcessHead(
                PsActiveProcessHead)

        if self.kdbg:
            return self.list_eprocess_from_kdbg(self.kdbg)

        logging.debug("Unable to list processes using any method.")
        return []

    def render(self, renderer):

        renderer.table_header([("Offset (V)", "offset_v", "[addrpad]"),
                               ("Name", "file_name", "20s"),
                               ("PID", "pid", ">6"),
                               ("PPID", "ppid", ">6"),
                               ("Thds", "thread_count", ">6"),
                               ("Hnds", "handle_count", ">8"),
                               ("Sess", "session_id", ">6"),
                               ("Wow64", "wow64", ">6"),
                               ("Start", "process_create_time", "24"),
                               ("Exit", "process_exit_time", "24")]
                              )

        for task in self.filter_processes():
            renderer.table_row(task.obj_offset,
                               task.ImageFileName,
                               task.UniqueProcessId,
                               task.InheritedFromUniqueProcessId,
                               task.ActiveThreads,
                               task.ObjectTable.HandleCount,
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

            renderer.write(u"*" * 72 + "\n")
            renderer.format(u"{0} pid: {1:6}\n", task.ImageFileName, pid)

            if task.Peb:
                renderer.format(u"Command line : {0}\n",
                                task.Peb.ProcessParameters.CommandLine)

                if task.IsWow64:
                    renderer.write(u"Note: use ldrmodules for listing DLLs "
                                   "in Wow64 processes\n")

                renderer.format(u"{0}\n", task.Peb.CSDVersion)
                renderer.write(u"\n")
                renderer.table_header([("Base", "module_base", "[addrpad]"),
                                       ("Size", "module_size", "[addr]"),
                                       ("Path", "loaded_dll_path", ""),
                                       ])
                for m in task.get_load_modules():
                    renderer.table_row(m.DllBase, m.SizeOfImage, m.FullDllName)
            else:
                renderer.write("Unable to read PEB for task.\n")


class WinMemMap(core.MemmapMixIn, common.WinProcessFilter):
    """Calculates the memory regions mapped by a process."""
    __name = "memmap"


class WinMemDump(core.DirectoryDumperMixin, WinMemMap):
    """Dump the addressable memory for a process"""

    __name = "memdump"

    def dump_process(self, eprocess, fd):
        task_as = eprocess.get_process_address_space()

        for virtual_address, phys_address, length in task_as.get_available_addresses():
            fd.write(self.physical_address_space.read(phys_address, length))

    def render(self, renderer):
        if self.dump_dir is None:
            raise plugin.PluginError("Dump directory not specified.")

        for task in self.filter_processes():
            renderer.section()
            filename = u"{0}_{1:d}.dmp".format(
                task.ImageFileName, task.UniqueProcessId)

            renderer.format(u"Writing {0} {1:6} to {2}\n",
                            task.ImageFileName, task, filename)

            with open(os.path.join(self.dump_dir, filename), 'wb') as fd:
                self.dump_process(task, fd)
