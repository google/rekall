# Volatility
# Copyright (C) 2007-2011 Volatile Systems
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

import logging
import os

import volatility.win32 as win32
import volatility.obj as obj
import volatility.debug as debug
import volatility.utils as utils
import volatility.cache as cache

from volatility.plugins.windows import common
from volatility import plugin



class WinPsList(common.WinProcessFilter):
    """List processes for windows."""

    __name = "pslist"

    kdbg = None
    eprocess = None

    def __init__(self, kdbg=None, eprocess=None, **kwargs):
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

        Args:
          kernel_address_space: The kernel AS we operate on, if None we use the
            session's.

          profile: The profile. If None we use the session's.

          kdbg: The location of the kernel debugger block (In the physical
             AS). If this is specified we use the PsActiveProcessHead method.

          eprocess: The location of any eprocess location (in kernel AS). This
             can be obtained from e.g. psscan or find_dtb. If neither kdbg or
             eprocess are specified we just do the best we have from the
             session.
        """
        super(WinPsList, self).__init__(**kwargs)

        if kdbg:
            self.kdbg = kdbg
        elif eprocess:
            self.eprocess = eprocess
        else:
            self.kdbg = self.session.kdbg
            self.eprocess = self.session.eprocess

    def list_eprocess_from_kdbg(self, kdbg_offset):
        """List the eprocess using the kdbg method."""
        kdbg = self.profile.Object(
            theType="_KDDEBUGGER_DATA64", 
            offset=kdbg_offset, vm=self.kernel_address_space.base)

        PsActiveList = kdbg.PsActiveProcessHead.dereference_as(
            "_LIST_ENTRY", vm=self.kernel_address_space)

        if PsActiveList:
            return iter(PsActiveList.list_of_type(
                    "_EPROCESS", "ActiveProcessLinks"))

    def list_eprocess_from_eprocess(self, eprocess_offset):
        eprocess = self.profile.Object(
            theType="_EPROCESS", 
            offset=eprocess_offset, vm=self.kernel_address_space)

        for task in eprocess.ActiveProcessLinks:
            # TODO: Need to filter out the PsActiveProcessHead (which is not
            # really an _EPROCESS)
            yield task

    def list_eprocess(self):
        if self.kdbg:
            return self.list_eprocess_from_kdbg(self.kdbg)
        elif self.eprocess:
            return self.list_eprocess_from_eprocess(self.eprocess)
        else:
            logging.info("KDBG not provided - Volatility will try to "
                         "automatically scan for it now using plugin.kdbgscan.")
            for kdbg in self.session.plugins.kdbgscan().hits():
                # Just return the first one
                logging.info("Found a KDBG hit @0x%X. Hope it works. If not try "
                             "setting it manually.", kdbg)

                # Cache this for next time in the session.
                self.kdbg = self.session.kdbg = kdbg
                return self.list_eprocess_from_kdbg(kdbg)

    def render(self, fd=None):
        fd.write(" Offset(V) Offset(P)  Name                 PID    PPID   Thds   Hnds   Time\n" + \
                 "---------- ---------- -------------------- ------ ------ ------ ------ ------------------- \n")

        for task in self.filter_processes():
            offset = task.obj_offset
            fd.write("{0:#010x} {1:#010x} {2:20} {3:6} {4:6} {5:6} {6:6} {7:26}\n".format(
                offset,
                task.obj_vm.vtop(offset),
                task.ImageFileName,
                task.UniqueProcessId,
                task.InheritedFromUniqueProcessId,
                task.ActiveThreads,
                task.ObjectTable.HandleCount,
                task.CreateTime))


class WinDllList(common.WinProcessFilter):
    """Prints a list of dll modules mapped into each process."""

    __name = "dlllist"

    def render(self, outfd):
        for task in self.filter_processes():
            pid = task.UniqueProcessId

            outfd.write("*" * 72 + "\n")
            outfd.write("{0} pid: {1:6}\n".format(task.ImageFileName, pid))

            if task.Peb:
                outfd.write("Command line : {0}\n".format(
                        task.Peb.ProcessParameters.CommandLine))
                outfd.write("{0}\n".format(task.Peb.CSDVersion))
                outfd.write("\n")
                outfd.write("{0:12} {1:12} {2}\n".format('Base', 'Size', 'Path'))
                for m in task.get_load_modules():
                    outfd.write("0x{0:08x}   0x{1:06x}     {2}\n".format(
                            m.DllBase, m.SizeOfImage, m.FullDllName))
            else:
                outfd.write("Unable to read PEB for task.\n")


class WinMemMap(common.WinProcessFilter):
    """Calculates the memory regions mapped by a process."""

    __name = "memmap"

    def get_pages_for_eprocess(self, eprocess, coalesce=False):
        """Returns the list of pages the _EPROCESS has mapped.

        Args:
          eprocess: A _EPROCESS to use.
          coalesce: Should memory ranges be coalesced into larger blocks.

        Yields:
          Tuples of (virtual address, physical address, range length)
        """
        last_va = 0
        last_pa = 0
        last_len = 0

        task_address_space = eprocess.get_process_address_space()
        for va, length in task_address_space.get_available_pages():
            pa = task_address_space.vtop(va)
            if pa == None:
                continue

            ## This page is right after the last page in the range
            if coalesce and va == last_va + last_len and pa == last_pa + last_len:
                last_len += length
            else:
                if last_len > 0:
                    yield (last_va, last_pa, last_len)

                last_va, last_pa, last_len = va, pa, length

        yield (last_va, last_pa, last_len)                

    def render(self, outfd):
        for task in self.filter_processes():
            outfd.write("*" * 72 + "\n")
            task_space = task.get_process_address_space()
            outfd.write("{0} pid: {1:6}\n".format(
                    task.ImageFileName, task.UniqueProcessId))

            outfd.write("{0:12} {1:12} {2:12}\n".format(
                    'Virtual', 'Physical', 'Size'))

            ranges = list(self.get_pages_for_eprocess(task))

            if not ranges:
                outfd.write("Unable to read pages for task.\n")
                continue

            for virtual_address, phys_address, length in ranges:
                outfd.write("0x{0:010x} 0x{1:010x} 0x{2:012x}\n".format(
                        virtual_address, phys_address, length))


class MemDump(object):
    """Dump the addressable memory for a process"""

    def __init__(self, config, *args):
        MemMap.__init__(self, config, *args)
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          cache_invalidator = False,
                          help = 'Directory in which to dump memory')

    def render_text(self, outfd, data):
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        for pid, task, pagedata in data:
            outfd.write("*" * 72 + "\n")

            task_space = task.get_process_address_space()
            outfd.write("Writing {0} [{1:6}] to {2}.dmp\n".format(
                    task.ImageFileName, pid, str(pid)))

            f = open(os.path.join(self._config.DUMP_DIR, str(pid) + ".dmp"), 'wb')
            if pagedata:
                for p in pagedata:
                    data = task_space.read(p[0], p[1])
                    f.write(data)
            else:
                outfd.write("Unable to read pages for task.\n")
            f.close()
