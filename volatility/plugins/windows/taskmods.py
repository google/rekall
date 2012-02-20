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

#pylint: disable-msg=C0111

import os
import volatility.win32 as win32
import volatility.obj as obj
import volatility.debug as debug
import volatility.utils as utils
import volatility.cache as cache

from volatility.plugins.windows import common
from volatility import plugin


class WinPsList(common.AbstractWindowsCommandPlugin):
    """List processes for windows."""

    __name = "pslist"

    kdbg = None
    eprocess = None

    def __init__(self, kernel_address_space=None, profile=None, kdbg=None, eprocess=None, 
                 **kwargs):
        """Lists the processes by following the _EPROCESS.PsActiveList.

        In the windows operating system, processes are linked together through a
        doubly linked list. This plugin follows the list around, printing
        information about each process.

        To begin, we need to find any element on the list. This can be done by:

        1) Obtaining the _KDDEBUGGER_DATA64.PsActiveProcessHead - debug information.
        2) Finding any _EPROCESS in memory (e.g. through psscan) and following its list.

        This plugin supports both approaches.

        Args:
          kernel_address_space: The kernel AS we operate on, if None we use the session's.

          profile: The profile. If None we use the session's.

          kdbg: The location of the kernel debugger block (In the physical
             AS). If this is specified we use the PsActiveProcessHead method.

          eprocess: The location of any eprocess location (in kernel AS). This
             can be obtained from e.g. psscan or find_dtb. If neither kdbg or
             eprocess are specified we just do the best we have from the
             session.
        """
        super(WinPsList, self).__init__(**kwargs)

        # Try to load the AS from the session if possible.
        self.kernel_address_space = (kernel_address_space or 
                                     self.session.kernel_address_space)
        if self.kernel_address_space is None:
            raise plugin.PluginError("kernel_address_space not specified.")

        self.profile = profile or self.session.profile
        if self.profile is None:
            raise plugin.PluginError("Profile not specified.")

        if kdbg:
            self.kdbg = kdbg
        elif eprocess:
            self.eprocess = eprocess
        else:
            self.kdbg = self.session.kdbg
            self.eprocess = self.session.eprocess

    def list_eprocess_from_kdbg(self, kdbg_offset):
        kdbg = self.profile.Object(theType="_KDDEBUGGER_DATA64", 
                                   offset=kdbg_offset, vm=self.kernel_address_space.base)

        PsActiveList = kdbg.PsActiveProcessHead.dereference_as(
            "_LIST_ENTRY", vm=self.kernel_address_space)

        if PsActiveList:
            return iter(PsActiveList.list_of_type("_EPROCESS", "ActiveProcessLinks"))

    def list_eprocess_from_eprocess(self, eprocess_offset):
        eprocess = self.profile.Object(theType="_EPROCESS", 
                                       offset=eprocess_offset, vm=self.kernel_address_space)

        for task in eprocess_offset.ActiveProcessLinks:
            # Need to filter out the PsActiveProcessHead (which is not really an
            # _EPROCESS)
            yield task

    def list_eprocess(self):
        if self.kdbg:
            return self.list_eprocess_from_kdbg(self.kdbg)
        elif self.eprocess:
            return self.list_eprocess_from_eprocess(self.eprocess)
        else:
            raise plugin.PluginError("I need either a kdbg address or an eprocess.")

    def render(self, fd=None):
        offsettype = "(V)"
        fd.write(" Offset{0}  Name                 PID    PPID   Thds   Hnds   Time \n".format(offsettype) + \
                    "---------- -------------------- ------ ------ ------ ------ ------------------- \n")

        for task in self.list_eprocess():
            # PHYSICAL_OFFSET must STRICTLY only be used in the results.  If it's used for anything else,
            # it needs to have cache_invalidator set to True in the options
            offset = task.obj_offset
            fd.write("{0:#010x} {1:20} {2:6} {3:6} {4:6} {5:6} {6:26}\n".format(
                offset,
                task.ImageFileName,
                task.UniqueProcessId,
                task.InheritedFromUniqueProcessId,
                task.ActiveThreads,
                task.ObjectTable.HandleCount,
                task.CreateTime))
        

class DllList(common.AbstractWindowsCommand):
    """Print list of loaded dlls for each process"""

    @staticmethod
    def register_options(config):
        config.add_option('OFFSET', short_option = 'o', default = None,
                          help = 'EPROCESS offset (in hex) in the physical address space',
                          action = 'store', type = 'int')

        config.add_option('PID', short_option = 'p', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')

    def render_text(self, outfd, data):
        for task in data:
            pid = task.UniqueProcessId

            outfd.write("*" * 72 + "\n")
            outfd.write("{0} pid: {1:6}\n".format(task.ImageFileName, pid))

            if task.Peb:
                outfd.write("Command line : {0}\n".format(task.Peb.ProcessParameters.CommandLine))
                outfd.write("{0}\n".format(task.Peb.CSDVersion))
                outfd.write("\n")
                outfd.write("{0:12} {1:12} {2}\n".format('Base', 'Size', 'Path'))
                for m in task.get_load_modules():
                    outfd.write("0x{0:08x}   0x{1:06x}     {2}\n".format(m.DllBase, m.SizeOfImage, m.FullDllName))
            else:
                outfd.write("Unable to read PEB for task.\n")

    def filter_tasks(self, tasks):
        """ Reduce the tasks based on the user selectable PIDS parameter.

        Returns a reduced list or the full list if config.PIDS not specified.
        """
        try:
            if self._config.PID:
                pidlist = [int(p) for p in self._config.PID.split(',')]
                newtasks = [t for t in tasks if t.UniqueProcessId in pidlist]
                # Make this a separate statement, so that if an exception occurs, no harm done
                tasks = newtasks
        except (ValueError, TypeError):
            # TODO: We should probably print a non-fatal warning here
            pass

        return tasks

    def virtual_process_from_physical_offset(self, addr_space, offset):
        """ Returns a virtual process from a physical offset in memory """
        # Since this is a physical offset, we find the process
        flat_addr_space = utils.load_as(addr_space.get_config(), astype = 'physical')
        flateproc = obj.Object("_EPROCESS", offset, flat_addr_space)
        # then use the virtual address of its first thread to get into virtual land
        # (Note: the addr_space and flat_addr_space use the same config, so should have the same profile)
        tleoffset = addr_space.profile.get_obj_offset("_ETHREAD", "ThreadListEntry")
        ethread = obj.Object("_ETHREAD", offset = flateproc.ThreadListHead.Flink.v() - tleoffset, vm = addr_space)
        # and ask for the thread's process to get an _EPROCESS with a virtual address space
        # For Vista/windows 7
        if hasattr(ethread.Tcb, 'Process'):
            return ethread.Tcb.Process.dereference_as('_EPROCESS')
        elif hasattr(ethread, 'ThreadsProcess'):
            return ethread.ThreadsProcess.dereference()
        return obj.NoneObject("Unable to bounce back from virtual _ETHREAD to virtual _EPROCESS")

    def calculate(self):
        """Produces a list of processes, or just a single process based on an OFFSET"""
        addr_space = utils.load_as(self._config)

        if self._config.OFFSET != None:
            tasks = [self.virtual_process_from_physical_offset(addr_space, self._config.OFFSET)]
        else:
            tasks = self.filter_tasks(win32.tasks.pslist(addr_space))

        return tasks

class PSList(DllList):
    """ print all running processes by following the EPROCESS lists """
    def __init__(self, config, *args):
        DllList.__init__(self, config, *args)
        config.add_option("PHYSICAL-OFFSET", short_option = 'P', default = False,
                          cache_invalidator = False, help = "Physical Offset", action = "store_true")

    def render_text(self, outfd, data):

        offsettype = "(V)" if not self._config.PHYSICAL_OFFSET else "(P)"
        outfd.write(" Offset{0}  Name                 PID    PPID   Thds   Hnds   Time \n".format(offsettype) + \
                    "---------- -------------------- ------ ------ ------ ------ ------------------- \n")

        for task in data:
            # PHYSICAL_OFFSET must STRICTLY only be used in the results.  If it's used for anything else,
            # it needs to have cache_invalidator set to True in the options
            if not self._config.PHYSICAL_OFFSET:
                offset = task.obj_offset
            else:
                offset = task.obj_vm.vtop(task.obj_offset)
            outfd.write("{0:#010x} {1:20} {2:6} {3:6} {4:6} {5:6} {6:26}\n".format(
                offset,
                task.ImageFileName,
                task.UniqueProcessId,
                task.InheritedFromUniqueProcessId,
                task.ActiveThreads,
                task.ObjectTable.HandleCount,
                task.CreateTime))


# Inherit from files just for the config options (__init__)
class MemMap(DllList):
    """Print the memory map"""

    def render_text(self, outfd, data):
        first = True
        for pid, task, pagedata in data:
            if not first:
                outfd.write("*" * 72 + "\n")

            task_space = task.get_process_address_space()
            outfd.write("{0} pid: {1:6}\n".format(task.ImageFileName, pid))
            first = False

            if pagedata:
                outfd.write("{0:12} {1:12} {2:12}\n".format('Virtual', 'Physical', 'Size'))

                for p in pagedata:
                    pa = task_space.vtop(p[0])
                    # pa can be 0, according to the old memmap, but can't == None(NoneObject)
                    if pa != None:
                        outfd.write("0x{0:010x} 0x{1:010x} 0x{2:012x}\n".format(p[0], pa, p[1]))
                    #else:
                    #    outfd.write("0x{0:10x} 0x000000     0x{1:12x}\n".format(p[0], p[1]))
            else:
                outfd.write("Unable to read pages for task.\n")

    @cache.CacheDecorator(lambda self: "tests/memmap/pid={0}/offset={1}".format(self._config.PID, self._config.OFFSET))
    def calculate(self):
        tasks = DllList.calculate(self)

        for task in tasks:
            if task.UniqueProcessId:
                pid = task.UniqueProcessId
                task_space = task.get_process_address_space()
                pages = task_space.get_available_pages()
                yield pid, task, pages

class MemDump(MemMap):
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
            outfd.write("Writing {0} [{1:6}] to {2}.dmp\n".format(task.ImageFileName, pid, str(pid)))

            f = open(os.path.join(self._config.DUMP_DIR, str(pid) + ".dmp"), 'wb')
            if pagedata:
                for p in pagedata:
                    data = task_space.read(p[0], p[1])
                    f.write(data)
            else:
                outfd.write("Unable to read pages for task.\n")
            f.close()
