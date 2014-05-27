# Rekall Memory Forensics
#
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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""
import os

from rekall import plugin
from rekall import testlib
from rekall.plugins import core
from rekall.plugins.linux import common
from rekall.ui import text

class LinuxPsList(common.LinProcessFilter):
    """Gathers active tasks by walking the task_struct->task list.

    It does not display the swapper process. If the DTB column is blank, the
    item is likely a kernel thread.
    """
    __name = "pslist"

    def render(self, renderer):
        renderer.table_header([("Offset (V)", "offset_v", "[addrpad]"),
                               ("Name", "file_name", "20s"),
                               ("PID", "pid", ">6"),
                               ("PPID", "ppid", ">6"),
                               ("UID", "uid", ">6"),
                               ("GID", "gid", ">6"),
                               ("DTB", "dtb", "[addrpad]"),
                               ("Start Time", "start_time", ">24"),
                               ])

        for task in self.filter_processes():
            start_time = (task.start_time.as_timestamp()+
                          task.start_time.getboottime())

            dtb = self.kernel_address_space.vtop(task.mm.pgd)
            renderer.table_row(task.obj_offset,
                               task.comm,
                               task.pid,
                               task.parent.pid,
                               task.uid,
                               task.gid,
                               dtb, start_time)


class LinMemMap(core.MemmapMixIn, common.LinProcessFilter):
    """Dumps the memory map for linux tasks."""
    __name = "memmap"


class LinMemDump(core.DirectoryDumperMixin, LinMemMap):
    """Dump the addressable memory for a process.

    This plugin traverses the page tables and dumps all accessible memory for
    the task. Note that this excludes kernel memory even though it is mapped
    into the task.
    """

    __name = "memdump"

    def dump_process(self, task, fd):
        task_as = task.get_process_address_space()

        # We want to stop dumping memory when we reach the max addressable
        # memory by the process (anything above that is kernel memory).
        max_memory = task.mm.task_size

        result = []
        for virtual_address, phys_address, length in task_as.get_address_ranges(
            end=max_memory):
            result.append((fd.tell(), length, virtual_address))
            fd.write(self.physical_address_space.read(phys_address, length))

        return result

    def write_index(self, renderer, maps):
        file_addr = old_file_addr = old_length = old_virtual = 0
        for file_addr, length, virtual in maps:
            # Merge the addresses as much as possible.
            if (old_virtual + old_length == virtual and
                old_file_addr + old_length == file_addr):
                old_length += length
                continue

            renderer.table_row(old_file_addr, old_length, old_virtual)

            old_file_addr = file_addr
            old_length = length
            old_virtual = virtual

        if old_file_addr != file_addr:
            renderer.table_row(old_file_addr, old_length, old_virtual)

    def render(self, renderer):
        if self.dump_dir is None:
            raise plugin.PluginError("Dump directory not specified.")

        for task in self.filter_processes():
            filename = os.path.join(
                self.dump_dir, u"{0}_{1:d}.dmp".format(task.comm, task.pid))

            renderer.write(u"Writing {0} {1:6x} to {2}\n".format(
                    task.comm, task, filename))

            with open(filename, 'wb') as fd:
                maps = self.dump_process(task, fd)

            with open(filename + ".idx", 'wb') as fd:
                with text.TextRenderer(fd=fd) as temp_renderer:
                    temp_renderer.table_header([
                        ("File Address", "file_addr", "[addrpad]"),
                        ("Length", "length", "[addrpad]"),
                        ("Virtual Addr", "virtual", "[addrpad]")])

                    self.write_index(temp_renderer, maps)


class TestLinMemDump(testlib.HashChecker):
    PARAMETERS = dict(
        commandline="memdump --proc_regex bash --dump-dir %(tempdir)s"
        )

# We only care about PIDTYPE_PID here.
# http://lxr.free-electrons.com/source/include/linux/pid.h?v=3.8#L6
#enum pid_type
# {
#         PIDTYPE_PID,
# };
PIDTYPE_PID = 0


class PidHashTable(LinuxPsList):
    """List processes by enumerating the pid hash tables."""

    __name = "pidhashtable"

    def list_tasks(self):
        # According to
        # http://lxr.free-electrons.com/source/kernel/pid.c?v=3.8#L566, the
        # pid_hash table is a pointer to a dynamically allocated array of
        # hlist_head.
        pidhash_shift = self.profile.get_constant_object(
            "pidhash_shift", "unsigned int")

        pidhash = self.profile.get_constant_object(
            "pid_hash",
            target="Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    count=1 << pidhash_shift,
                    target="hlist_head")
                )
            )

        seen = set()

        # Now we iterate over all the hash slots in the hash table to retrieve
        # their struct upid entries.
        for hash in pidhash:
            for upid in hash.list_of_type("upid", "pid_chain"):
                # upid structures are contained inside pid structures:
                # http://lxr.free-electrons.com/source/kernel/pid.c?v=3.8#L351
                # container_of(pnr, struct pid, numbers[ns->level]);
                level = upid.ns.level

                pid = self.profile.pid(
                    upid.obj_offset -
                    self.profile.get_obj_offset("pid", "numbers") -
                    level * self.profile.get_obj_size("pid"))

                # Here we only care about regular PIDs.
                for task in pid.tasks[PIDTYPE_PID].list_of_type(
                    "task_struct", "pids"):
                    if task not in seen:
                        yield task
                        seen.add(task)
