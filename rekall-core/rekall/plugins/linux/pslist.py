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

from rekall import utils
from rekall import testlib
from rekall.plugins.common import memmap
from rekall.plugins.linux import common


class LinuxPsList(common.LinProcessFilter):
    """Gathers active tasks by walking the task_struct->task list.

    It does not display the swapper process. If the DTB column is blank, the
    item is likely a kernel thread.
    """
    __name = "pslist"

    table_header = [
        dict(name="proc", width=40, type="task_struct"),
        dict(name="ppid", align="r", width=6),
        dict(name="uid", align="r", width=6),
        dict(name="gid", align="r", width=6),
        dict(name="dtb", style="address"),
        dict(name="start_time", align="r", width=24),
        dict(name="binary")
    ]

    def column_types(self):
        task = self.session.profile.task_struct()
        return dict(
            proc=task,
            ppid=0,
            uid=utils.HexInteger(0),
            gid=utils.HexInteger(0),
            dtb=utils.HexInteger(0),
            start_time=task.task_start_time,
            binary="")

    def collect(self):
        for task in self.filter_processes():
            dtb = self.kernel_address_space.vtop(task.mm.pgd)
            path = task.get_path(task.mm.m("exe_file"))
            yield (task,
                   task.parent.pid,
                   task.uid,
                   task.gid,
                   dtb, task.task_start_time,
                   path)


class LinMemMap(memmap.MemmapMixIn, common.LinProcessFilter):
    """Dumps the memory map for linux tasks."""
    __name = "memmap"


class LinMemDump(memmap.MemDumpMixin, common.LinProcessFilter):
    """Dump the addressable memory for a process."""


class TestLinMemDump(testlib.HashChecker):
    mode = "mode_linux_memory"

    PARAMETERS = dict(
        commandline="memdump --proc_regex %(proc_name)s --dump_dir %(tempdir)s",
        proc_name="bash",
    )

# We only care about PIDTYPE_PID here.
# http://lxr.free-electrons.com/source/include/linux/pid.h?v=3.8#L6
# enum pid_type
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
                    target="hlist_head"
                )
            )
        )

        seen = set()

        # Now we iterate over all the hash slots in the hash table to retrieve
        # their struct upid entries.
        for hash_slot in pidhash:
            for upid in hash_slot.list_of_type("upid", "pid_chain"):
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
