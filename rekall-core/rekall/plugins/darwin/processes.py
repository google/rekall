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
Darwin Process collectors.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall import plugin
from rekall import registry

from rekall.plugins import core
from rekall.plugins.darwin import common
from rekall.plugins.common import memmap


class DarwinPslist(common.ProcessFilterMixin,
                   common.AbstractDarwinCommand):
    name = "pslist"

    table_header = [
        dict(width=40, name="proc", type="proc"),
        dict(width=8, name="alive"),
        dict(name="ppid", width=6),
        dict(name="uid", width=6),
        dict(name="is64bit", width=6),
        dict(name="start_time", width=30, style="short"),
        dict(name="cr3", width=15, style="address")
    ]

    def collect(self):
        for proc in self.filter_processes():
            yield dict(
                proc=proc,
                alive=proc.obj_producers != {"dead_procs"},
                ppid=proc.p_ppid,
                uid=proc.p_uid,
                is64bit=proc.task.map.pmap.pm_task_map == "TASK_MAP_64BIT",
                start_time=proc.p_start.as_datetime(),
                cr3=proc.task.map.pmap.pm_cr3
            )


class DarwinPsxView(common.ProcessFilterMixin,
                    common.AbstractDarwinCommand):
    name = "psxview"

    # pylint: disable=no-self-argument
    @registry.classproperty
    @registry.memoize
    def table_header(cls):
        header = [dict(width=40, name="proc", type="proc")]

        for method in cls.methods():
            header.append(dict(name=method, width=8))

        return plugin.PluginHeader(*header)

    def collect(self):
        methods = self.methods()
        for proc in self.filter_processes():
            row = [proc]
            for method in methods:
                row.append(method in proc.obj_producers)

            yield row


class DarwinPsTree(common.AbstractDarwinCommand):
    name = "pstree"

    table_header = [
        dict(name="depth", type="DepthIndicator", width=10),
        dict(name="pid", width=6),
        dict(name="ppid", width=6),
        dict(name="uid", width=6),
        dict(name="name", width=30)
    ]

    def collect(self):
        # Get the first process from pslist.
        first_proc = self.session.plugins.search(
            "(select * from pslist() where proc.pid == 0).proc").first_result
        for proc, depth in self.recurse_proc(first_proc, 0):
            yield [depth, proc.pid, proc.p_ppid, proc.p_uid, proc.command]

    def recurse_proc(self, proc, depth):
        if proc.validate():
            yield proc, depth
        for child in proc.p_children.lh_first.p_sibling:
            for subproc, subdepth in self.recurse_proc(child, depth + 1):
                yield subproc, subdepth


class DarwinMaps(common.ProcessFilterMixin, common.AbstractDarwinCommand):
    """Display the process maps."""

    __name = "maps"

    def render(self, renderer):
        renderer.table_header([
            dict(name="vm_map_entry", style="address"),
            dict(name="Proc", width=40),
            ("Start", "start", "[addrpad]"),
            ("End", "end", "[addrpad]"),
            ("Protection", "protection", "6"),
            dict(name="Map Name", wrap=False),
        ])

        for proc in self.filter_processes():
            for map in proc.task.map.hdr.walk_list(
                    "links.next", include_current=False):

                # Format the map permissions nicesly.
                protection = (
                    ("r" if map.protection.VM_PROT_READ else "-") +
                    ("w" if map.protection.VM_PROT_WRITE else "-") +
                    ("x" if map.protection.VM_PROT_EXECUTE else "-"))

                # Find the vnode this mapping is attached to.
                vnode = map.find_vnode_object()

                renderer.table_row(
                    map,
                    proc,
                    map.links.start,
                    map.links.end,
                    protection,
                    "sub_map" if map.is_sub_map else vnode.path,
                )


class DarwinVadDump(core.DirectoryDumperMixin, common.ProcessFilterMixin,
                    common.AbstractDarwinCommand):
    """Dump the VMA memory for a process."""

    __name = "vaddump"

    def render(self, renderer):
        for proc in self.filter_processes():
            if not proc.task.map.pmap:
                continue

            renderer.format("Pid: {0:6}\n", proc.p_pid)

            # Get the task and all process specific information
            task_space = proc.get_process_address_space()
            name = proc.p_comm

            for vma in proc.task.map.hdr.walk_list(
                    "links.next", include_current=False):
                filename = "{0}.{1}.{2:08x}-{3:08x}.dmp".format(
                    name, proc.p_pid, vma.links.start, vma.links.end)

                renderer.format(u"Writing {0}, pid {1} to {2}\n",
                                proc.p_comm, proc.p_pid, filename)

                with renderer.open(directory=self.dump_dir,
                                   filename=filename,
                                   mode='wb') as fd:
                    self.CopyToFile(task_space, vma.links.start,
                                    vma.links.end, fd)


class DarwinPSAUX(common.ProcessFilterMixin, common.AbstractDarwinCommand):
    """List processes with their commandline."""

    __name = "psaux"

    def render(self, renderer):
        renderer.table_header([
            ("Pid", "pid", "8"),
            ("Name", "name", "20"),
            ("Stack", "stack", "[addrpad]"),
            ("Length", "length", "8"),
            ("Argc", "argc", "8"),
            ("Arguments", "argv", "[wrap:80]")])

        for proc in self.filter_processes():
            renderer.table_row(
                proc.p_pid,
                proc.p_comm,
                proc.user_stack,
                proc.p_argslen,
                proc.p_argc,
                " ".join(proc.argv))


class DarwinMemMap(memmap.MemmapMixIn, common.ProcessFilterMixin,
                   common.AbstractDarwinCommand):
    """Prints the memory map for darwin tasks."""
    __name = "memmap"

    def _get_highest_user_address(self):
        return 0x800000000000


class DarwinMemDump(memmap.MemDumpMixin, common.ProcessFilterMixin,
                    common.AbstractDarwinCommand):
    """Dumps the memory map for darwin tasks."""


# Plugins below represent different enumeration methods for process filter:


class PsListAllProcHook(common.AbstractDarwinParameterHook):
    """List all processes by following the _allproc list head."""

    name = "allproc"

    def calculate(self):
        first = self.session.profile.get_constant_object(
            "_allproc", target="proclist").lh_first

        result = set(first.p_list)
        return [x.obj_offset for x in result]


class PsListTasksHook(common.AbstractDarwinParameterHook):
    """List all processes by following the _allproc list head."""

    name = "tasks"

    def calculate(self):
        """List processes using the processor tasks queue.

        See
        /osfmk/kern/processor.c (processor_set_things)
        """
        seen = set()

        tasks = self.session.profile.get_constant_object(
            "_tasks",
            target="queue_entry",
            vm=self.session.kernel_address_space)

        for task in tasks.list_of_type("task", "tasks"):
            proc = task.bsd_info.deref()
            if proc:
                seen.add(proc.obj_offset)

        return seen


class PsListPgrpHashHook(common.AbstractDarwinParameterHook):
    """List all processes by following the _allproc list head."""

    name = "pgrphash"

    def calculate(self):
        """Process groups are organized in a hash chain.

        xnu-1699.26.8/bsd/sys/proc_internal.h
        """
        seen = set()

        # Note that _pgrphash is initialized through:

        # xnu-1699.26.8/bsd/kern/kern_proc.c:195
        # hashinit(int elements, int type, u_long *hashmask)

        # /xnu-1699.26.8/bsd/kern/kern_subr.c: 327
        # hashinit(int elements, int type, u_long *hashmask) {
        #    ...
        # *hashmask = hashsize - 1;

        # Hence the value in _pgrphash is one less than the size of the hash
        # table.
        pgr_hash_table = self.session.profile.get_constant_object(
            "_pgrphashtbl",
            target="Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    target="pgrphashhead",
                    count=self.session.profile.get_constant_object(
                        "_pgrphash", "unsigned long") + 1
                )
            )
        )

        for slot in pgr_hash_table.deref():
            for pgrp in slot.lh_first.walk_list("pg_hash.le_next"):
                for proc in pgrp.pg_members.lh_first.walk_list(
                        "p_pglist.le_next"):
                    seen.add(proc.obj_offset)

        return seen


class PsListPidHashHook(common.AbstractDarwinParameterHook):
    """List all processes by following the _allproc list head."""

    name = "pidhash"

    def calculate(self):
        """Lists processes using pid hash tables.

        xnu-1699.26.8/bsd/kern/kern_proc.c:834:
        pfind_locked(pid_t pid)
        """
        seen = set()

        # Note that _pidhash is initialized through:

        # xnu-1699.26.8/bsd/kern/kern_proc.c:194
        # pidhashtbl = hashinit(maxproc / 4, M_PROC, &pidhash);

        # /xnu-1699.26.8/bsd/kern/kern_subr.c: 327
        # hashinit(int elements, int type, u_long *hashmask) {
        #    ...
        # *hashmask = hashsize - 1;

        # Hence the value in pidhash is one less than the size of the hash
        # table.
        pid_hash_table = self.session.profile.get_constant_object(
            "_pidhashtbl",
            target="Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    target="pidhashhead",
                    count=self.session.profile.get_constant_object(
                        "_pidhash", "unsigned long") + 1
                )
            )
        )

        for plist in pid_hash_table.deref():
            for proc in plist.lh_first.walk_list("p_hash.le_next"):
                if proc:
                    seen.add(proc.obj_offset)

        return seen


class DarwinPgrpHashCollector(common.AbstractDarwinCachedProducer):
    name = "pgrphash"
    type_name = "proc"


class DarwinTaskProcessCollector(common.AbstractDarwinCachedProducer):
    name = "tasks"
    type_name = "proc"


class DarwinAllProcCollector(common.AbstractDarwinCachedProducer):
    name = "allproc"
    type_name = "proc"


class DarwinPidHashProcessCollector(common.AbstractDarwinCachedProducer):
    name = "pidhash"
    type_name = "proc"
