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

__author__ = "Michael Cohen <scudette@google.com>"

import os

from rekall.plugins import core
from rekall.plugins.darwin import common


class DarwinPsxView(common.DarwinProcessFilter):
    __name = "psxview"

    def render(self, renderer):
        headers = [
            ("Offset (V)", "offset_v", "[addrpad]"),
            ("Comm", "comm", "20s"),
            ("PID", "pid", ">6"),
        ]

        method_names = self.METHODS.keys()

        for method in method_names:
            headers.append((method, method, str(len(method))))

        renderer.table_header(headers)

        for process in self.filter_processes():
            row = [
                process,
                process.p_comm,
                process.p_pid,
            ]

            for method in method_names:
                row.append(process in self.cache[method])

            renderer.table_row(*row)


class DarwinPsList(common.DarwinProcessFilter):
    __name = "pslist"

    def render(self, renderer):
        renderer.table_header([
            ("Offset (V)", "offset_v", "[addrpad]"),
            ("Name", "file_name", "20s"),
            ("PID", "pid", ">6"),
            ("PPID", "ppid", ">6"),
            ("UID", "uid", ">6"),
            ("GID", "gid", ">6"),
            ("Bits", "bits", "12"),
            ("DTB", "dtb", "[addrpad]"),
            ("Start Time", "start_time", ">24"),
        ])

        for proc in self.filter_processes():
            renderer.table_row(
                proc,
                proc.p_comm,
                proc.p_pid,
                proc.p_pgrpid,
                proc.p_uid,
                proc.p_gid,
                proc.task.map.pmap.pm_task_map,
                proc.task.map.pmap.pm_cr3,
                proc.p_start,
            )


class DawrinPSTree(common.DarwinPlugin):
    """Shows the parent/child relationship between processes.

    This plugin prints a parent/child relationship tree by walking the
    proc.p_children list.
    """
    __name = "pstree"

    def render(self, renderer):
        renderer.table_header([
            ("Pid", "pid", ">6"),
            ("Ppid", "ppid", ">6"),
            ("Uid", "uid", ">6"),
            ("", "depth", "0"),
            ("Name", "name", "<30"),
        ])

        # Find the kernel process.
        pslist = list(self.session.plugins.pslist(
            proc_regex="kernel_task").filter_processes())
        root_proc = pslist[0]

        for proc, level in self.recurse_proc(root_proc, 0):
            renderer.table_row(
                proc.p_pid, proc.p_pgrpid, proc.p_uid,
                "." * level, proc.p_comm)

    def recurse_proc(self, proc, level):
        """Yields all the children of this proc."""
        yield proc, level

        # Iterate over all the siblings of the child.
        for child in proc.p_children.lh_first.p_sibling:
            for subproc, sublevel in self.recurse_proc(child, level + 1):
                yield subproc, sublevel


class DarwinMaps(common.DarwinProcessFilter):
    """Display the process maps."""

    __name = "maps"

    def render(self, renderer):
        renderer.table_header([
            ("Pid", "pid", "8"),
            ("Name", "name", "20"),
            ("Start", "start", "[addrpad]"),
            ("End", "end", "[addrpad]"),
            ("Protection", "protection", "6"),
            ("Map Name", "map_name", "20"),
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
                    proc.p_pid,
                    proc.p_comm,
                    map.links.start,
                    map.links.end,
                    protection,
                    "sub_map" if map.is_sub_map else vnode.path,
                )

class DarwinVadDump(core.DirectoryDumperMixin, common.DarwinProcessFilter):
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

                with open(os.path.join(self.dump_dir, filename), 'wb') as fd:
                    self.CopyToFile(task_space, vma.links.start,
                                    vma.links.end, fd)


class DarwinListSessions(common.DarwinPlugin):
    """Enumerate sessions."""

    __name = "sessions"

    def render(self, renderer):
        renderer.table_header([("Leader Pid", "leader_pid", ">10"),
                               ("Leader Name", "leader_name", "20"),
                               ("Login", "login", "25")])

        session_hash_table_size = self.profile.get_constant_object(
            "_sesshash", "unsigned long")

        # The hashtable is an array to session list heads.
        session_hash_table = self.profile.get_constant_object(
            "_sesshashtbl",
            target="Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    target="sesshashhead",
                    count=session_hash_table_size.v()
                    )
                )
            )

        # We iterate over the table and then over each list.
        for sesshashhead in session_hash_table:
            for session in sesshashhead.lh_first.walk_list("s_hash.le_next"):
                if session.s_leader:
                    renderer.table_row(session.s_leader.p_pid,
                                       session.s_leader.p_comm,
                                       session.s_login)


class DarwinPSAUX(common.DarwinProcessFilter):
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
