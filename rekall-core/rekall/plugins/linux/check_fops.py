# Rekall Memory Forensics
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright 2013 Google Inc. All Rights Reserved.
#
# This file is part of Rekall Memory Forensics.
#
# Rekall Memory Forensics is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General Public
# License.
#
# Rekall Memory Forensics is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# Rekall Memory Forensics.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Michael Cohen based on code by Andrew Case
@license:      GNU General Public License 2.0
@contact:      scudette@gmail.com
"""
import itertools
import posixpath

from rekall import testlib
from rekall.plugins.linux import common


class CheckProcFops(common.LinuxPlugin):
    """Checks the proc filesystem for hooked f_ops."""
    __name = "check_proc_fops"

    @classmethod
    def args(cls, parser):
        super(CheckProcFops, cls).args(parser)
        parser.add_argument("--all", type="Boolean", default=False,
                            help="Specify to see all the fops, even if they "
                            "are known.")

    def __init__(self, all=False, **kwargs):
        super(CheckProcFops, self).__init__(**kwargs)
        self.module_plugin = self.session.plugins.lsmod(session=self.session)
        self.all = all

    def _check_members(self, struct, members):
        """Yields struct members and their containing module."""
        for member in members:
            ptr = struct.m(member)
            if not ptr:
                continue

            # This is really a function pointer.
            func = ptr.dereference_as(target="Function",
                                      target_args=dict(name=member))

            yield member, func

    def _walk_proc(self, current, seen, path=""):
        """Recursively traverse the proc filesystem yielding proc_dir_entry.

        Yields:
          tuples of proc_dir_entry, full_path to this proc entry.
        """
        # Prevent infinite recursion here.
        if current in seen:
            return
        seen.add(current)

        yield current, posixpath.join(path, current.Name)

        # Yield our peers.
        for proc_dir_entry in current.walk_list("next"):
            for x in self._walk_proc(proc_dir_entry, seen, path):
                yield x

        # Now also yield the subdirs:
        if current.subdir:
            for x in self._walk_proc(
                current.subdir, seen,
                posixpath.join(path, unicode(current.Name))):
                yield x

    def check_proc_fop(self):
        """Check the proc mount point."""
        f_op_members = sorted(self.profile.file_operations().members.keys())
        proc_mnt = self.profile.get_constant_object(
            "proc_mnt",
            target="Pointer",
            target_args=dict(
                target="vfsmount"
                ),
            vm=self.kernel_address_space)

        root = proc_mnt.mnt_root
        for member, func in self._check_members(
            root.d_inode.i_fop, f_op_members):
            yield (proc_mnt, "proc_mnt: root", member, func)


        # only check the root directory
        for dentry in root.d_subdirs.list_of_type("dentry", "d_u"):
            name = dentry.d_name.name.deref()
            for member, func in self._check_members(
                dentry.d_inode.i_fop, f_op_members):
                yield dentry, name, member, func

    def check_fops(self):
        """Check the file ops for all the open file handles."""
        f_op_members = sorted(self.profile.file_operations().members.keys())
        proc_root = self.profile.get_constant_object(
            "proc_root",
            target="proc_dir_entry",
            vm=self.kernel_address_space)

        seen = set()
        for proc_dir_entry, full_path in self._walk_proc(proc_root, seen):
            for member, func in self._check_members(
                proc_dir_entry.proc_fops, f_op_members):
                yield proc_dir_entry, full_path, member, func

    def render(self, renderer):
        renderer.table_header([
            ("DirEntry", "proc_dir_entry", "[addrpad]"),
            ("Path", "path", "<50"),
            ("Member", "member", "<20"),
            ("Address", "address", "[addrpad]"),
            ("Module", "module", "")])

        for proc_dir_entry, path, member, func in itertools.chain(
            self.check_proc_fop(), self.check_fops()):
            location = ", ".join(
                self.session.address_resolver.format_address(
                    func.obj_offset))

            # Point out suspicious constants.
            highlight = None if location else "important"

            if highlight or self.all:
                renderer.table_row(proc_dir_entry, path, member, func,
                                   location, highlight=highlight)

            self.session.report_progress(
                    "Checking proc f_ops for %(path)s", path=path)


class TestCheckProcFops(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="check_proc_fops --all"
        )



class CheckTaskFops(CheckProcFops, common.LinProcessFilter):
    """Check open files in tasks for f_ops modifications."""
    __name = "check_task_fops"

    def check_fops(self):
        """Check the file ops for all the open file handles."""
        f_op_members = sorted(self.profile.file_operations().members.keys())

        # Use the lsof plugin to get all the open files in each task we care
        # about.
        lsof = self.session.plugins.lsof(session=self.session)

        for task in self.filter_processes():
            for file_struct, _ in lsof.get_open_files(task):
                for member, func in self._check_members(
                    file_struct.f_op, f_op_members):
                    yield task, member, func

    def render(self, renderer):
        renderer.table_header([("Pid", "pid", "6"),
                               ("Command", "comm", "20"),
                               ("Member", "member", "30"),
                               ("Address", "address", "[addrpad]"),
                               ("Module", "module", "<20")])

        for task, member, func in self.check_fops():
            location = ", ".join(
                self.session.address_resolver.format_address(
                    func.obj_offset))

            highlight = None if location else "important"

            if highlight or self.all:
                renderer.table_row(task.pid, task.comm, member, func,
                                   location, highlight=highlight)

            self.session.report_progress(
                "Checking task f_ops for %(comm)s (%(pid)s)",
                comm=task.comm, pid=task.pid)


class TestCheckTaskFops(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="check_task_fops --proc_regex %(proc_name)s --all",
        proc_name="bash"
        )
