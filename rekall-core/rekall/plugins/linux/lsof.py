# Rekall Memory Forensics
#
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright 2013 Google Inc. All Rights Reserved.
#
# This file is part of Rekall Memory Forensics.
#
# Rekall Memory Forensics is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# Rekall Memory Forensics is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with Rekall Memory Forensics.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization:
"""

from rekall import testlib
from rekall.plugins.linux import common


class Lsof(common.LinProcessFilter):
    """Lists open files."""

    __name = "lsof"

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="proc", hidden=True),
        dict(name="file_struct", hidden=True),
        dict(name="name", width=30),
        dict(name="pid", width=6, align="r"),
        dict(name="user", width=8),
        dict(name="fd", width=4),
        dict(name="size", width=12),
        dict(name="offset", width=12),
        dict(name="node", width=8),
        dict(name="path"),
    ]

    def get_open_files(self, task):
        """List all the files open by a task."""
        # The user space file descriptor is simply the offset into the fd
        # array.
        for i, file_ptr in enumerate(task.files.fds):
            file_struct = file_ptr.deref()
            if file_struct:
                yield file_struct, i

    def lsof(self):
        for task in self.filter_processes():
            for file_struct, fd in self.get_open_files(task):
                yield task, file_struct, fd

    def collect(self):
        for task in self.filter_processes():
            yield dict(divider=task)
            for file_struct, fd in self.get_open_files(task):
                yield dict(proc=task,
                           name=task.comm,
                           pid=task.pid,
                           user=task.uid,
                           fd=fd,
                           file_struct=file_struct,
                           size=file_struct.m("f_path.dentry.d_inode.i_size"),
                           offset=file_struct.m("f_pos"),
                           node=file_struct.m("f_path.dentry.d_inode.i_ino"),
                           path=task.get_path(file_struct))


class TestLsof(testlib.SimpleTestCase):
    @classmethod
    def is_active(cls, session):
        return Lsof.is_active(session)

    PARAMETERS = dict(
        commandline="lsof --proc_regex %(proc_name)s",
        proc_name="bash"
        )
