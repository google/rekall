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

from rekall import plugin
from rekall.plugins.darwin import common


class DarwinHandles(common.ProcessFilterMixin, common.AbstractDarwinProducer):
    """Walks open files of each proc and collects the fileproc.

    This is the same algorithm as lsof, but aimed at just collecting the
    fileprocs, without doing anything with them, or sorting.
    """

    name = "handles"
    type_name = "fileproc"

    def collect(self):
        for proc in self.filter_processes():
            for _, fileproc, _ in proc.get_open_files():
                yield [fileproc]


class DarwinLsof(common.AbstractDarwinCommand):
    """Walks open files of each proc in order and prints PID, FD and the handle.

    Each process has an array of pointers to fileproc structs - the offset into
    the array is the file descriptor and each fileproc struct represents a
    handle on some resource. A type field in the fileproc determines the type
    of the resource pointed to from the fileproc (e.g. vnode, socket, pipe...).
    """

    name = "lsof"

    table_header = [
        dict(name="proc", type="proc",
             columns=[
                 dict(name="command", width=16),
                 dict(name="pid", width=8),
                 dict(name="p_uid", width=8)
             ]),
        dict(name="fd", width=5),
        dict(name="fileproc", type="fileproc")
    ]

    def collect(self):
        procs = self.session.plugins.collect("proc").collect()

        for proc in sorted(procs, key=lambda proc: proc.pid):
            for fd, fileproc, _ in proc.get_open_files():
                yield (proc, fd, fileproc)
