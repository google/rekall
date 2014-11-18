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

from rekall.plugins.darwin import common


class DarwinLsof(common.DarwinProcessFilter):
    """Lists open files, grouped by process that has the handle.

    A file is an overloaded term; this plugin will list files, directories,
    Unix sockets, pipes, shared memory regions and certain other kernel
    structures.
    """

    __name = "old_lsof"

    def lsof(self, proc_sort_key=None):
        """Get all open files (sockets, vnodes, etc.) for all processes.

        Args:
          proc_sort_key:
            A callable that takes proc and returns a key to sort by. If None
            (default) then no sorting will be done.

        Yields:
          Dict of proc, fd, flags and fileproc.
        """
        procs = self.filter_processes()
        if proc_sort_key:
            procs = sorted(procs, key=proc_sort_key)

        for proc in procs:
            for fd, fileproc, flags in proc.get_open_files():
                yield dict(proc=proc,
                           fd=fd,
                           flags=flags,
                           fileproc=fileproc)

    def render(self, renderer):
        renderer.table_header([("Command", "command", "16"),
                               ("PID", "pid", "8"),
                               ("UID", "uid", "8"),
                               ("FD", "fd", "10"),
                               ("Type", "type", "15"),
                               ("Name", "name", "40")])

        for open_file in self.lsof(proc_sort_key=lambda proc: proc.pid):
            renderer.table_row(open_file["proc"].p_comm,
                               open_file["proc"].pid,
                               open_file["proc"].p_uid,
                               open_file["fd"],
                               open_file["fileproc"].human_type,
                               open_file["fileproc"].human_name)
