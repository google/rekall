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
    """List open files for processes."""

    __name = "lsof"

    def Lsof(self, proc):
        for i, fileproc in enumerate(proc.p_fd.fd_ofiles):
            # When the type of the glob is VNODE it contains a vnode struct.
            if fileproc.f_fglob.fg_type == "DTYPE_VNODE":
                vnode = fileproc.f_fglob.fg_data.dereference_as("vnode")
                yield fileproc, i, vnode.full_path

    def render(self, renderer):
        renderer.table_header([("PID", "pid", "8"),
                               ("Command", "command", "16"),
                               ("File Desc", "desc", "10"),
                               ("Path", "path", "20")])

        for proc in sorted(self.filter_processes(), key=lambda x: x.p_pid):
            for _, fd, path in self.Lsof(proc):
                renderer.table_row(proc.p_pid, proc.p_comm, fd, path)
