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
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization:
"""
from rekall.plugins.linux import common

class PSAux(common.LinProcessFilter):
    """Gathers processes along with full command line and start time."""

    __name = "psaux"

    def render(self, renderer):
        renderer.table_header([
                ("PID", "pid", "5"),
                ("UID", "uid", "5"),
                ("GID", "gid", "5"),
                ("Command", "command", "50")])

        for task in self.filter_processes():
            renderer.table_row(task.pid, task.uid, task.gid, task.commandline)
