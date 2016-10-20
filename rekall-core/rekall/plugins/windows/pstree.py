# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors
# Michael Cohen <scudette@users.sourceforge.net>
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
#

"""pstree example file"""

from rekall.plugins.windows import common


class PSTree(common.WinProcessFilter):
    """Print process list as a tree"""

    __name = "pstree"

    table_header = [
        dict(name="_EPROCESS", type="TreeNode", max_depth=5, child=dict(
            type="_EPROCESS", style="light")),
        dict(name="ppid", width=6, align="r"),
        dict(name="thd_count", width=6, align="r"),
        dict(name="hnd_count", width=6, align="r"),
        dict(name="create_time", width=24),
        dict(name="cmd", width=40, hidden=True),
        dict(name="path", width=40, hidden=True),
        dict(name="audit", width=40, hidden=True),
    ]

    def _find_root(self, pid_dict, pid):
        # Prevent circular loops.
        seen = set()

        while pid in pid_dict and pid not in seen:
            seen.add(pid)
            pid = int(pid_dict[pid].InheritedFromUniqueProcessId)

        return pid

    def _make_process_dict(self):
        """Returns a dict keyed by pids with values _EPROCESS objects."""
        result = {}
        for eprocess in self.filter_processes():
            result[int(eprocess.UniqueProcessId)] = eprocess

        return result

    def collect(self):
        process_dict = self._make_process_dict()

        def draw_children(pad, pid):
            """Given a pid output all its children."""
            for task in sorted(process_dict.values(), key=lambda x: x.pid):
                if task.InheritedFromUniqueProcessId != pid:
                    continue

                process_params = task.Peb.ProcessParameters

                yield dict(
                    _EPROCESS=task,
                    ppid=task.InheritedFromUniqueProcessId,
                    thd_count=task.ActiveThreads,
                    hnd_count=task.ObjectTable.m("HandleCount"),
                    create_time=task.CreateTime,
                    cmd=process_params.CommandLine,
                    path=process_params.ImagePathName,
                    audit=task.SeAuditProcessCreationInfo.ImageFileName.Name,
                    depth=pad)

                process_dict.pop(task.pid, None)
                for x in draw_children(pad + 1, task.pid):
                    yield x

        while process_dict:
            keys = process_dict.keys()
            root = self._find_root(process_dict, keys[0])
            for x in draw_children(0, root):
                yield x
