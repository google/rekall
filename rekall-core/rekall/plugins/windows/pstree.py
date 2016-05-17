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

from rekall import plugin
from rekall.plugins.windows import common


class PSTree(plugin.VerbosityMixIn, common.WinProcessFilter):
    """Print process list as a tree"""

    __name = "pstree"

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

    def render(self, renderer):
        renderer.table_header([
            dict(name="Name", type="TreeNode", max_depth=5, child=dict(
                type="_EPROCESS", style="light")),
            ("PPid", "ppid", ">6"),
            ("Thds", "thd_count", ">6"),
            ("Hnds", "hnd_count", ">6"),
            ("Time", "process_create_time", "24")])

        process_dict = self._make_process_dict()

        def draw_children(pad, pid):
            """Given a pid output all its children."""
            for task in sorted(process_dict.values(), key=lambda x: x.pid):
                if task.InheritedFromUniqueProcessId != pid:
                    continue

                renderer.table_row(
                    task,
                    task.InheritedFromUniqueProcessId,
                    task.ActiveThreads,
                    task.ObjectTable.m("HandleCount"),
                    task.CreateTime, depth=pad, parent=pid)

                if self.plugin_args.verbosity > 1:
                    try:
                        process_params = task.Peb.ProcessParameters
                        renderer.format(u"{0}    cmd: {1}\n",
                                        ' ' * pad, process_params.CommandLine)
                        renderer.format(u"{0}    path: {1}\n",
                                        ' ' * pad, process_params.ImagePathName)
                        renderer.format(
                            u"{0}    audit: {1}\n", ' ' * pad,
                            (task.SeAuditProcessCreationInfo.ImageFileName.Name
                             or "UNKNOWN"))
                    except KeyError:
                        pass

                process_dict.pop(int(task.UniqueProcessId), None)
                draw_children(pad + 1, task.UniqueProcessId)

        while process_dict:
            keys = process_dict.keys()
            root = self._find_root(process_dict, keys[0])
            draw_children(0, root)
