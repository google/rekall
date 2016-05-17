# Rekall Memory Forensics
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2010, 2011, 2012 Michael Ligh <michael.ligh@mnin.org>
# Copyright 2014 Google Inc. All Rights Reserved.
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

# pylint: disable=protected-access


from rekall.plugins.linux import common


class LinuxPsxView(common.LinProcessFilter):
    """Find hidden processes comparing various process listings."""

    __name = "psxview"

    METHODS = common.LinProcessFilter.METHODS + [
        "PidHashTable",
    ]

    __args = [
        dict(name="method", choices=METHODS, type="ChoiceArray",
             default=METHODS, help="Method to list processes.",
             override=True),
    ]

    def render(self, renderer):
        headers = [('Offset(V)', 'virtual_offset', '[addrpad]'),
                   ('Name', 'name', '<20'),
                   ('PID', 'pid', '>12'),
                  ]

        for method in self.plugin_args.method:
            headers.append((method, method, "%s" % len(method)))

        renderer.table_header(headers)

        for process in self.filter_processes():
            row = [process.obj_offset, process.comm, process.pid]

            for method in self.plugin_args.method:
                row.append(process.obj_offset in
                           self.session.GetParameter("pslist_%s" % method))

            renderer.table_row(*row)


class PidHashTableHook(common.AbstractLinuxParameterHook):
    name = "pslist_PidHashTable"

    def calculate(self):
        seen = set()
        pidhashtable_plugin = self.session.plugins.pidhashtable()
        for task in pidhashtable_plugin.filter_processes():
            if task.obj_offset not in seen:
                seen.add(task.obj_offset)

        return seen
