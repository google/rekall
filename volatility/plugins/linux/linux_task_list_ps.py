# Volatility
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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""

import volatility.obj as obj
import linux_common

class linux_task_list_ps(linux_common.AbstractLinuxCommand):

    ''' gathers active tasks by walking the task_struct->task list '''

    __name = "pslist"

    def __init__(self, config, *args):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args)
        self._config.add_option('PID', short_option = 'p', default = None, help = 'Operate on these Process IDs (comma-separated)', action = 'store', type = 'str')

    def calculate(self):
        init_task_addr = self.smap["init_task"]

        init_task = obj.Object("task_struct", vm = self.addr_space, offset = init_task_addr)

        pidlist = None

        try:
            if self._config.PID:
                pidlist = [int(p) for p in self._config.PID.split(',')]
        except:
            pass

        # walk the ->tasks list, note that this will *not* display "swapper"
        for task in linux_common.walk_list_head("task_struct", "tasks", init_task.tasks, self.addr_space):

            if not pidlist or task.pid in pidlist:
                yield task

    def render_text(self, outfd, data):

        outfd.write("{0:8s} {1:20s} {2:15s} {3:15s}\n".format(
            "Offset", "Name", "Pid", "Uid"))

        for task in data:
            outfd.write("0x{0:08x} {1:20s} {2:15s} {3:15s}\n".format(
                task.obj_offset, task.comm, str(task.pid), str(task.get_uid())))
