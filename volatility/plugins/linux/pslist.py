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

from volatility.plugins.linux import common


class LinuxPsList(common.AbstractLinuxCommandPlugin):
    """Gathers active tasks by walking the task_struct->task list."""

    __name = "pslist"

    def __init__(self, **kwargs):
        super(LinuxPsList, self).__init__(**kwargs)

    def pslist(self):
        """A generator of task_struct objects for all running tasks."""
        init_task_addr = self.profile.constants["init_task"]

        init_task = self.profile.Object(theType="task_struct", 
                                        vm=self.kernel_address_space,
                                        offset=init_task_addr)

        # walk the ->tasks list, note that this will *not* display "swapper"
        for task in init_task.tasks:
            yield task

    def render(self, outfd):
        outfd.write("{0:8s} {1:20s} {2:15s} {3:15s}\n".format(
            "Offset", "Name", "Pid", "Uid"))

        for task in self.pslist():
            outfd.write("0x{0:08x} {1:20s} {2:15s} {3:15s}\n".format(
                task.obj_offset, task.comm, str(task.pid), str(task.uid)))


class LinuxMemMap(common.LinProcessFilter):
    """Dumps the memory map for linux tasks."""

    __name = "memmap"

    def render(self, outfd):
        outfd.write("*" * 72 + "\n")

        for task in self.filter_processes():
            task_space = task.get_process_address_space()
            outfd.write("Process '{0}' pid: {1:6}\n".format(
                    task.comm, task.pid))

            outfd.write("{0:12} {1:12} {2:12}\n".format(
                    'Virtual', 'Physical', 'Size'))

            for va, length in task_space.get_available_pages():
                pa = task_space.vtop(va)
                if pa == None:
                    continue

                outfd.write("0x{0:010x} 0x{1:010x} 0x{2:012x}\n".format(
                        va, pa, length))
