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


class LinuxPsList(common.LinProcessFilter):
    """Gathers active tasks by walking the task_struct->task list."""

    __name = "pslist"

    def __init__(self, **kwargs):
        super(LinuxPsList, self).__init__(**kwargs)

    def list_tasks(self):
        task = self.profile.task_struct(
            offset=self.task_head, vm=self.kernel_address_space)

        return iter(task.tasks)

    def render(self, renderer):
    	renderer.table_header( [("Offset (V)", "offset_v", "[addrpad]"),
                                ("Name", "file_name", "20s"),
                                ("PID", "pid", ">6"),
                                ("PPID", "ppid", ">6"),
                                ("UID", "uid", ">6"),
                                ("GID", "gid", ">6"),
                                ("DTB", "dtb", "[addrpad]"),
                                ("Start Time", "start_time", ">24"),
                                ])

        for task in self.filter_processes():
            start_time = (task.start_time.as_timestamp()+
                          task.start_time.getboottime())

            dtb = self.kernel_address_space.vtop(task.mm.pgd)
            renderer.table_row(task.obj_offset,
                               task.comm,
                               task.pid,
                               task.parent.pid,
                               task.uid,
                               task.gid,
                               dtb, start_time)


class LinuxMemMap(common.LinProcessFilter):
    """Dumps the memory map for linux tasks."""

    __name = "memmap"

    @classmethod
    def args(cls, parser):
         super(LinuxMemMap, cls).args(parser)

    def address_ranges(self, address_space):
      """Combine the addresses into ranges."""
      contiguous_offset = None
      total_length = 0

      for (offset, length) in address_space.get_available_addresses():
          # Try to join up adjacent pages as much as possible.
          if contiguous_offset is None:
              # Reset the contiguous range.
              contiguous_offset = offset
              total_length = length

          elif offset == contiguous_offset + total_length:
              total_length += length
          else:
              # Scan the last contiguous range.
              yield contiguous_offset, total_length

              # Reset the contiguous range.
              contiguous_offset = offset
              total_length = length

      if total_length > 0:
          # Do the last range.
          yield contiguous_offset, total_length

    def render(self, outfd):
        outfd.write("*" * 72 + "\n")

        for task in self.filter_processes():
            task_space = task.get_process_address_space()
            outfd.write("Process '{0}' pid: {1:6}\n".format(
                    task.comm, task.pid))

            outfd.write("{0:12} {1:12} {2:12}\n".format(
                    'Virtual', 'Physical', 'Size'))

            for va, length in self.address_ranges(task_space):
                pa = task_space.vtop(va)
                if pa == None:
                    continue

                outfd.write("0x{0:010x} 0x{1:010x} 0x{2:012x}\n".format(
                        va, pa, length))
