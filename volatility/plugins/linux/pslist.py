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

from volatility.plugins import core
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


class LinMemMap(common.LinProcessFilter):
    """Dumps the memory map for linux tasks."""

    __name = "memmap"

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(LinMemMap, cls).args(parser)
        parser.add_argument(
            "--coalesce", default=False, action="store_true",
            help="Merge contiguous pages into larger ranges.")

    def __init__(self, coalesce=False, **kwargs):
        """Calculates the memory regions mapped by a process.

        Args:
          coalesce: Merge pages which are contiguous in memory into larger
             ranges.
        """
        self.coalesce = coalesce
        super(LinMemMap, self).__init__(**kwargs)

    def render(self, renderer):
        for task in self.filter_processes():
            renderer.section()
            renderer.RenderProgress("Dumping pid {0}".format(
                    task.pid))

            task_space = task.get_process_address_space()
            renderer.format(u"Process: '{0}' pid: {1:6}\n",
                            task.comm, task.pid)

            if not task_space:
                renderer.write("Unable to read pages for task.\n")
                continue

            renderer.table_header([("Virtual", "offset_v", "[addrpad]"),
                                   ("Physical", "offset_p", "[addrpad]"),
                                   ("Size", "process_size", "[addr]")])

            if self.coalesce:
                ranges = task_space.get_address_ranges()
            else:
                ranges = task_space.get_available_addresses()

            for virtual_address, length in ranges:
                phys_address = task_space.vtop(virtual_address)
                renderer.table_row(virtual_address, phys_address, length)


class LinMemDump(core.DirectoryDumperMixin, LinMemMap):
    """Dump the addressable memory for a process."""

    __name = "memdump"

    def dump_process(self, task, fd):
        task_as = task.get_process_address_space()

        for virtual_address, length in task_as.get_available_addresses():
            phys_address = task_as.vtop(virtual_address)
            fd.write(self.physical_address_space.read(phys_address, length))

    def render(self, renderer):
        if self.dump_dir is None:
            raise plugin.PluginError("Dump directory not specified.")

        for task in self.filter_processes():
            outfd.write("*" * 72 + "\n")
            filename = u"{0}_{1:d}.dmp".format(task.comm, task.pid)

            renderer.write(u"Writing {0} {1:6} to {2}\n".format(
                    task.comm, task, filename))

            with open(os.path.join(self.dump_dir, filename), 'wb') as fd:
                self.dump_process(task, fd)
