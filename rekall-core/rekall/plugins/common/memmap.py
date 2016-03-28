
# Rekall Memory Forensics
# Copyright 2015 Google Inc. All Rights Reserved.
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

"""This module implements core memmap/memdump plugins."""

__author__ = "Michael Cohen <scudette@gmail.com>"

from rekall import plugin
from rekall import utils
from rekall.ui import text
from rekall.plugins import core


class MemmapMixIn(object):
    """A Mixin to create the memmap plugins for all the operating systems."""

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(MemmapMixIn, cls).args(parser)
        parser.add_argument(
            "--coalesce", default=False, type="Boolean",
            help="Merge contiguous pages into larger ranges.")

        parser.add_argument(
            "--all", default=False, type="Boolean",
            help="Use the entire range of address space.")

    def __init__(self, *pos_args, **kwargs):
        """Calculates the memory regions mapped by a process or the kernel.

        If no process filtering directives are provided, enumerates the kernel
        address space.
        """
        self.coalesce = kwargs.pop("coalesce", False)
        self.all = kwargs.pop("all", False)
        super(MemmapMixIn, self).__init__(*pos_args, **kwargs)

    def _render_map(self, task_space, renderer, highest_address):
        renderer.format(u"Dumping address space at DTB {0:#x}\n\n",
                        task_space.dtb)

        renderer.table_header([("Virtual", "offset_v", "[addrpad]"),
                               ("Physical", "offset_p", "[addrpad]"),
                               ("Size", "process_size", "[addr]")])

        if self.coalesce:
            ranges = task_space.merge_base_ranges()
        else:
            ranges = task_space.get_mappings()

        for run in ranges:
            # When dumping out processes do not dump the kernel.
            if not self.all and run.start > highest_address:
                break

            renderer.table_row(run.start, run.file_offset, run.length)

    def render(self, renderer):
        if not self.filtering_requested:
            # Dump the entire kernel address space.
            return self._render_map(self.kernel_address_space, renderer, 2**64)

        max_memory = self.session.GetParameter("highest_usermode_address")
        for task in self.filter_processes():
            renderer.section()
            renderer.RenderProgress("Dumping pid {0}".format(task.pid))

            task_space = task.get_process_address_space()
            renderer.format(u"Process: '{0}' pid: {1:6}\n\n",
                            task.name, task.pid)

            if not task_space:
                renderer.write("Unable to read pages for task.\n")
                continue

            self._render_map(task_space, renderer, max_memory)


class MemDumpMixin(core.DirectoryDumperMixin, MemmapMixIn):
    """Dump the addressable memory for a process.

    Note that because the addressable memory is sparse we do not maintain
    alignment in the output file. Instead, we also write an index file which
    describes all the sparse runs in the dump - but the dump file has all the
    data concatenated.
    """

    name = "memdump"

    def dump_process(self, eprocess, fd, index_fd):
        task_as = eprocess.get_process_address_space()
        temp_renderer = text.TextRenderer(session=self.session,
                                          fd=index_fd)
        with temp_renderer.start():
            temp_renderer.table_header([
                ("File Address", "file_addr", "[addrpad]"),
                ("Length", "length", "[addrpad]"),
                ("Virtual Addr", "virtual", "[addrpad]")])

            # Only dump the userspace portion of addressable memory.
            max_memory = self.session.GetParameter("highest_usermode_address")
            blocksize = 1024 * 1024

            for run in task_as.get_address_ranges(end=max_memory):
                for offset in utils.xrange(run.start, run.end, blocksize):
                    to_read = min(blocksize, run.end - offset)
                    if to_read == 0:
                        break

                    data = task_as.read(offset, to_read)
                    file_offset = fd.tell()
                    fd.write(data)

                    # Write the index file.
                    temp_renderer.table_row(file_offset, to_read, offset)


    def render(self, renderer):
        if self.dump_dir is None:
            raise plugin.PluginError("Dump directory not specified.")

        for task in self.filter_processes():
            renderer.section()
            filename = u"{0}_{1:d}.dmp".format(task.name, task.pid)

            renderer.format(u"Writing {0} to {1}\n",
                            task, filename)

            with renderer.open(directory=self.dump_dir,
                               filename=filename,
                               mode='wb') as fd:
                with renderer.open(directory=self.dump_dir,
                                   filename=filename + ".idx",
                                   mode='wb') as index_fd:
                    self.dump_process(task, fd, index_fd)
