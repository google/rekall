# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
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

import bisect

from rekall import config
from rekall.plugins.linux import common


class LinPas2Vas(common.LinProcessFilter):
    """Resolves a physical address to a virtual addrress in a process."""

    __name = "pas2vas"

    @classmethod
    def args(cls, parser):
        super(LinPas2Vas, cls).args(parser)
        parser.add_argument("offsets", action=config.ArrayIntParser, nargs="+",
                            help="A list of physical offsets to resolve.")

    def __init__(self, offsets=None, **kwargs):
        """Resolves a physical address to a vertial address.

        Often a user might want to see which process maps a particular physical
        offset. In reality the same physical memory can be mapped into multiple
        processes (and the kernel) at the same time. Usually since the kernel
        memory is mapped into each process's address space, a single physical
        offset which is mapped into the kernel will also be mapped into each
        process.

        The only way to tell if a physical page is mapped into a process is to
        enumerate all process maps and then search them for the physical
        offset. This takes a fair bit of memory and effort to build so by
        default we store the maps in the session for quick reuse.
        """
        super(LinPas2Vas, self).__init__(**kwargs)

        # Now we build the tables for each process. We do this simply by listing
        # all the tasks using pslist, and then for each task we get its address
        # space, and enumerate available pages.
        if offsets is None:
            raise RuntimeError("Some offsets must be provided.")

        try:
            self.physical_address = list(offsets)
        except TypeError:
            self.physical_address = [offsets]

        # Cache the process maps in the session.
        if self.session.process_maps is None:
            self.session.process_maps = {}

        self.maps = self.session.process_maps

        self.memmap = self.session.plugins.memmap(session=self.session)
        if "Kernel" not in self.maps:
            self.build_address_map(self.kernel_address_space, "Kernel", None)

        for task in self.filter_processes():
            pid = int(task.pid)

            task_as = task.get_process_address_space()

            # All kernel processes have the same page tables.
            if task_as.dtb == self.kernel_address_space.dtb:
                continue

            if pid in self.session.process_maps:
                continue

            self.session.report_progress("Enumerating memory for %s (%s)" % (
                task.pid, task.comm))

            self.build_address_map(task_as, pid, task)

    def build_address_map(self, virtual_address_space, pid, task):
        """Given the virtual_address_space, build the address map."""
        # This lookup map is sorted by the physical address. We then use
        # bisect to efficiently look up the physical page.
        tmp_lookup_map = []
        for va, pa, length in virtual_address_space.get_available_addresses():
            tmp_lookup_map.append((pa, length, va, task))

        tmp_lookup_map.sort()
        self.maps[pid] = tmp_lookup_map

    def get_virtual_address(self, physical_address):
        # Check if its in the kernel first.
        virtual_offset, task = self._get_virtual_address(
            physical_address, "Kernel")

        # Its not in the kernel - find which process owns it.
        if virtual_offset is None:
            for pid in self.maps:
                virtual_offset, task = self._get_virtual_address(
                    physical_address, pid)
                if virtual_offset is not None:
                    yield virtual_offset, task
        else:
            yield virtual_offset, "Kernel"

    def _get_virtual_address(self, physical_address, pid):
        lookup_map = self.maps[pid]

        if physical_address > lookup_map[0][0]:
            # This efficiently finds the entry in the map just below the
            # physical_address.
            lookup_pa, length, lookup_va, task = lookup_map[
                bisect.bisect(lookup_map, (physical_address, 2**64, 0))-1]

            if (lookup_pa <= physical_address and
                lookup_pa + length > physical_address):
                # Yield the pid and the virtual offset
                return lookup_va + physical_address - lookup_pa, task
        return None, None

    def render(self, renderer):
        renderer.table_header([('Physical', 'virtual_offset', '[addrpad]'),
                               ('Virtual', 'physical_offset', '[addrpad]'),
                               ('Pid', 'pid', '>6'),
                               ('Name', 'name', '')])

        for physical_address in self.physical_address:
            for virtual_address, task in self.get_virtual_address(
                physical_address):
                if task is 'Kernel':
                    renderer.table_row(physical_address, virtual_address,
                                       0, 'Kernel')
                else:
                    renderer.table_row(physical_address, virtual_address,
                                       task.pid, task.comm)
