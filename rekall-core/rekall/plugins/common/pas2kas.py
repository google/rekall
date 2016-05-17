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

# pylint: disable=protected-access

import bisect

from rekall import testlib
from rekall.ui import json_renderer


class Pas2VasResolver(object):
    """An object which resolves physical addresses to virtual addresses."""
    def __init__(self, session):
        self.session = session
        self.dirty = True

        # Maintains some maps to ensure fast lookups.
        self.dtb2task = {}
        self.dtb2maps = {}
        self.dtb2userspace = {}

        # Add the kernel.
        self.dtb2task[self.session.GetParameter("dtb")] = "Kernel"

        pslist = self.session.plugins.pslist()
        for task in pslist.filter_processes():
            task_dtb = task.dtb
            if task_dtb != None:
                self.dtb2task[task_dtb] = task.obj_offset

    def _get_highest_user_address(self):
        return 2**64-1

    def GetTaskStruct(self, address):
        """Returns the task struct for the address.

        Should be overridden by OS specific implementations.
        """
        return address

    def PA2VA_for_DTB(self, physical_address, dtb, userspace=None):
        if dtb == None:
            return None, None

        # Choose the userspace mode automatically.
        if userspace is None:
            userspace = dtb != self.session.kernel_address_space.dtb

        # Build a map for this dtb.
        lookup_map = self.dtb2maps.get(dtb)

        # If we want the full resolution and the previous cached version was for
        # userspace only, discard this lookup map and rebuild it.
        if not userspace and self.dtb2userspace.get(dtb):
            lookup_map = None

        if lookup_map is None:
            lookup_map = self.dtb2maps[dtb] = self.build_address_map(
                dtb, userspace=userspace)
            self.dtb2userspace[dtb] = userspace

        if lookup_map:
            if physical_address > lookup_map[0][0]:
                # This efficiently finds the entry in the map just below the
                # physical_address.
                lookup_pa, length, lookup_va = lookup_map[
                    bisect.bisect(
                        lookup_map, (physical_address, 2**64, 0, 0))-1]

                if (lookup_pa <= physical_address and
                        lookup_pa + length > physical_address):
                    # Yield the pid and the virtual offset
                    task = self.dtb2task.get(dtb)
                    if task is not None:
                        task = self.GetTaskStruct(task)
                    else:
                        task = "Kernel"

                    return lookup_va + physical_address - lookup_pa, task

        return None, None

    def build_address_map(self, dtb, userspace=True):
        """Given the virtual_address_space, build the address map."""
        # This lookup map is sorted by the physical address. We then use
        # bisect to efficiently look up the physical page.
        tmp_lookup_map = []
        self.dirty = True

        if dtb != None:
            address_space = self.session.kernel_address_space.__class__(
                base=self.session.physical_address_space,
                session=self.session,
                dtb=dtb)

            highest_virtual_address = self.session.GetParameter(
                "highest_usermode_address")

            for run in address_space.get_mappings():
                # Only consider userspace addresses for processes.
                if userspace and run.start > highest_virtual_address:
                    break

                tmp_lookup_map.append((run.file_offset, run.length, run.start))
                self.session.report_progress(
                    "Enumerating memory for dtb %#x (%#x)", dtb, run.start)

            # Now sort the map and return it.
            tmp_lookup_map.sort()

        return tmp_lookup_map


class Pas2VasMixin(object):
    """Resolves a physical address to a virtual addrress in a process."""

    name = "pas2vas"

    __args = [
        dict(name="offsets", type="ArrayIntParser",
             help="A list of physical offsets to resolve."),
    ]

    def get_virtual_address(self, physical_address, tasks=None):
        resolver = self.session.GetParameter("physical_address_resolver")

        if tasks is None:
            tasks = list(self.filter_processes())

        # First try the kernel.
        virtual_address, _ = resolver.PA2VA_for_DTB(
            physical_address, dtb=self.session.kernel_address_space.dtb,
            userspace=False)

        if virtual_address:
            yield virtual_address, "Kernel"

        # Find which process owns it.
        for task in tasks:
            virtual_offset, task = resolver.PA2VA_for_DTB(
                physical_address, task.dtb, userspace=True)
            if virtual_offset is not None:
                yield virtual_offset, task

    def render(self, renderer):
        renderer.table_header([('Physical', 'virtual_offset', '[addrpad]'),
                               ('Virtual', 'physical_offset', '[addrpad]'),
                               ('Pid', 'pid', '>6'),
                               ('Name', 'name', '')])

        tasks = list(self.filter_processes())
        for physical_address in self.plugin_args.offsets:
            for virtual_address, task in self.get_virtual_address(
                    physical_address, tasks):
                if task is 'Kernel':
                    renderer.table_row(physical_address, virtual_address,
                                       0, 'Kernel')
                else:
                    renderer.table_row(
                        physical_address, virtual_address,
                        task.pid, task.name)


class Pas2VasResolverJsonObjectRenderer(json_renderer.StateBasedObjectRenderer):
    """Encode and decode the pas2vas maps efficiently."""

    renders_type = "Pas2VasResolver"

    def EncodeToJsonSafe(self, item, **_):
        result = {}
        result["dtb2task"] = item.dtb2task
        result["dtb2maps"] = item.dtb2maps
        result["dtb2userspace"] = item.dtb2userspace
        result["mro"] = ":".join(self.get_mro(item))

        return result

    def DecodeFromJsonSafe(self, value, _):
        # Get the original class to instantiate the required item.
        cls = self.GetImplementationFromMRO(Pas2VasResolver, value)
        result = cls(session=self.session)

        for attr in ["dtb2maps", "dtb2userspace", "dtb2task"]:
            if attr in value:
                setattr(result, attr, value[attr])

        result.dirty = False
        return result



class TestPas2Vas(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="pas2vas --offsets %(offset)s - %(pids)s ",
        pid=0,
    )
