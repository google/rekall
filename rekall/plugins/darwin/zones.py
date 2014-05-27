# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
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
"""Plugins for inspecting memory allocation zones."""

__author__ = "Michael Cohen <scudette@google.com>"


from rekall import obj
from rekall.plugins.darwin import common


class DarwinListZones(common.DarwinPlugin):
    """List all the allocation zones."""

    __name = "list_zones"

    def ListZones(self):
        first_zone = self.profile.get_constant_object(
            "_first_zone",
            target="Pointer",
            target_args=dict(
                target="zone"
                )
            )

        return first_zone.walk_list("next_zone")

    def GetZone(self, name):
        for zone in self.ListZones():
            if zone.zone_name.deref() == name:
                return zone

        return obj.NoneObject("Zone for %s not found." % name, log=True)

    def render(self, renderer):
        renderer.table_header([
                ("Name", "name", "30"),
                ("Active", "active", ">10"),
                ("Free", "free", ">10"),
                ("Size", "size", ">10")])

        for zone in self.ListZones():
            renderer.table_row(zone.zone_name.deref(),
                               zone.count,
                               zone.m("sum_count") - zone.count,
                               zone.elem_size)


class DarwinDeadProcesses(common.DarwinPlugin):
    """Show deallocated processes which still exist in the zone allocator."""

    __name = "dead_procs"

    def render(self, renderer):
        # Find the proc zone from the allocator.
        proc_zone = DarwinListZones(session=self.session).GetZone("proc")

        # Walk over the free list and get all proc objects.
        procs = []
        for allocation in proc_zone.free_elements.walk_list("next"):
            proc = allocation.cast("proc")
            # Validate the proc.
            if proc.p_argc > 0:
                procs.append(proc)

        if procs:
            # Just delegate the rendering to the regular pslist plugin.
            pslist_plugin = self.session.plugins.pslist(proc=procs)
            pslist_plugin.render(renderer)
