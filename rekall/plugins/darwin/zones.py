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

import re

from rekall import utils
from rekall.plugins.darwin import common

from rekall.entities.query import expression

class DarwinListZones(common.DarwinPlugin):
    """List all the allocation zones."""

    __name = "list_zones"

    def render(self, renderer):
        renderer.table_header([
            ("Name", "name", "30"),
            ("Active", "active", ">10"),
            ("Free", "free", ">10"),
            ("Element Size", "size", ">10"),
            ("Tracks pages", "tracks_pages", "15"),
            ("Allows foreign pages", "allows_foreign", "15")])

        for zone in sorted(
                self.session.entities.find_by_component("AllocationZone"),
                key=lambda e: e["AllocationZone/name"]):
            renderer.table_row(
                zone["AllocationZone/name"],
                zone["AllocationZone/count_active"],
                zone["AllocationZone/count_free"],
                zone["AllocationZone/element_size"],
                zone["AllocationZone/tracks_pages"],
                zone["AllocationZone/allows_foreign"])


class DarwinDumpZone(common.DarwinPlugin):
    """Dumps an allocation zone's contents."""

    __name = "dump_zone"

    @classmethod
    def args(cls, parser):
        super(DarwinDumpZone, cls).args(parser)
        parser.add_argument("--zone", default="buf.512")

    def __init__(self, zone="buf.512", **kwargs):
        super(DarwinDumpZone, self).__init__(**kwargs)
        self.zone_name = zone

    def render(self, renderer):
        for entity in self.session.entities.find(
                expression.Intersection(
                    expression.Equivalence(
                        expression.Binding("Buffer/purpose"),
                        expression.Literal("zones")),
                    expression.LetAny(
                        "Buffer/context",
                        expression.Equivalence(
                            expression.Binding("AllocationZone/name"),
                            expression.Literal(self.zone_name))))):
            utils.WriteHexdump(
                renderer=renderer,
                data=entity["Buffer/contents"],
                base=entity["Buffer/address"][0])


class DarwinDeadProcesses(common.DarwinPlugin):
    """Show deallocated processes which still exist in the zone allocator."""

    __name = "dead_procs"

    def render(self, renderer):
        # Find the proc zone from the allocator.
        proc_zone = self.session.entities.find_first(
            expression.Equivalence(
                expression.Binding("AllocationZone/name"),
                expression.Literal("proc")))["MemoryObject/base_object"]

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
