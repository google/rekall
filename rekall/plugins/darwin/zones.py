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

from rekall import utils
from rekall.plugins.darwin import common


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
                query=("Buffer/purpose is 'zones' and "
                       "any Buffer/context matches "
                       " (AllocationZone/name is {zone_name})"),
                query_params=dict(zone_name=self.zone_name)):
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
            "AllocationZone/name is 'proc'")["Struct/base"]

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
