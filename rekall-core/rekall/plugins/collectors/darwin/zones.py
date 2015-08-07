# Rekall Memory Forensics
#
# Copyright 2014 Google Inc. All Rights Reserved.
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

"""
Collectors that deal with Darwin zone allocator.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall.entities import collector
from rekall.entities import definitions

from rekall.plugins.collectors.darwin import common


class DarwinZoneCollector(common.DarwinEntityCollector):
    """Lists all allocation zones."""
    outputs = ["AllocationZone", "Struct/type=zone"]

    def collect(self, hint):
        first_zone = self.profile.get_constant_object(
            "_first_zone",
            target="Pointer",
            target_args=dict(
                target="zone"))

        for zone in first_zone.walk_list("next_zone"):
            yield [
                definitions.AllocationZone(
                    name=zone.zone_name.deref(),
                    count_active=int(zone.count),
                    count_free=int(zone.m("sum_count") - zone.count),
                    element_size=zone.elem_size,
                    tracks_pages=bool(zone.m("use_page_list")),
                    allows_foreign=bool(zone.allows_foreign)),
                definitions.Struct(
                    base=zone,
                    type="zone")]


class DarwinZoneElementCollector(common.DarwinEntityCollector):
    """Lists all the valid elements in a given allocation zone."""

    __abstract = True

    zone_name = None
    type_name = None
    collect_args = dict(zones="has component AllocationZone")

    def collect(self, hint, zones):
        for element, state in self.collect_base_objects(
                zone_name=self.zone_name, zones=zones):
            yield definitions.Struct(
                base=element,
                type=self.type_name,
                state=state)

    def collect_base_objects(self, zone_name, zones):
        zone = None
        for entity in zones:
            if entity["AllocationZone/name"] == zone_name:
                zone_entity = entity
                zone = entity["Struct/base"]
                break

        if zone is None:
            return

        seen_offsets = set()
        seen_pages = set()

        # Each zone has a list of addresses that are either fresh or have been
        # freed. We don't know which is which, so we'll walk them all and rely
        # on validation.
        for element in zone.free_elements.walk_list("next"):
            for validated_element in self._process_offset(
                    offset=element.obj_offset,
                    state="freed",
                    seen_offsets=seen_offsets):
                yield validated_element

        # Having done that, we now have a list of addresses we already know are
        # designated as free. Now we'll process each of the pages that they
        # were on.
        for element in seen_offsets.copy():
            for validated_element in self._process_page(
                    offset=int(element),
                    seen_pages=seen_pages,
                    element_size=zone.elem_size,
                    seen_offsets=seen_offsets):
                yield validated_element

        # Some zones track the pages they've been given (see flag
        # use_page_list) - if this data is available then process those pages
        # as well.
        lists = {"all_free": "freed",
                 "all_used": "allocated",
                 "intermediate": "unknown"}
        if zone_entity["AllocationZone/tracks_pages"]:
            for purpose in lists.keys():
                for validated_element in self._process_page_list(
                        list_head=zone.m(purpose).next,
                        seen_pages=seen_pages,
                        state=lists[purpose],
                        element_size=zone.elem_size,
                        seen_offsets=seen_offsets):
                    yield validated_element

    def _process_offset(self, offset, seen_offsets, state="allocated"):
        if offset in seen_offsets:
            return
        seen_offsets.add(offset)

        element = self.profile.Object(offset=offset, type_name=self.type_name)
        if self.validate_element(element):
            yield element, state

    def _process_page(self, offset, seen_pages, seen_offsets, element_size,
                      state="allocated"):
        # This code assumes zones are 4096 bytes. If we run into large zones
        # then we'll cross that bridge when we come to it.
        page_start = offset & ~0xfff
        if page_start in seen_pages:
            return
        seen_pages.add(page_start)

        limit = page_start + 4096 - element_size
        # Page metadata is inlined at the end of each page.
        limit -= self.profile.get_obj_size("zone_page_metadata")

        offset = page_start
        while offset < limit:
            for element in self._process_offset(
                    offset=offset,
                    seen_offsets=seen_offsets,
                    state=state):
                yield element
            offset += element_size

    def _process_page_list(self, list_head, seen_pages, element_size,
                           seen_offsets, state="allocated"):
        for page in list_head.walk_list("next"):
            for validated_element in self._process_page(
                    offset=page.obj_offset(),
                    element_size=element_size,
                    seen_offsets=seen_offsets,
                    seen_pages=seen_pages,
                    state=state):
                yield validated_element


class DarwinZoneBufferCollector(DarwinZoneElementCollector):
    """Finds all valid offsets in an allocation zone as Buffers."""

    outputs = ["Buffer/purpose=zones"]
    type_name = "int"  # Dummy type.

    collect_args = dict(zones="has component AllocationZone")
    enforce_hint = True
    run_cost = collector.CostEnum.VeryHighCost

    def collect(self, hint, zones):
        # If given a hint, we analyze it and see if it can tell us the
        # name of the allocation zone this is looking for.
        hinted_zone = None
        if hint:
            for dependency in self.manager.analyze(hint)["dependencies"]:
                if (dependency.component == "AllocationZone" and
                        dependency.attribute == "name"):
                    hinted_zone = dependency.value
                    break

        if not hinted_zone:
            return

        for zone in zones:
            if hinted_zone and zone["AllocationZone/name"] != hinted_zone:
                continue

            for element, state in self.collect_base_objects(
                    zone_name=zone["AllocationZone/name"], zones=zones):
                yield definitions.Buffer(
                    start=(element.obj_offset, element.obj_vm.dtb),
                    size=zone["AllocationZone/element_size"],
                    contents=element.obj_vm.read(
                        element.obj_offset,
                        zone["AllocationZone/element_size"]),
                    state=state,
                    purpose="zones",
                    context=zone.identity)

    def validate_element(self, _):
        return True


class DarwinZoneVnodeCollector(DarwinZoneElementCollector):
    outputs = ["Struct/type=vnode"]
    zone_name = "vnodes"
    type_name = "vnode"

    def validate_element(self, vnode):
        # Note for later: HFS-related vnodes can be validated
        # by the pointer they have back to the vnode from the cnode (v_data).
        return vnode.v_owner == 0 and vnode.v_mount != 0
