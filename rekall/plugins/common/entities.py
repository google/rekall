# Rekall Memory Forensics
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

"""Various plugins that make entities testable and easier to profile."""

__author__ = "Adam Sindelar <adamsh@google.com>"

import sys

from rekall import plugin
from rekall.entities import component as entity_component


class DebugCollector(plugin.Command):
    __name = "debug_collector"

    @classmethod
    def args(cls, parser):
        super(DebugCollector, cls).args(parser)
        parser.add_argument("--collector")

    def find_collector(self, collector_name):
        for collector in self.session.entities.collectors:
            if collector.name == collector_name:
                return collector

        return None

    def __init__(self, collector=None, **kwargs):
        super(DebugCollector, self).__init__(**kwargs)
        self.collector = self.find_collector(collector)

    def render(self, renderer):
        ingest = None
        if self.collector.ingests:
            ingest = self.session.entities.find(self.collector.ingests)

        for result in self.collector.collect(ingest=ingest):
            renderer.write(str(result))
            renderer.write("\n\n")


class EntityStats(plugin.Command):
    """Lists all active entity collectors and how many entities they collect.

    This will collect ALL currently collectable entities and may be slow!
    """

    __name = "entity_stats"

    def render(self, renderer):
        renderer.table_header([
            ("Component", "component", "30"),
            ("Entities collected", "count_entities", ">30"),
            ("Active collectors", "count_collectors", ">30")])

        for component_name in sorted(entity_component.Component.classes.keys()):
            collector_count = 0
            for collector in self.session.entities.collectors:
                if collector.can_collect(component_name):
                    collector_count += 1

            renderer.table_row(
                component_name,
                len(self.session.entities.find_by_component(component_name)),
                collector_count)


class ListEvents(plugin.Command):
    __name = "list_events"

    @staticmethod
    def event_sortkey(event):
        timestamp = event["Event/timestamp"]
        if timestamp:
            return timestamp

        category = event["Event/category"]
        if category in ("latest", "recent"):
            # Stuff that doesn't have a timestamp but is flagged as latest or
            # recent should sort as AFTER all known timestamps.
            return sys.maxint

        # Events without a timestamp that aren't recent or latest should sort
        # as BEFORE all known timestamps.
        return -(sys.maxint - 1)

    def render(self, renderer):
        renderer.table_header([
            ("Time", "time", "35"),
            ("Category", "category", "10"),
            ("Actor", "actor", "30"),
            ("Action", "action", "30"),
            ("Target", "target", "30")])

        for event in sorted(
                self.session.entities.find_by_component("Event"),
                key=self.event_sortkey):
            renderer.table_row(
                event["Event/timestamp"],
                event["Event/category"],
                event["Event/actor"],
                event["Event/action"],
                event["Event/target"])
