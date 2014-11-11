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

from rekall import config
from rekall import plugin

from rekall.entities import component as entity_component

from rekall.entities.query import query as entity_query


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


config.DeclareOption(
    "-E", "--entity_filter", default=None,
    help="Filter to apply to all plugins backed by the entity layer.")


class EntityFind(plugin.Command):
    __name = "find"

    @classmethod
    def args(cls, parser):
        super(EntityFind, cls).args(parser)
        parser.add_positional_arg("query")
        parser.add_argument("--explain", type="Boolean", default=False,
                            help="Show which part of the query matched.")

    def __init__(self, query=None, explain=None, **kwargs):
        super(EntityFind, self).__init__(**kwargs)
        self.query = entity_query.Query(query)
        self.explain = explain

    def render(self, renderer):
        renderer.table_header([("Entity", "entity", "120")])
        for entity in self.session.entities.find(self.query):
            renderer.table_row(entity)
            if self.explain:
                match = self.query.execute("QueryMatcher", method="match",
                                           bindings=entity,
                                           match_backtrace=True)

                source = self.query.expression_source(match.matched_expression)
                explanation = "Explanation: %s >>> %s <<< %s\n" % source
                renderer.write(explanation)


class EntityDescribe(plugin.Command):
    __name = "describe"

    @classmethod
    def args(cls, parser):
        super(EntityDescribe, cls).args(parser)
        parser.add_positional_arg("component")

    def __init__(self, component=None, **kwargs):
        super(EntityDescribe, self).__init__(**kwargs)
        self.component = component

    def render_component(self, renderer, component_cls):
        renderer.section(
            "%s: %s" % (component_cls.component_name,
                        component_cls.component_docstring),
            width=100)
        renderer.table_header([
            dict(name="Field", cname="field", width=20),
            dict(name="Type", cname="type", width=20),
            dict(name="Description", cname="description", width=50)])

        for field in component_cls.component_fields:
            renderer.table_row(field.name,
                               field.typedesc.type_name,
                               field.docstring)

    def render(self, renderer):
        if self.component:
            return self.render_component(
                renderer,
                entity_component.Component.classes[self.component])

        for component_cls in entity_component.Component.classes.itervalues():
            self.render_component(renderer, component_cls)
