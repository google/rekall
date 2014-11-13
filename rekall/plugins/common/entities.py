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

import itertools
import sys

from rekall import config
from rekall import plugin

from rekall.entities import component as entity_component

from rekall.entities.query import expression as expr
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


class EntityAnalyze(plugin.Command):
    __name = "analyze"

    COLLECTOR_COSTS = ["none", "cheap", "normal", "high", "INSANE!"]

    @classmethod
    def args(cls, parser):
        super(EntityAnalyze, cls).args(parser)
        parser.add_positional_arg("query")

    def __init__(self, query=None, **kwargs):
        super(EntityAnalyze, self).__init__(**kwargs)
        self.query = entity_query.Query(query)
        self.analysis = self.session.entities.analyze(self.query)

    def render_components(self, renderer):
        renderer.section("Expected components in result set:", width=140)
        renderer.table_header([
            dict(name="Guaranteed", width=20),
            dict(name="Component", width=20)])

        for component in self.analysis["guaranteed_components"]:
            renderer.table_row(True, component)

        for component in self.analysis["possible_components"]:
            renderer.table_row(False, component)

    def render_dependencies(self, renderer):
        renderer.section("Expected requirements for matching objects:",
                         width=140)
        renderer.table_header([
            dict(name="Dependency", cname="dependency", width=40,
                 type="Dependency"),
            dict(name="Explanation", cname="explanation", width=100,
                 type="Query")])

        for dependency in itertools.chain(self.analysis["dependencies"],
                                          self.analysis["exclusions"]):
            renderer.table_row(dependency, self.query,
                               query_highlight=dependency.expression)

    def render_collectors(self, renderer):
        manager = self.session.entities
        renderer.section("Dependencies on collectors:", width=140)
        renderer.table_header([
            dict(name="Collector", cname="collector", width=40),
            dict(name="Cost to run", cname="cost", width=20),
            dict(name="Needed because of", cname="reason", width=80)])

        collectors = {}
        queue = []
        for collector in self.analysis["collectors"]:
            queue.append(collector)
            collectors[collector] = ["the query"]

        while queue:
            collector = queue.pop()
            for query in collector.collect_queries.itervalues():
                for additional in manager.analyze(query)["collectors"]:
                    if additional in collectors:
                        collectors[additional].append(collector.name)
                        continue
                    else:
                        collectors[additional] = [collector.name]
                        queue.append(additional)

        for collector, reasons in collectors.iteritems():
            renderer.table_row(collector.name,
                               self.COLLECTOR_COSTS[collector.run_cost],
                               ", ".join(reasons))

    def _render_node(self, node, renderer, depth=0):
        renderer.table_row(
            type(node).__name__,
            self.query,
            depth=depth, query_highlight=node)

        for child in node.children:
            if not isinstance(child, expr.Expression):
                renderer.table_row(
                    "leaf (%s):" % type(child).__name__,
                    "",
                    depth=depth + 1)
                continue

            self._render_node(node=child, renderer=renderer, depth=depth + 1)

    def render_tree(self, renderer):
        renderer.section("Query analysis:", width=140)
        renderer.table_header([
            dict(name="Expression", cname="expression", type="TreeNode",
                 max_depth=15, width=40),
            dict(name="Location in query", cname="source", type="Query",
                 width=100)])

        self._render_node(self.query.expression, renderer)

    def render(self, renderer):
        self.render_tree(renderer)
        self.render_dependencies(renderer)
        self.render_components(renderer)
        self.render_collectors(renderer)


class EntityFind(plugin.Command):
    __name = "find"

    @classmethod
    def args(cls, parser):
        super(EntityFind, cls).args(parser)
        parser.add_positional_arg("query")
        parser.add_argument("--components", default=None, nargs="+",
                            type="str")
        parser.add_argument("--attributes", default=None, nargs="+",
                            type="str")
        parser.add_argument("--explain", type="Boolean", default=False,
                            help="Show which part of the query matched.")

    def __init__(self, query=None, explain=None, components=None,
                 attributes=None, **kwargs):
        super(EntityFind, self).__init__(**kwargs)
        self.query = entity_query.Query(query)
        self.explain = explain
        self.components = components
        self.attributes = attributes

    def render(self, renderer):
        analysis = self.session.entities.analyze(self.query)

        if self.components:
            components = self.components
        else:
            analysis = self.session.entities.analyze(self.query)
            components = analysis["guaranteed_components"]

        columns = [dict(name="Entity", cname="entity", type="Entity", width=120,
                        style="full", components=components,
                        attributes=self.attributes)]

        if self.explain:
            columns.append(dict(name="Matched query", type="Query", width=60))
        renderer.table_header(columns)

        for entity in self.session.entities.find(self.query):
            cols = [entity]
            opts = dict(style="full")
            if self.explain:
                match = self.query.execute("QueryMatcher", method="match",
                                           bindings=entity,
                                           match_backtrace=True)
                cols.append(self.query)
                opts["query_highlight"] = match.matched_expression

            renderer.table_row(*cols, **opts)


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
