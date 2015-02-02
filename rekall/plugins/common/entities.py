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

from rekall import plugin
from rekall import testlib

from rekall.entities import entity as entity_module
from rekall.entities import component as entity_component

from rekall.entities.query import expression as expr
from rekall.entities.query import query as entity_query


class TestEntityFind(testlib.SortedComparison):
    PARAMETERS = dict(
        commandline="find \"Process/command =~ '%(process)s'\"",
        process="lsass")


class TestEntityAnalyze(testlib.SortedComparison):
    PARAMETERS = dict(commandline="analyze \"Process/command =~ 'lsass'\"")


class EntityAnalyze(plugin.ProfileCommand):
    __name = "analyze"

    COLLECTOR_COSTS = ["none", "cheap", "normal", "high", "INSANE!"]

    @classmethod
    def args(cls, parser):
        super(EntityAnalyze, cls).args(parser)
        parser.add_argument("query", positional=True,
                            help="The filter query to use")

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

    def render_indexing(self, renderer):
        renderer.section("Suggested indexing (created automatically).")
        renderer.table_header([
            dict(name="Indexed attribute", width=40)])
        for lookup in self.analysis["lookups"]:
            renderer.table_row(lookup)

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
        self.render_indexing(renderer)


class EntityFind(plugin.ProfileCommand):
    """Runs the query and displays results. Base class for saved searches.

    This class is designed to be subclasses by saved searches. Subclasses may
    override the defaults for the following properties:

    query, search: The query that'll be run.
    (--)display_filter: Another query that'll be used to filter out unwanted
                        results.
    (--)columns: A list of attributes to render in the output. Format as
                 "Component/attribute".
    (--)sort: A list of columns to sort by. Sort is currently ASC. Same format
              as above.
    (--)width: Width of the rendered table.
    (--)stream_results: If on, will render results as soon as they're available.
                        This typically means the results will be incomplete. It
                        is probably pointless to use this in combination with
                        'sort' but no one will stop you.

    Further arguments that can be supplied at runtime:

    --explain: If set, an analysis of the query will be rendered and each
               row in results will include a highlight of the part of the query
               that matched it (obviously a heuristic, your mileage may vary).
    """

    __name = "find"
    description = None

    search = None
    display_filter = None
    columns = ()
    sort = ()
    width = 120
    stream_results = False
    complete_results = True

    query = None

    @classmethod
    def args(cls, parser):
        super(EntityFind, cls).args(parser)
        parser.add_argument("query", required=False,
                            help="The filter query to use.")
        parser.add_argument("--columns", default=None, nargs="+", type="str")
        parser.add_argument("--sort", default=None, nargs="+", type="str")
        parser.add_argument("--explain", type="Boolean", default=False,
                            help="Show which part of the query matched.")
        parser.add_argument("--width", type="int", default=None)
        parser.add_argument("--filter", type="str")
        parser.add_argument("--complete_results", type="Boolean", default=True)
        parser.add_argument("--stream_results", type="Boolean", default=False)

    def __init__(self, query=None, explain=None, columns=None, sort=None,
                 width=None, filter=None, stream_results=False,
                 complete_results=True, **kwargs):
        super(EntityFind, self).__init__(**kwargs)
        if query:
            self.query = entity_query.Query(query)
        else:
            self.query = entity_query.Query(self.search)

        if columns is not None:
            self.columns = columns

        if sort is not None:
            self.sort = sort

        if width is not None:
            self.width = width

        if filter is not None:
            self.display_filter = entity_query.Query(filter)

        if stream_results is not None:
            self.stream_results = stream_results

        if complete_results is not None:
            self.complete_results = complete_results

        self.explain = explain

    def _build_sort_func(self):
        if not self.sort:
            return
        sort_keys = tuple(self.sort)
        sort_types = [entity_module.Entity.reflect_attribute(a).typedesc
                      for a in sort_keys]

        # Entity is in the first column. Rows are tuples of (object, options).
        def _sort_func(row):
            entity = row[0][0]
            result = []
            for idx, key in enumerate(sort_keys):
                result.append(sort_types[idx].sortkey(entity[key]))
            return result

        return _sort_func

    def render_entity(self, renderer, entity):
        if self.display_filter and not self.display_filter.execute(
                "QueryMatcher", method="match", bindings=entity):
            return

        cols = [entity]
        opts = dict(style="full")
        if self.explain:
            match = self.query.execute("QueryMatcher", method="match",
                                       bindings=entity,
                                       match_backtrace=True)
            cols.append(self.query)
            opts["query_highlight"] = match.matched_expression

        renderer.table_row(*cols, **opts)

    def render(self, renderer):
        if self.explain:
            self.session.RunPlugin("analyze", self.query)
            renderer.section("Results:", width=self.width)

        # If no columns were specified, try to guess from the list of
        # components we think will appear in results.
        if not self.columns:
            self.columns = []
            for component in self.session.entities.analyze(self.query).get(
                    "guaranteed_components"):
                component_cls = entity_module.Entity.reflect_component(
                    component)
                for attribute in component_cls.component_attributes.values():
                    if attribute.hidden:
                        continue

                    self.columns.append(attribute.path)

            self.columns.sort()

        columns = [dict(name="Entity", cname="entity", type="Entity",
                        width=self.width, style="full", columns=self.columns)]

        if self.explain:
            columns.append(dict(name="Matched query", type="Query", width=60))

        renderer.table_header(columns, sort_key_func=self._build_sort_func())

        self.session.report_progress(
            "Running query %(query)s %(spinner)s", query=self.query)

        if self.stream_results:
            def _handler(entity):
                self.render_entity(renderer, entity)

            self.session.entities.stream(self.query, _handler)
        else:
            for entity in self.session.entities.find(
                    self.query, complete=self.complete_results):
                self.render_entity(renderer, entity)


class FindBatch(plugin.ProfileCommand):
    """Runs several plugins in order. Subclass to set the batch."""

    __abstract = True
    batch = []

    @classmethod
    def args(cls, parser):
        super(FindBatch, cls).args(parser)
        parser.add_argument("--sort", default=None, nargs="+", type="str")
        parser.add_argument("--explain", type="Boolean", default=False,
                            help="Show which part of the query matched.")
        parser.add_argument("--filter", type="str")

    def __init__(self, filter=None, sort=None, explain=None, **kwargs):
        super(FindBatch, self).__init__(**kwargs)
        self.display_filter = filter
        self.sort = sort
        self.explain = explain

    def render(self, renderer):
        for command in self.batch:
            plugin_obj = getattr(self.session.plugins, command)()
            description = getattr(plugin_obj, "description")
            if description:
                renderer.section(description, width=120)

            self.session.RunPlugin(
                command, filter=self.display_filter, sort=self.sort,
                explain=self.explain)


class EntityDescribe(plugin.ProfileCommand):
    """Analyzes the query and prints a lot of mostly useless information."""
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
            width=140)
        renderer.table_header([
            dict(name="Field", cname="field", width=16),
            dict(name="Type", cname="type", width=20),
            dict(name="Description", cname="description", width=60),
            dict(name="Show by default", cname="visible", width=16),
            dict(name="Notes", cname="notes", width=30)])

        for attribute in sorted(
                component_cls.component_attributes.itervalues(),
                key=lambda attr: attr.name):
            alias = getattr(attribute, "alias", None)
            renderer.table_row(attribute.name,
                               "%s (%s)" % (attribute.typedesc.type_name,
                                            type(attribute).__name__),
                               attribute.docstring,
                               not attribute.hidden,
                               "Aliased to %s" % alias if alias else None)

    def render(self, renderer):
        if self.component:
            return self.render_component(
                renderer,
                entity_component.Component.classes[self.component])

        for component_cls in sorted(
                entity_component.Component.classes.itervalues(),
                key=lambda comp: comp.component_name):
            self.render_component(renderer, component_cls)
