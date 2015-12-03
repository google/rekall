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

"""Rekall's search function."""

__author__ = "Adam Sindelar <adamsh@google.com>"


from rekall import obj
from rekall import plugin
from rekall import testlib
from rekall import utils

from rekall.ui import identity as identity_renderer

from efilter import ast
from efilter import errors
from efilter import protocol
from efilter import query as q

from efilter.transforms import solve
from efilter.transforms import infer_type

from efilter.protocols import associative
from efilter.protocols import reflective
from efilter.protocols import repeated


class TestWhichPlugin(testlib.SimpleTestCase):
    PLUGIN = "which_plugin"
    PARAMETERS = dict(
        commandline="which_plugin %(struct)s",
        struct="proc"
    )


class TestCollect(testlib.SimpleTestCase):
    PLUGIN = "collect"
    PARAMETERS = dict(
        commandline="collect %(struct)s",
        struct="proc"
    )


class TestExplain(testlib.SimpleTestCase):
    PLUGIN = "explain"
    PARAMETERS = dict(
        commandline="explain %(query)r",
        query="select * from pslist where (proc.pid == 1)"
    )


class TestSearch(testlib.SimpleTestCase):
    PLUGIN = "search"
    PARAMETERS = dict(
        commandline="search %(query)r",
        query="select * from pslist where (proc.pid == 1)"
    )


class FindPlugins(plugin.ProfileCommand):
    name = "which_plugin"

    type_name = None
    producers_only = False

    @classmethod
    def args(cls, parser):
        super(FindPlugins, cls).args(parser)
        parser.add_argument("type_name", required=True,
                            help="Which plugins produce this type?")
        parser.add_argument("producers_only", required=False, default=False,
                            help="Only include hook-backed plugins?")

    def __init__(self, type_name, producers_only=False, **kwargs):
        super(FindPlugins, self).__init__(**kwargs)
        self.type_name = type_name
        self.producers_only = producers_only

    def collect(self):
        if self.producers_only:
            pertinent_cls = plugin.Producer
        else:
            pertinent_cls = plugin.TypedProfileCommand

        for plugin_cls in plugin.Command.classes.itervalues():
            if not plugin_cls.is_active(self.session):
                continue

            if not issubclass(plugin_cls, pertinent_cls):
                continue

            for t in plugin_cls.table_header.types_in_output:
                if isinstance(t, type) and self.type_name == t.__name__:
                    yield plugin_cls(session=self.session)
                elif self.type_name == t:
                    yield plugin_cls(session=self.session)

    def render(self, renderer):
        renderer.table_header([
            dict(name="Plugin", cname="plugin", type="Plugin", style="compact",
                 width=30)
        ])

        for command in self.collect():
            renderer.table_row(command)


class Collect(plugin.ProfileCommand):
    name = "collect"

    type_name = None

    @classmethod
    def args(cls, parser):
        super(Collect, cls).args(parser)
        parser.add_argument("type_name", required=True,
                            help="The type (struct) to collect.")

    def __init__(self, type_name, **kwargs):
        super(Collect, self).__init__(**kwargs)
        self.type_name = type_name

    def collect(self):
        which = self.session.plugins.which_plugin(type_name=self.type_name,
                                                  producers_only=True)

        results = {}
        for producer in which.collect():
            # We know the producer plugin implements 'produce' because
            # 'which_plugin' guarantees it.
            for result in producer.produce():
                previous = results.get(result.indices)
                if previous:
                    previous.obj_producers.add(producer.name)
                else:
                    result.obj_producers = set([producer.name])
                    results[result.indices] = result

        return results.itervalues()

    def render(self, renderer):
        renderer.table_header([
            dict(name=self.type_name, cname=self.type_name,
                 type=self.type_name),
            dict(name="Producers", cname="producers")
        ])

        for result in self.collect():
            renderer.table_row(result, result.obj_producers)


class EfilterPlugin(plugin.ProfileCommand):
    """Abstract base class for plugins that do something with queries.

    Provides implementations of the basic EFILTER protocols for selecting and
    inspecting the output of plugins.
    """
    __abstract = True

    query = None
    _cached_plugin_renderers = {}

    # Plugin lifecycle:

    @classmethod
    def args(cls, parser):
        super(EfilterPlugin, cls).args(parser)
        parser.add_argument(
            "query",
            required=True,
            help="The dotty/EFILTER query to run.")

        parser.add_argument(
            "query_parameters",
            default=[],
            type="ArrayStringParser",
            help="Positional parameters for parametrized queries.")

    def __init__(self, query, query_parameters=None, **kwargs):
        super(EfilterPlugin, self).__init__(**kwargs)
        self.query = q.Query(query, params=query_parameters)
        self.query_parameters = query_parameters

    # EFILTER protocol implementations:

    def select(self, key):
        """Return output of a plugin."""
        if key in self.getkeys():
            return self._select_plugin(key)

        raise KeyError("No plugin named %r." % key)

    def _select_plugin(self, key):
        """Get output from a plugin indicated by key.

        This has two modes of operation. If the plugin is typed we can just run
        collect. If it doesn't, we pass the render function a special renderer
        which preserves output.

        The renderer instances we pass the plugins also preserve the table
        headers and are cached in _cached_plugin_renderers for future reference.

        Returns:
            An instance of IdentityRenderer holding table header and rows.
        """
        meta = self.session.plugins.plugin_db.GetActivePlugin(key)
        plugin_cls = meta.plugin_cls

        # The identity renderer will contain all the rendered rows.
        renderer = identity_renderer.IdentityRenderer()
        self._cached_plugin_renderers[key] = renderer

        if issubclass(plugin_cls, plugin.TypedProfileCommand):
            # We have access to table_header and rows without running render.
            renderer.table_header = plugin_cls.table_header

            plugin_curry = getattr(self.session.plugins, key)
            renderer.rows = list(plugin_curry().collect_as_dicts())
        else:
            # We have to run the plugin to get output.
            self.session.RunPlugin(key, format=renderer)

        return renderer

    def resolve(self, key):
        return self.select(key)

    @classmethod
    def getkeys(cls):
        """Return available plugins, globals and entity types."""
        return (frozenset(plugin.Command.classes.iterkeys()) |
                frozenset(plugin.Command.classes_by_name.iterkeys()))

    def reflect(self, name):
        """Which active plugin does the name refer to?"""
        plugin_curry = getattr(self.session.plugins, name, None)
        if not plugin_curry:
            return None

        return plugin_curry()

    # Plugin methods:

    def render(self, renderer):
        raise NotImplementedError()


class Search(EfilterPlugin):
    """EXPERIMENTAL: Searches and recombines output of other plugins.

    Search allows you to use the EFILTER search engine to filter, transform
    and combine output of most Rekall plugins. The most common use for this
    is running IOCs.

    This feature is EXPERIMENTAL and the filtering language, as well as the
    capabilities of this plugin are subject to frequent change.

    Some examples that work right now:
    ==================================

    # Find the process with pid 1:
    search("select * pslist where proc.pid == 1")

    # Sort lsof output by file descriptor:
    search("sort(lsof, fd)") # or:
    search("select * from lsof order by fd)")

    # Filter and sort through lsof in one step:
    search("select * from lsof where proc.pid == 1 order by fd)

    # Is there any proc with PID 1, that has a TCPv6 connection and isn't a
    # dead process?
    search("(any lsof where (proc.pid == 1 and fileproc.human_type == 'TCPv6'))
             and not (any dead_procs where (proc.pid == 1))")

    # Note: "ANY" is just a short hand for "SELECT ANY FROM" which does what
    # it sounds like, and returns True or False depending on whether the
    # query has any results.
    """

    name = "search"

    @classmethod
    def args(cls, parser):
        super(Search, cls).args(parser)
        parser.add_argument(
            "silent",
            default=False,
            help="Queries should fail silently.")

    def __init__(self, *args, **kwargs):
        self.silent = kwargs.pop("silent", None)
        super(Search, self).__init__(*args, **kwargs)

    def collect(self):
        try:
            result = solve.solve(self.query, self)
            return repeated.getvalues(result.value)
        except errors.EfilterError:
            if self.silent:
                return None

            raise

    @property
    def first_result(self):
        try:
            for result in self.collect():
                return result
        except (TypeError, ValueError):
            return None

    def _render_plugin_output(self, renderer, table_header, *rows):
        try:
            columns = [column["cname"] for column in table_header]
        except KeyError:
            raise ValueError(
                "Column spec %r is missing a cname. Full header was: %r." %
                (column, table_header))

        for row in rows:
            renderer.table_row(*[row[key] for key in columns])

    def _render_dicts(self, renderer, *rows):
        for row in rows:
            renderer.table_row(*row.itervalues())

    def _render_whatever_i_guess(self, renderer, *rows):
        for row in rows:
            renderer.table_row(row)

    def render(self, renderer):
        # Figure out what the header should look like.
        # Can we infer the type?
        try:
            t = infer_type.infer_type(self.query, self)
        except Exception:
            t = None

        rows = self.collect() or []

        # If we know the header, great!
        if isinstance(t, plugin.TypedProfileCommand):
            renderer.table_header(t.table_header)
            return self._render_plugin_output(renderer, t.table_header,
                                              *rows)

        # Maybe we cached the header when we ran the plugin?
        if isinstance(t, plugin.Command):
            header = self._cached_plugin_renderers.get(t.name)
            if header:
                renderer.table_header(header.columns)
                return self._render_plugin_output(renderer,
                                                  header.columns, *rows)

        # Try to guess the header based on structure of the first row.
        if not rows:
            renderer.table_header([("No Results", "no_results", "20")])
            return

        rows = iter(rows)
        first_row = next(rows)
        if isinstance(first_row, dict):
            renderer.table_header(
                [dict(name=k, cname=k) for k in first_row.iterkeys()])

            return self._render_dicts(renderer, first_row, *rows)

        # Sigh. Give up, and render whatever you got, I guess.
        renderer.table_header([dict(name="Result", cname="result")])
        return self._render_whatever_i_guess(renderer, first_row, *rows)


class Explain(EfilterPlugin):
    """Prints various information about a query.

    Explains how a query was parsed and how it will be interpreted. It also
    runs a full type inferencer, to attempt to determine the output of the
    query once it's executed.
    """
    name = "explain"

    def recurse_expr(self, expr, depth):
        yield expr, depth

        if not isinstance(expr, ast.Expression):
            return

        for child in expr.children:
            for expr_, depth in self.recurse_expr(child, depth + 1):
                yield expr_, depth

    def _render_node(self, node, renderer, depth=1):
        t = infer_type.infer_type(node, self)

        try:
            name = "(%s) <%s>" % (t.__name__, type(node).__name__)
        except AttributeError:
            name = "(%r) <%s>" % (t, type(node).__name__)

        renderer.table_row(
            name,
            utils.AttributedString(
                str(self.query),
                [dict(start=node.start, end=node.end, fg="RED", bold=True)]
            ),
            depth=depth
        )

        for child in node.children:
            if isinstance(child, ast.Expression):
                self._render_node(node=child, renderer=renderer,
                                  depth=depth + 1)
            else:
                renderer.table_row(
                    "(%s) <leaf: %r>" % (type(child).__name__, child),
                    None,
                    depth=depth + 1
                )

    def render(self, renderer):
        self.render_query(renderer)
        self.render_output(renderer)

    def render_output(self, renderer):
        renderer.section("Expected Output", width=140)

    def render_query(self, renderer):
        renderer.section("Query Analysis", width=140)
        renderer.table_header([
            dict(name="Expression", cname="expression", type="TreeNode",
                 max_depth=15, width=40),
            dict(name="Subquery", cname="query", width=100, nowrap=True),
        ])

        self._render_node(self.query.root, renderer)


# Implement the repeated field interface for IdentityRenderer, so we can just
# pass it to EFILTER as the value of a plugin.
repeated.IRepeated.implement(
    for_type=identity_renderer.IdentityRenderer,
    implementations={
        repeated.getvalues: lambda r: r.rows,
        repeated.value_type: lambda _: dict,
        repeated.value_eq: lambda _, __: False,
        repeated.value_apply: lambda r, f: [f(x) for x in r.rows]
    }
)


# Implement IAssociative for Structs because why not.
associative.IAssociative.implement(
    for_types=(obj.Struct, obj.Pointer),
    implementations={
        associative.select: getattr,
        associative.resolve: getattr
    }
)


# What this implementation SHOULD do is run the plugin, select the column from
# each row and then return a repeated value. However, that'll be implemented
# once we've converted most plugins to typed plugins. Right now, this never
# actually gets called and exists mainly to get infer_type to shut up about
# Command not implementing IAssociative.
associative.IAssociative.implement(
    for_type=plugin.Command,
    implementations={
        associative.select: lambda x, idx: list(x)[idx],
        associative.resolve: lambda x, idx: list(x)[idx]
    }
)


# By default, plugins have no idea what they return.
reflective.IReflective.implement(
    for_type=plugin.Command,
    implementations={
        reflective.reflect: lambda _, __: protocol.AnyType,
        reflective.getkeys: lambda _: ()
    }
)


# Typed plugins, however, do have some idea, and even provide a reflect
# method.
reflective.IReflective.implicit_dynamic(plugin.TypedProfileCommand)


# Tell EFILTER that the search plugin implements the INameDelegate protocol
# and can be queried for type information of plugins.
reflective.IReflective.implicit_static(EfilterPlugin)
associative.IAssociative.implicit_static(EfilterPlugin)
