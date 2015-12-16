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

from efilter.transforms import asdottysql
from efilter.transforms import solve
from efilter.transforms import infer_type

from efilter.protocols import applicative
from efilter.protocols import associative
from efilter.protocols import repeated
from efilter.protocols import structured


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
    """Find which plugin(s) are available to produce the desired output."""

    name = "which_plugin"

    type_name = None
    producers_only = False

    @classmethod
    def args(cls, parser):
        super(FindPlugins, cls).args(parser)
        parser.add_argument("type_name", required=True,
                            help="The name of the type we're looking for. "
                                 "E.g.: 'proc' will find psxview, pslist, etc.")
        parser.add_argument("producers_only", required=False, default=False,
                            help="Only include producers: plugins that output "
                                 "only this struct and have no side effects.")

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
    """Collect instances of struct of type 'type_name'.

    This plugin will find all other plugins that produce 'type_name' and merge
    all their output. For example, running collect 'proc' will give you a 
    rudimentary psxview.

    This plugin is mostly used by other plugins, like netstat and psxview.
    """

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


class CommandWrapper(object):
    """Wraps a plugin and its output for the purpose of EFILTER searches.

    This is a helper class for the Search plugin. It lets us pretend that
    plugins are functions to be called from inside EFILTER queries, and also
    takes care of running the plugin and saving its output and headers.
    """
    plugin_cls = None
    rows = None
    table_header = None
    session = None

    def __init__(self, plugin_cls, session):
        self.plugin_cls = plugin_cls
        self.session = session

    # IApplicative

    def apply(self, args, kwargs):
        """Instantiate the plugin with given args and run it.

        Note: Apply will only run once per instance - once we have rows it will
        not rerun, even if the arguments change!

        Arguments:
            args, kwargs: Arguments to the plugin.
        """
        if self.rows:
            # We've already applied.
            return self

        if issubclass(self.plugin_cls, plugin.TypedProfileCommand):
            # We have access to table header and rows without running render.
            self.table_header = self.plugin_cls.table_header
            plugin_curry = getattr(self.session.plugins, self.plugin_cls.name)
            command = plugin_curry(session=self.session, *args, **kwargs)
            self.rows = list(command.collect_as_dicts())
        else:
            # We do not have a table header declaration, so we need to run
            # the plugin and use an identity renderer to capture its output
            # and headers.

            # The identity renderer will capture rendered rows.
            renderer = identity_renderer.IdentityRenderer()

            self.session.RunPlugin(self.plugin_cls.name, format=renderer,
                                   *args, **kwargs)

            self.rows = renderer.rows
            self.columns = renderer.columns

        return self

    # IRepeated

    def getvalues(self):
        """Pretend the plugin is an IRepeated instead of a function."""
        # Make sure we have data.
        self.apply((), {})

        return self.rows

    def value_eq(self, other):
        """This is required by the IRepeated protocol, but not actually used."""
        return self.getvalues() == repeated.getvalues(other)

    def value_apply(self, f):
        """This is required by the IRepeated protocol, but not actually used."""
        return repeated.meld(*[f(r) for r in self.rows])

    def value_type(self):
        """This is required by the IRepeated protocol, but not actually used."""
        return self.plugin_cls

    # IStructured

    def resolve(self, name):
        """Pretend the plugin is an IStructured instead of a function.
        
        This lets us pretend that the plugin is a structured datatype (like an
        object) making it possible for the user to get data without calling
        it as a function. The first time the plugin is asked for any data
        we just run 'apply' with no arguments to populate 'rows'.
        """
        # Make sure we have data.
        self.apply((), {})

        return repeated.meld(*[r[name] for r in self.rows])


# Implement the relevant EFILTER protocols using methods already on the
# CommandWrapper class.
structured.IStructured.implicit_static(CommandWrapper)
repeated.IRepeated.implicit_static(CommandWrapper)
applicative.IApplicative.implicit_static(CommandWrapper)


class EfilterPlugin(plugin.ProfileCommand):
    """Abstract base class for plugins that do something with queries.

    Provides implementations of the basic EFILTER protocols for selecting and
    inspecting the output of plugins. Search and Explain extend this.
    """
    __abstract = True

    query = None  # The Query instance we're working with.
    query_source = None  # The source of the query, passed by the user.
    query_error = None  # An exception, if any, caused when parsing the query.

    # We cache plugin wrappers here, keyed on plugin class. Each renderer
    # is populated with rows and the table header for future reference.
    _cached_plugin_wrappers = {}  # Instances of CommandWrapper.

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
        self.query_source = query

        try:
            self.query = q.Query(query, params=query_parameters)
        except errors.EfilterError as error:
            self.query_error = error
            self.query = None

        self.query_parameters = query_parameters

    # IStructured implementation for EFILTER:

    def resolve(self, name):
        """Find and return a CommandWrapper for the plugin 'name'."""
        if name in self.getmembers_runtime():
            return self._build_plugin_wrapper(name)

        raise KeyError("No plugin named %r." % name)

    def _build_plugin_wrapper(self, name):
        """Get a wrapper around the plugin called 'name'.

        Arguments:
            name: Plugin name to find.

        Returns:
            Instance of CommandWrapper.
        """
        meta = self.session.plugins.plugin_db.GetActivePlugin(name)
        wrapper = CommandWrapper(meta.plugin_cls, self.session)
        self._cached_plugin_wrappers[name] = wrapper

        return wrapper

    def getmembers_runtime(self):
        """Get all available plugins."""
        return frozenset(
            [c.name for c in plugin.Command.GetActiveClasses(self.session)])

    def reflect_runtime_member(self, name):
        """Find the type* of 'name', which is a plugin.
        
        * This returns the plugin instance, not its class, because the entire
        reflection API requires information only available to Rekall at runtime.
        """
        return self.session.plugins.plugin_db.GetActivePlugin(name).plugin_cls(
            session=self.session)

    # Plugin methods:

    def render_error(self, renderer):
        """Render the query parsing error in a user-friendly manner."""
        renderer.section("Query Error")

        try:
            start = self.query_error.adjusted_start
            end = self.query_error.adjusted_end
            source = self.query_error.source
            text = self.query_error.text
        except AttributeError:
            # Maybe query_error isn't a subclass of EfilterError. Let's be
            # careful.
            start = None
            end = None
            source = self.query_source
            text = str(self.query_error)

        if start is not None and end is not None:
            renderer.format(
                "EFILTER error ({}) {} at position {}-{} in query:\n{}\n\n",
                type(self.query_error).__name__, repr(text), start, end,
                utils.AttributedString(
                    source,
                    [dict(start=start, end=end, fg="RED", bold=True)]))
        else:
            renderer.format(
                "EFILTER error ({}) {} in query:\n{}\n",
                type(self.query_error).__name__, repr(text), source)

    def render(self, renderer):
        raise NotImplementedError()


structured.IStructured.implicit_dynamic(EfilterPlugin)


class Search(EfilterPlugin):
    """Searches and recombines output of other plugins.

    Search allows you to use the EFILTER search engine to filter, transform
    and combine output of most Rekall plugins. The most common use for this
    is running IOCs.

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
        """Return the search results without displaying them."""
        try:
            result = solve.solve(self.query, self)
            return repeated.getvalues(result.value)
        except errors.EfilterError:
            if self.silent:
                return None

            raise

    @property
    def first_result(self):
        """Get only the first search result.
        
        This is useful when we need to find a concrete structure for some other
        purpose, such as finding a concrete allocator zone when writing a
        'dump_zone' plugin.
        """
        try:
            for result in self.collect():
                return result
        except (TypeError, ValueError):
            return None

    def _render_plugin_output(self, renderer, table_header, *rows):
        """Used to render search results if they come from a plugin."""
        try:
            columns = [column["cname"] for column in table_header]
        except KeyError:
            raise ValueError(
                "Column spec %r is missing a cname. Full header was: %r." %
                (column, table_header))

        for row in rows:
            renderer.table_row(*[row[key] for key in columns])

    def _render_dicts(self, renderer, *rows):
        """Used to render search results if they are basic dicts."""
        for row in rows:
            renderer.table_row(*row.itervalues())

    def _render_whatever_i_guess(self, renderer, *rows):
        """Used to render search results if we don't know WTF they are."""
        for row in rows:
            renderer.table_row(row)

    def render(self, renderer):
        # Do we have a query?
        if not self.query:
            return self.render_error(renderer)

        # Figure out what the header should look like.
        # Can we infer the type?
        try:
            t = infer_type.infer_type(self.query, self)
        except Exception:
            t = None

        # Get the data we're rendering.
        try:
            rows = self.collect() or []
        except errors.EfilterError as error:
            self.query_error = error
            return self.render_error(renderer)

        # If we know the header, great!
        if isinstance(t, plugin.TypedProfileCommand):
            renderer.table_header(t.table_header)
            return self._render_plugin_output(renderer, t.table_header,
                                              *rows)

        # Maybe we cached the header when we ran the plugin?
        if isinstance(t, plugin.Command):
            wrapper = self._cached_plugin_wrappers.get(t.name)
            if wrapper:
                renderer.table_header(wrapper.columns)
                return self._render_plugin_output(renderer,
                                                  wrapper.columns,
                                                  *rows)

        # Try to guess the header based on structure of the first row.
        if not rows:
            renderer.table_header([("No Results", "no_results", "20")])
            return

        rows = iter(rows)
        first_row = next(rows)
        if isinstance(first_row, dict):
            renderer.table_header(
                [dict(name=unicode(k), cname=unicode(k))
                 for k in first_row.iterkeys()])

            return self._render_dicts(renderer, first_row, *rows)

        # Sigh. Give up, and render whatever you got, I guess.
        renderer.table_header([dict(name="Result", cname="result")])
        return self._render_whatever_i_guess(renderer, first_row, *rows)


class Explain(EfilterPlugin):
    """Prints various information about a query.

    Explains how a query was parsed and how it will be interpreted. It also
    runs a full type inferencer, to attempt to determine the output of the
    query once it's executed.
    
    The Explain plugin can analyse a strict superset of expressions that
    are valid in the Search plugin. It supports:
    
     - Any search query that can be passed to Search.
     - Expressions asking about types and members of profile types
       (like structs).
    """

    name = "explain"
    
    # As long as this is True, the input is a valid search query and will be
    # analysed in the output. This may become False if we realize the input
    # is not a valid search query, but instead asking about something like the
    # structure of a native type.
    input_is_regular_query = True

    def reflect_runtime_member(self, name):
        """Reflect what Search reflects, and also struct types."""
        result = super(Explain, self).reflect_runtime_member(name)

        if not result or result == protocol.AnyType:
            result = self.session.profile.GetPrototype(name)
            if result and result != protocol.AnyType:
                # We found something that makes this not a query (aka a struct).
                self.input_is_regular_query = False

        return result

    def getmembers_runtime(self):
        """Reflect what Search reflects, and also struct types."""
        result = super(Explain, self).getmembers_runtime()

        return set(result) | set(self.session.profile.vtypes.iterkeys())

    def recurse_expr(self, expr, depth):
        yield expr, depth

        if not isinstance(expr, ast.Expression):
            return

        for child in expr.children:
            for expr_, depth in self.recurse_expr(child, depth + 1):
                yield expr_, depth

    def _render_node(self, query, node, renderer, depth=1):
        """Render an AST node and recurse."""
        t = infer_type.infer_type(node, self)

        try:
            name = "(%s) <%s>" % (t.__name__, type(node).__name__)
        except AttributeError:
            name = "(%r) <%s>" % (t, type(node).__name__)

        renderer.table_row(
            name,
            utils.AttributedString(
                str(query),
                [dict(start=node.start, end=node.end, fg="RED", bold=True)]
            ),
            depth=depth
        )

        for child in node.children:
            if isinstance(child, ast.Expression):
                self._render_node(node=child, renderer=renderer, query=query,
                                  depth=depth + 1)
            else:
                renderer.table_row(
                    "(%s) <leaf: %r>" % (type(child).__name__, child),
                    None,
                    depth=depth + 1
                )

    def render(self, renderer):
        # Do we have a query?
        if not self.query:
            return self.render_error(renderer)

        # render_output_analysis must run before render_query_analysis
        # because it decides whether the input is a regular query.
        self.render_output_analysis(renderer)
        self.render_query_analysis(renderer)

    def render_output_analysis(self, renderer):
        """Render analysis of the expression's return type and its members."""
        output_type = infer_type.infer_type(self.query, self)

        renderer.section("Type Analysis", width=140)
        renderer.table_header([
            dict(name="Name", cname="name", type="TreeNode", max_depth=2,
                 width=60),
            dict(name="Type", cname="type", width=40)
        ])

        renderer.table_row(self.query.source,
                           repr(output_type),
                           depth=1)

        try:
            for member in structured.getmembers(output_type):
                subq = "(%s)[%r]" % (self.query.source, member)
                subtype = infer_type.infer_type(q.Query(subq), self)
                if isinstance(subtype, type):
                    subtype = subtype.__name__
                else:
                    subtype = repr(subtype)

                renderer.table_row(subq, subtype, depth=2)
        except (NotImplementedError, TypeError):
            pass

    def render_query_analysis(self, renderer):
        """Render query analysis if the input is a regular query.

        A non-regular query could be the user asking us to explain (e.g.) a
        struct.
        """
        if not self.input_is_regular_query:
            return

        original_query = self.query.source
        canonical_query = asdottysql.asdottysql(self.query)

        renderer.section("Query Analysis", width=140)
        self.render_query(renderer, self.query)

        if canonical_query != original_query:
            renderer.section("Query Analysis (Using canonical syntax)",
                             width=140)
            self.render_query(renderer, q.Query(canonical_query))

    def render_query(self, renderer, query):
        """Render a single query object's analysis."""
        renderer.table_header([
            dict(name="(Return Type) Expression", cname="expression",
                 type="TreeNode", max_depth=15, width=40),
            dict(name="Subquery", cname="query", width=100, nowrap=True),
        ])

        self._render_node(query, query.root, renderer)


# Below we implement various EFILTER protocols for various Rekall types.


# Implement IApplicative for Command to get reflection APIs.
applicative.IApplicative.implement(
    for_type=plugin.Command,
    implementations={
        applicative.apply:
            lambda x, *args, **kwargs: x(*args, **kwargs).collect(),

        # Plugins "return" themselves, as far as the type inference cares.
        applicative.reflect_runtime_return: lambda command: command
    }
)


# TypedProfileCommands can reflect a lot about their output columns.
structured.IStructured.implement(
    for_type=plugin.TypedProfileCommand,
    implementations={
        structured.resolve: lambda _, __: None,  # This should not happen.
        structured.reflect_runtime_member:
            lambda c, name: c.get_column_type(name),
        structured.getmembers_runtime: lambda c: c.table_header.all_names
    }
)


# We support IAssociative (plugin[column]) using the same accessors as
# IStructured (plugin.column). We're easy-going like that.
associative.IAssociative.implement(
    for_type=plugin.TypedProfileCommand,
    implementations={
        associative.select: lambda _, __: None,  # This should not happen.
        associative.reflect_runtime_key:
            lambda c, name: c.get_column_type(name),
        associative.getkeys_runtime: lambda c: c.table_header.all_names
    }
)


# Implement IAssociative for Structs because why not. This lets us do
# struct[key] as well as struct.key.
associative.IAssociative.implement(
    for_type=obj.Struct,
    implementations={
        associative.select: getattr,
        associative.reflect_runtime_key: structured.reflect_runtime_member,
        associative.getkeys_runtime: structured.getmembers_runtime
    }
)


# This lets us do struct.member.
structured.IStructured.implement(
    for_type=obj.Struct,
    implementations={
        structured.resolve: getattr,
        structured.reflect_runtime_member:
            lambda s, m: type(getattr(s, m, None)),
        structured.getmembers_runtime:
            lambda s: set((name for name, _ in s.getproperties()))
    }
)


# This lets us get indices out of Arrays.
associative.IAssociative.implement(
    for_type=obj.Array,
    implementations={
        associative.select: lambda obj, key: obj[key],
    }
)


# This lets us do some_array.some_member.
structured.IStructured.implement(
    for_type=obj.Array,
    implementations={
        structured.resolve: getattr
    }
)


# Pointer[key] is implemented as Pointer.dereference()[key].
associative.IAssociative.implement(
    for_type=obj.Pointer,
    implementations={
        associative.select:
            lambda ptr, key: associative.select(ptr.deref(), key),
    }
)


# Pointer.member is implemented as Pointer.dereference().member.
structured.IStructured.implement(
    for_type=obj.Pointer,
    implementations={
        structured.resolve:
            lambda ptr, key: structured.resolve(ptr.deref(), key)
    }
)
