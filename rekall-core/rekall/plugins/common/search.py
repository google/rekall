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

import itertools

from efilter import ast
from efilter import errors
from efilter import protocol
from efilter import query as q

from efilter.ext import row_tuple

from efilter.transforms import asdottysql
from efilter.transforms import solve
from efilter.transforms import infer_type

from efilter.protocols import applicative
from efilter.protocols import associative
from efilter.protocols import repeated
from efilter.protocols import structured

from rekall import obj
from rekall import plugin
from rekall import testlib
from rekall import utils

from rekall.ui import identity as identity_renderer


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
        query="select * from pslist() where (proc.pid == 1)"
    )


class TestSearch(testlib.SimpleTestCase):
    PLUGIN = "search"
    PARAMETERS = dict(
        commandline="search %(query)r",
        query="select * from pslist() where (proc.pid == 1)"
    )


class TestLookup(testlib.SimpleTestCase):
    PLUGIN = "lookup"
    PARAMETERS = dict(
        commandline="lookup %(constant)r %(type_name)r",
        constant="_PE_state",
        type_name="PE_state"
    )


class FindPlugins(plugin.TypedProfileCommand, plugin.ProfileCommand):
    """Find which plugin(s) are available to produce the desired output."""

    name = "which_plugin"

    type_name = None
    producers_only = False

    __args = [
        dict(name="type_name", required=True, positional=True,
             help="The name of the type we're looking for. "
             "E.g.: 'proc' will find psxview, pslist, etc."),

        dict(name="producers_only", required=False, type="Boolean",
             help="Only include producers: plugins that output "
             "only this struct and have no side effects.")
    ]

    def collect(self):
        if self.plugin_args.producers_only:
            pertinent_cls = plugin.Producer
        else:
            pertinent_cls = plugin.TypedProfileCommand

        for plugin_cls in plugin.Command.classes.itervalues():
            if not plugin_cls.is_active(self.session):
                continue

            if not issubclass(plugin_cls, pertinent_cls):
                continue

            table_header = plugin_cls.table_header
            if table_header:
                if isinstance(table_header, list):
                    table_header = plugin.PluginHeader(*table_header)

                try:
                    for t in table_header.types_in_output:
                        if (isinstance(t, type) and
                                self.plugin_args.type_name == t.__name__):
                            yield plugin_cls(session=self.session)
                        elif self.plugin_args.type_name == t:
                            yield plugin_cls(session=self.session)
                except plugin.Error:
                    # We were unable to instantiate this plugin to figure out
                    # what it wants to emit. We did our best so move on.
                    continue

    def render(self, renderer):
        renderer.table_header([
            dict(name="Plugin", cname="plugin", type="Plugin", style="compact",
                 width=30)
        ])

        for command in self.collect():
            renderer.table_row(command)


class Collect(plugin.TypedProfileCommand, plugin.ProfileCommand):
    """Collect instances of struct of type 'type_name'.

    This plugin will find all other plugins that produce 'type_name' and merge
    all their output. For example, running collect 'proc' will give you a
    rudimentary psxview.

    This plugin is mostly used by other plugins, like netstat and psxview.
    """

    name = "collect"

    type_name = None

    __args = [
        dict(name="type_name", required=True, positional=True,
             help="The type (struct) to collect.")
    ]

    @classmethod
    def GetPrototype(cls, session):
        """Instantiate with suitable default arguments."""
        return cls(None, session=session)

    def collect(self):
        which = self.session.plugins.which_plugin(
            type_name=self.plugin_args.type_name,
            producers_only=True)

        results = {}
        for producer in which.collect():
            # We know the producer plugin implements 'produce' because
            # 'which_plugin' guarantees it.
            self.session.logging.debug("Producing %s from producer %r",
                                       self.type_name, producer)
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
            dict(name=self.plugin_args.type_name,
                 cname=self.plugin_args.type_name,
                 type=self.plugin_args.type_name),
            dict(name="Producers", cname="producers")
        ])

        for result in self.collect():
            renderer.table_row(result, result.obj_producers)


class Lookup(plugin.TypedProfileCommand, plugin.ProfileCommand):
    """Lookup a global in the profile.

    This plugin lets the user ask for a specific global constant in the
    active profile.
    """

    name = "lookup"

    __args = [
        dict(name="constant", required=True, positional=True,
             help="The constant to look up in the profile."),
        dict(name="target", positional=True, default=None,
             help="The type of the constant."),
        dict(name="target_args", positional=True, default=None,
             help="The target args"),
    ]

    def collect(self):
        yield [self.session.address_resolver.get_constant_object(
            self.plugin_args.constant,
            target=self.plugin_args.target,
            target_args=self.plugin_args.target_args)]

    def render(self, renderer):
        renderer.table_header([
            dict(name=self.plugin_args.constant, cname="result",
                 type=self.plugin_args.target)
        ])

        for row in self.collect():
            renderer.table_row(*row)


class CommandWrapper(object):
    """Wraps a plugin and its output for the purpose of EFILTER searches.

    This is a helper class for the Search plugin. It lets us pretend that
    plugins are functions to be called from inside EFILTER queries, and also
    takes care of running the plugin and saving its output and headers.

    Members:
        plugin_cls: The type of the Command subclass.
        rows: Output of rendering the plugin.
        columns: How 'rows' are structured.
        table_header: If Command is a subclass of TypedProfileCommand then this
            will contain its table header once applied.
    """
    plugin_cls = None
    plugin_obj = None

    rows = None
    columns = None

    session = None

    # Once the CommandWrapper is run, this will be set to the arguments that
    # were used. You cannot apply the same CommandWrapper twice with different
    # args. If you need to do that, create two instances of CommandWrapper.
    _applied_args = None

    def __init__(self, plugin_cls, session):
        self.plugin_cls = plugin_cls
        self.session = session

    def __repr__(self):
        return "<CommandWrapper: %r>" % (self.plugin_cls.__name__)

    # IApplicative

    def apply(self, args, kwargs):
        """Instantiate the plugin with given args and run it.

        This caches the output of the plugin. Subsequently, table_header,
        rows and columns will be populated.

        The CommmandWrapper must not be applied twice with different
        arguments - each instance represents a unique application.

        Arguments:
            args, kwargs: Arguments to the plugin.
        """
        if self._applied_args is not None:
            # Called before. Return what we cached.
            if self._applied_args != (args, kwargs):
                raise ValueError(
                    "%r was previously called with %r but is now being called"
                    " with %r. This should never happen."
                    % (self, self._applied_args, (args, kwargs)))

            return self.rows

        self._applied_args = (args, kwargs)

        # First time - instantiate the plugin with arguments.
        plugin_curry = getattr(self.session.plugins, self.plugin_cls.name)
        self.plugin_obj = plugin_curry(session=self.session,
                                       *args, **kwargs)

        output_header = getattr(self.plugin_cls, "table_header", None)
        collector = getattr(self.plugin_obj, "collect_as_dicts", None)

        if callable(collector) and output_header is not None:
            # The plugin supports the collect API and declares its output ahead
            # of time. This is the ideal case.
            self.columns = output_header
            self.rows = repeated.lazy(collector)
        else:
            # We don't know enough about the plugin to do the easy thing. We
            # need to create a shim renderer that will cache the plugin output
            # and then use that.
            renderer = identity_renderer.IdentityRenderer(session=self.session)
            with renderer.start():
                self.session.RunPlugin(self.plugin_cls.name, format=renderer,
                                       *args, **kwargs)

            # The identity renderer will now contain the plugin output and
            # columns.
            self.columns = renderer.columns
            self.rows = repeated.repeated(*list(renderer.rows))

        return self.rows

    def reflect_runtime_return(self):
        """Return the return type* of this CommandWrapper.

        This actually returns a dummy instance (prototype) of the plugin this
        CommandWrapper wraps. EFILTER allows use of stand-in objects for type
        inference. We make heavy use of prototypes to represent Rekall's
        profile-dependent type system.
        """
        # Does this plugin implement the reflection helper?
        try:
            return self.plugin_cls.GetPrototype(session=self.session)
        except NotImplementedError:
            # GetPrototype is not overriden and the default implementation
            # didn't work.
            return None


# Implementing the IApplicative protocol will let EFILTER call the
# CommandWrapper as though it were a function.
applicative.IApplicative.implicit_static(CommandWrapper)


class EfilterPlugin(plugin.TypedProfileCommand, plugin.Command):
    """Abstract base class for plugins that do something with queries.

    Provides implementations of the basic EFILTER protocols for selecting and
    inspecting the output of plugins. Search and Explain extend this.
    """
    __abstract = True

    query = None  # The Query instance we're working with.
    query_source = None  # The source of the query, passed by the user.
    query_error = None  # An exception, if any, caused when parsing the query.

    # We cache CommandWrapper instances because they end up containing header
    # information for untyped plugins.
    _cached_command_wrappers = None

    # Plugin lifecycle:

    __args = [
        dict(name="query", required=True, positional=True,
             help="The dotty/EFILTER query to run."),

        dict(name="query_parameters", type="ArrayString",
             help="Positional parameters for parametrized queries."),
    ]

    def __init__(self, *args, **kwargs):
        super(EfilterPlugin, self).__init__(*args, **kwargs)

        try:
            self.query = q.Query(self.plugin_args.query,
                                 params=self.plugin_args.query_parameters)
        except errors.EfilterError as error:
            self.query_error = error
            self.query = None
        except Exception:
            # I am using a broad except here to make sure we always display a
            # friendly error message. EFILTER will usually raise a friendly
            # error, but we might get a non-EfilterError exception if the user
            # gets creative (e.g. passing a custom object as query, instead of a
            # string).
            raise ValueError("Could not parse your query %r." % (
                self.plugin_args.query,))

        self._cached_command_wrappers = dict()

    # IStructured implementation for EFILTER:

    def resolve(self, name):
        """Find and return a CommandWrapper for the plugin 'name'."""
        meta = self.session.plugins.plugin_db.GetActivePlugin(name)
        if meta != None:
            wrapper = CommandWrapper(meta.plugin_cls, self.session)

            # We build the cache but don't retrieve wrappers from it. We need to
            # build a new wrapper every time a plugin is resolved from the query
            # because plugins are functions and might be called with different
            # args every time.
            self._cached_command_wrappers[name] = wrapper

            return wrapper

        raise KeyError("No plugin named %r." % name)

    def getmembers_runtime(self):
        """Get all available plugins."""
        return frozenset(
            [c.name for c in plugin.Command.GetActiveClasses(self.session)])

    def reflect_runtime_member(self, name):
        """Find the type* of 'name', which is a plugin.

        * This returns a CommandWrapper which allows plugins to be called from
        EFILTER queries as functions. EFILTER allows the use of stand-in objects
        as proxies for actual types, so we make heavy use of plugin and struct
        prototypes to represent Rekall's profile-dependent type system.
        """
        cls = self.session.plugins.plugin_db.GetActivePlugin(name).plugin_cls
        return CommandWrapper(cls, self.session)

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

    __args = [
        dict(name="silent", default=False, type="Boolean",
             help="Queries should fail silently."),
    ]

    def collect(self):
        """Return the search results without displaying them.

        Returns:
            A list of results from the query solver.

        Raises:
            EfilterError unless 'silent' flag was set.
        """
        try:
            result = self.solve()
            return repeated.getvalues(result)
        except errors.EfilterError:
            if self.plugin_args.silent:
                return None

            raise

    def solve(self):
        """Return the search results exactly as EFILTER returns them.

        Returns:
            Depends on the query.

        Raises:
            EfilterError if anything goes wrong.
        """
        return solve.solve(self.query, self).value

    @utils.safe_property
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

    def _render_plugin_output(self, renderer, table_header, rows):
        """Used to render search results if they come from a plugin."""
        columns = []
        for column in table_header or []:
            column_name = column.get("cname") or column.get("name")
            columns.append(column_name)

            if column_name is None:
                raise ValueError(
                    "Column spec %r is missing a cname. Full header was: %r." %
                    (column, table_header))

        try:
            for row in rows:
                renderer.table_row(*[row[key] for key in columns])
        except errors.EfilterError as error:
            # Because 'rows' could be a lazy iterator it's possible that an
            # exception will get raised while output is already being rendered.
            self.query_error = error
            return self.render_error(renderer)

    def _render_dicts(self, renderer, rows):
        """Used to render search results if they are basic dicts."""
        try:
            for row in rows:
                renderer.table_row(*row.itervalues())
        except errors.EfilterError as error:
            self.query_error = error
            return self.render_error(renderer)

    def _render_whatever_i_guess(self, renderer, rows):
        """Used to render search results if we don't know WTF they are."""
        try:
            for row in rows:
                if isinstance(row, CommandWrapper):
                    raise ValueError(
                        "%(plugin)r is a Rekall plugin and must be called as a"
                        " function. Try '%(name)s()'' instead of '%(name)s'."
                        % dict(plugin=row.plugin_cls, name=row.plugin_cls.name))
                renderer.table_row(row)
        except errors.EfilterError as error:
            self.query_error = error
            return self.render_error(renderer)

    def _find_matching_header(self, keys):
        sorted_keys = sorted(keys)
        for cached_wrapper in self._cached_command_wrappers.itervalues():
            if not cached_wrapper.columns:
                continue

            column_names = [c.get("cname", c.get("name"))
                            for c in cached_wrapper.columns]
            if sorted(column_names) == sorted_keys:
                return cached_wrapper.columns

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

        if isinstance(t, CommandWrapper):
            raise RuntimeError(
                "%r is a plugin and must be called as a function. Try '%s()'"
                " instead of '%s'"
                % (t.plugin_cls, t.plugin_cls.name, t.plugin_cls.name))

        # Get the data we're rendering.
        try:
            rows = self.collect() or []
        except errors.EfilterError as error:
            self.query_error = error
            return self.render_error(renderer)

        # If the query returns the output of a plugin then we have to render
        # the same columns as the plugin. If the plugin declares its columns
        # then that's easy. Otherwise we have to try and get the columns from
        # cache.
        if isinstance(t, plugin.Command):
            output_header = getattr(t, "table_header", None)

            if output_header is None:
                cached_wrapper = self._cached_command_wrappers.get(t.name)
                if not cached_wrapper:
                    raise RuntimeError(
                        "EFILTER query %r seems to return the output of the "
                        "Rekall plugin named %r, but no such plugin was "
                        "executed during evaluation. This should not happen."
                        % (self.query, t.name))

                output_header = cached_wrapper.columns

            renderer.table_header(output_header)
            return self._render_plugin_output(renderer, output_header, rows)

        # In the past, if there were no results, the renderer would output
        # a special column to indicate status. That provided a strong cue to the
        # interactive user that there were no results but confused tools that
        # process Rekall output automatically. If there are no rows in the
        # output and we don't know the output header then we return right away.
        # To provide a visual cue we use unstructured output.
        remaining_rows = iter(rows)
        try:
            first_row = next(remaining_rows)
        except StopIteration:
            renderer.format("No results.")
            return

        all_rows = itertools.chain((first_row,), remaining_rows)

        # If we have some output but don't know what it is we can try to use
        # dict keys as columns.
        if isinstance(first_row, dict):
            # Maybe we have a plugin with matching columns in its output?
            columns = self._find_matching_header(first_row.keys())
            if columns:
                renderer.table_header(columns)
                return self._render_plugin_output(renderer, columns, all_rows)

            renderer.table_header(
                [dict(name=unicode(k), cname=unicode(k))
                 for k in first_row.iterkeys()])

            return self._render_dicts(renderer, all_rows)

        elif isinstance(first_row, row_tuple.RowTuple):
            columns = [dict(name=x)
                       for x in first_row.getmembers_runtime()]
            renderer.table_header(columns, auto_widths=True)
            return self._render_plugin_output(renderer, columns, all_rows)

        # Sigh. Give up, and render whatever you got, I guess.
        renderer.table_header([dict(name="Result", cname="result")])
        return self._render_whatever_i_guess(renderer, all_rows)


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
        except (NotImplementedError, TypeError, AttributeError):
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
# The 'resolve' function will never actually be called on TypeProfileCommand,
# because we treat plugins as tables, not rows. 'resolve' will instead be
# passed the rowdicts.
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
# As with IStructured, the 'select' function doesn't get called on the
# plugin itself, which is why we don't provide a real implementation.
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


# This lets us do some_array.some_member. Useful for accessing properties.
structured.IStructured.implement(
    for_type=obj.Array,
    implementations={
        structured.resolve: getattr
    }
)


def select_Pointer(ptr, key):
    """Delegate to target of the pointer, if any."""
    target_obj = ptr.deref()
    if not target_obj:
        ptr.session.logging.warn(
            "Attempting to access key %r of a void pointer %r.", key, ptr)
    if target_obj:
        return associative.select(target_obj, key)


# Pointer[key] is implemented as Pointer.dereference()[key].
associative.IAssociative.implement(
    for_type=obj.Pointer,
    implementations={
        associative.select: select_Pointer
    }
)


def resolve_Pointer(ptr, member):
    """Delegate to target of the pointer, if any."""
    target_obj = ptr.deref()
    if not target_obj:
        ptr.session.logging.warn(
            "Attempting to access member %r of a void pointer %r.", member, ptr)
    if target_obj:
        return structured.resolve(target_obj, member)


# Pointer.member is implemented as Pointer.dereference().member.
structured.IStructured.implement(
    for_type=obj.Pointer,
    implementations={
        structured.resolve: resolve_Pointer
    }
)
