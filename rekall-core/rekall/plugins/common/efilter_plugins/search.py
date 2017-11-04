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

"""Rekall's search function.

Refer to the documentation:
http://blog.rekall-forensic.com/2016/07/searching-memory-with-rekall.html


And the test file:
https://github.com/rekall-innovations/rekall-test/blob/master/tigger/tests.config#L52
"""

from builtins import next
from builtins import str
from builtins import object
__author__ = "Adam Sindelar <adamsh@google.com>"
import collections
import itertools
import re
import six

from efilter import api
from efilter import ast
from efilter import errors
from efilter import protocol
from efilter import query as q

from efilter.ext import row_tuple

from efilter.transforms import asdottysql
from efilter.transforms import solve

from efilter.protocols import applicative
from efilter.protocols import associative
from efilter.protocols import eq
from efilter.protocols import number
from efilter.protocols import ordered
from efilter.protocols import repeated
from efilter.protocols import string
from efilter.protocols import structured

from rekall import config
from rekall import obj
from rekall import plugin
from rekall import testlib
from rekall.plugins.response import common
from rekall.plugins.overlays import basic
from rekall.plugins.common.efilter_plugins import helpers
from rekall.ui import identity as identity_renderer
from rekall_lib import utils

if six.PY3:
    long = int
    unicode = str


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

    table_header = [
            dict(name="field")
    ]

    def collect(self):
        yield dict(field=self.session.address_resolver.get_constant_object(
            self.plugin_args.constant,
            target=self.plugin_args.target,
            target_args=self.plugin_args.target_args))


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
        self.plugin_args = config.CommandMetadata(self.plugin_cls).Metadata()['arguments']

    def _get_arg_desc(self, name):
        for desc in self.plugin_args:
            if desc["name"] == name:
                return desc

        raise plugin.PluginError("Unknown arg %s for plugin %s" % (
            name, self.plugin_cls.name))

    def __repr__(self):
        return "<CommandWrapper: %r>" % (self.plugin_cls.__name__)

    # IApplicative

    def apply(self, args, kwargs):
        """Instantiate the plugin with given args and run it.

        This caches the output of the plugin. Subsequently, table_header,
        rows and columns will be populated.

        Note that if the args came from efilter itself (e.g. in a
        subquery) then they are always repeated. However if the arg is
        not repeating, we can not just pass it or the plugin might
        explode. We therefore run the plugin multiple times with each
        value of the subquery.

        Arguments:
            args, kwargs: Arguments to the plugin.

        """
        kwargs.pop("vars", None)

        # Materialized kwargs. This is needed because we might expand
        # into multiple plugins below and we might as well keep
        # repeated values between invocations. Note that being lazy
        # here does not buy anything because the args are already
        # expanded in the TypedProfileCommand's arg validation
        # routine.
        kwargs = self._materialize_repeated_kwarg(kwargs)

        # Expand repeating args into non repeating plugins.
        kwargs_groups = [kwargs]

        # Keep expanding until the kwargs_groups are stable.
        while 1:
            expanded_kw_groups = []
            for kwargs in kwargs_groups:
                expanded_kw_groups.extend(self._expand_kwargs(kwargs))

            if len(expanded_kw_groups) == len(kwargs_groups):
                kwargs_groups = expanded_kw_groups
                break

            kwargs_groups = expanded_kw_groups

        row_groups = [self._generate_rows(args, k) for k in kwargs_groups]
        return repeated.lazy(lambda: itertools.chain(*row_groups))

    def _expand_kwargs(self, kwargs):
        for name, value in six.iteritems(kwargs):
            arg_repeating = self._is_arg_repeating(name)
            value_repeating = repeated.isrepeating(value)

            # If the arg expects a singleton and the value is
            # repeating, then we run the plugin once per value.
            if not arg_repeating and value_repeating:
                result = []
                for value_item in value:
                    kwargs_copy = kwargs.copy()
                    kwargs_copy[name] = value_item
                    result.append(kwargs_copy)

                return result

        return [kwargs]

    def _materialize_repeated_kwarg(self, kwargs):
        """Materialize the result of the args.

        This is a shim between a repeated plugin arg and the efilter
        stream.  We handle the following cases.

        1. EFilter LazyRepetition with unstructured elements (e.g. dicts).

        2. EFilter LazyRepetition with structured elements. These are
           usually returned from a subselect. In the special case
           where the arg name is present in the structure

        """
        result = {}
        for k, v in six.iteritems(kwargs):
            if not repeated.isrepeating(v):
                result[k] = v
            else:
                expanded_value = []
                for item in v:
                    if structured.isstructured(item):
                        members = structured.getmembers(item)
                        if len(members) == 1 or k in members:
                            # A single column in the subquery - just
                            # use that as the arg value.  If the name
                            # emitted is the same as the expected arg
                            # name we also just take that one.
                            expanded_value.append(
                                structured.resolve(item, members[0]))
                            continue

                    expanded_value.append(item)

                result[k] = expanded_value

        return result

    def _is_arg_repeating(self, arg_name):
        return "Array" in self._get_arg_desc(arg_name).get('type', 'String')

    def _order_columns(self, output_header, collector):
        """A generator which converts the collector output into an OrderedDict
        with the right column order. This is important to ensure
        output column ordering is stable.
        """
        for row in collector():
            if isinstance(row, dict):
                result = collections.OrderedDict()
                for column in output_header:
                    result[column["name"]] = row.get(column["name"])

                yield result
            else:
                yield row

    def _generate_rows(self, args, kwargs):
        # instantiate the plugin with arguments.
        self.plugin_obj = self.plugin_cls(session=self.session,
                                          *args, **kwargs)
        output_header = getattr(self.plugin_cls, "table_header", None)
        collector = getattr(self.plugin_obj, "collect_as_dicts", None)

        if callable(collector) and output_header is not None:
            # The plugin supports the collect API and declares its output ahead
            # of time. This is the ideal case.
            self.columns = output_header
            return repeated.lazy(lambda: self._order_columns(output_header, collector))

        else:
            # TODO: Should we not support these kind of plugins?

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
            return repeated.repeated(*list(renderer.rows))


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

    __args = [
        dict(name="query", required=True, positional=True,
             help="The dotty/EFILTER query to run."),

        dict(name="query_parameters", type="ArrayString", positional=True,
             help="Positional parameters for parametrized queries."),
    ]

    def __init__(self, *args, **kwargs):
        super(EfilterPlugin, self).__init__(*args, **kwargs)

        try:
            self.scope = self._get_scope()
            self.query = q.Query(self.plugin_args.query,
                                 params=self.plugin_args.query_parameters,
                                 scope=self.scope)
        except errors.EfilterError as error:
            raise plugin.PluginError("Could not parse your query %r: %s." % (
                self.plugin_args.query, error))

        except Exception:
            # I am using a broad except here to make sure we always display a
            # friendly error message. EFILTER will usually raise a friendly
            # error, but we might get a non-EfilterError exception if the user
            # gets creative (e.g. passing a custom object as query, instead of a
            # string).
            raise plugin.PluginError("Could not parse your query %r." % (
                self.plugin_args.query,))

    def _get_scope(self):
        """Builds the scope for this query.

        We add some useful functions to be available to the query:

        timestamp(): Wrap an int or float in a UnixTimeStamp so it
           gets rendered properly.

        substr(): Allows a string to be substringed.

        file(): Marks a string as a file name. The Rekall Agent will
           then potentially upload this file.
        """
        scope = helpers.EFILTER_SCOPES.copy()
        scope["timestamp"] = api.user_func(
            lambda x, **_: basic.UnixTimeStamp(value=x, session=self.session),
            arg_types=[float, int, long])

        # This function is used to indicate that the string represents
        # a filename. This will cause the agent to upload it if the
        # user requested uploading files.
        # > select file(path.filename.name).filename.name from glob("/*")
        scope["file"] = api.scalar_function(
            lambda x: common.FileInformation(session=self.session, filename=x),
            arg_types=(string.IString,))

        scope["substr"] = api.scalar_function(
            lambda x, start, end: utils.SmartUnicode(x)[int(start):int(end)],
            arg_types=(string.IString, number.INumber, number.INumber))

        scope["hex"] = api.scalar_function(
            lambda x: hex(int(x)),
            arg_types=(number.INumber,))

        scope["deref"] = api.scalar_function(
            lambda x: x.deref(),
            arg_types=(obj.Pointer,))

        return scope

    # IStructured implementation for EFILTER:
    def resolve(self, name):
        """Find and return a CommandWrapper for the plugin 'name'."""
        function = self.scope.get(name)
        if function:
            return function

        meta = self.session.plugins.plugin_db.GetActivePlugin(name)
        if meta != None:
            wrapper = CommandWrapper(meta.plugin_cls, self.session)
            return wrapper

        raise KeyError("No plugin named %r." % name)

    def getmembers_runtime(self):
        """Get all available plugins."""
        result = dir(self.session.plugins)
        result += list(self.scope)

        return frozenset(result)

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
    """
    Searches and recombines output of other plugins.

    Search allows you to use the EFILTER search engine to filter, transform
    and combine output of most Rekall plugins. The most common use for this
    is running IOCs.

    ## Some examples

    * Find the process with pid 1:

      ```
      select * pslist() where proc.pid == 1
      ```

    * Sort lsof output by file descriptor:

      ```
      select * from lsof() order by fd
      ```

    * Filter and sort through lsof in one step:

      ```
      select * from lsof() where proc.name =~ "rekall" order by fd
      ```

    You will probably need to use the *describe* plugin to help
    discover the exact column structure.

    * regex match on array of strings - case insensitive.

      ```
      (Windows)
      select proc, proc.environ from pslist() where
        proc.environ.TMP =~ "temp"

      (Linux)
      select proc, proc.environ from pslist() where
         proc.environ.PATH =~ "home"
      ```

    * Format using the hex() method, using *as* to name columns.

      ```
      (Windows)
      select hex(VAD.start) as start, hex(VAD.end) as end,
            Protect from vad(proc_regex: "rekal")

      (Linux)
      select hex(start) as start, hex(end) as end, filename
            from maps(proc_regex: "rekall")
      ```

    * Autoselect column names - second column can not clash with first
      column name (should be hex, column 1).

      ```
      (Windows)
      select hex(VAD.start), hex(VAD.end), Protect
            from vad(proc_regex: "rekal")

      (Linux)
      select hex(start), hex(end), filename from maps(proc_regex: "rekall")
      ```
    * Timestamp user function

      ```
        select proc, timestamp(proc.create_time) from pslist()
      ```

    * Yarascan with sub query

      ```
        select * from file_yara(
           paths: (
            select path.filename from glob(
                "c:\windows\*.exe")).filename,
           yara_expression: "rule r1 {strings: $a = \"Microsoft\" wide condition: any of them}")
      ```

      On Linux:
      ```
      select * from file_yara(
            paths: (
              select path.filename from glob(
                 "/home/*/.ssh/*")).filename,
            yara_expression: "rule r1 {strings: $a = \"ssh-rsa\" condition: any of them}")
      ```

    * Parameter interpolations:

      ```
        a =  "select * from file_yara(paths: ( select path.filename from glob({0})).filename, yara_expression: {1})"

        search a, [r"c:\windows\*.exe",
             "rule r1 {strings: $a = \"Microsoft\" wide condition: any of them}"]
      ```
    * WMI integration + unknown field:

      ```
        select Result.Name, Result.SessionId, Result.foo
             from wmi("select * from Win32_Process")

        select Result.Name, Result.BootDevice
             from wmi("select * from Win32_OperatingSystem")
      ```

    * Describe WMI dynamic query

      ```
        describe wmi, dict(query="select * from Win32_Process")
      ```

    * Substitute a single string

      ```
        select sub("Microsoft", "MS", Result.Name)
               from wmi("select * from Win32_OperatingSystem")
      ```
    * Substiture an array

      ```
        select sub("rekal", "REKALL", proc.cmdline) from pslist()
      ```
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
        return solve.solve(self.query, self).value or []

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
            column_name = column.get("name")
            columns.append(column_name)

            if column_name is None:
                raise ValueError(
                    "Column spec %r is missing a name. Full header was: %r." %
                    (column, table_header))

        try:
            for row in rows:
                renderer.table_row(*[row.get(key) for key in columns])
        except errors.EfilterError as error:
            # Because 'rows' could be a lazy iterator it's possible that an
            # exception will get raised while output is already being rendered.
            self.query_error = error
            return self.render_error(renderer)

    def _render_dicts(self, renderer, rows):
        """Used to render search results if they are basic dicts."""
        try:
            for row in rows:
                renderer.table_row(*iter(row.values()))
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

    def render(self, renderer):
        # Do we have a query?
        if not self.query:
            return self.render_error(renderer)

        # Get the data we're rendering.
        try:
            rows = self.collect() or []
        except errors.EfilterError as error:
            self.query_error = error
            return self.render_error(renderer)

        # For queries which name a list of columns we need to get the first row
        # to know which columns will be output. Surely efilter can provide this
        # from the AST?  This seems like a hack because if the first row the
        # plugin produces does not include all the columns we will miss them.
        # If is also buggy because if the plugin does not produce any rows we
        # can not know if the query is correct or not. For example "select XXXX
        # from plugin()" can not raise an unknown column XXXX if the plugin does
        # not produce at least one row.
        remaining_rows = iter(rows)
        try:
            first_row = next(remaining_rows)
        except StopIteration:
            renderer.format("No results.")
            return

        except errors.EfilterKeyError as e:
            raise plugin.PluginError(
                "Column %s not found. "
                "Use the describe plugin to list all available "
                "columns. (%s)" % (e.key, e))

        except errors.EfilterError as e:
            raise plugin.PluginError("EFilter Error: %s:" % e)

        all_rows = itertools.chain((first_row,), remaining_rows)

        # If we have some output but don't know what it is we can try to use
        # dict keys as columns.
        if isinstance(first_row, (dict, row_tuple.RowTuple)):
            columns = [dict(name=x)
                       for x in structured.getmembers(first_row)]
            renderer.table_header(columns, auto_widths=True)
            return self._render_plugin_output(renderer, columns, all_rows)

        # Sigh. Give up, and render whatever you got, I guess.
        renderer.table_header([dict(name="result")])
        return self._render_whatever_i_guess(renderer, all_rows)


# Below we implement various EFILTER protocols for various Rekall types.


# Implement IApplicative for Command to get reflection APIs.
applicative.IApplicative.implement(
    for_type=plugin.Command,
    implementations={
        applicative.apply:
            lambda x, *args, **kwargs: x(*args, **kwargs).collect(),
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
        associative.getkeys_runtime: lambda c: c.table_header.all_names
    }
)


# Implement IAssociative for Structs because why not. This lets us do
# struct[key] as well as struct.key.
associative.IAssociative.implement(
    for_type=obj.Struct,
    implementations={
        associative.select: getattr,
        associative.getkeys_runtime: structured.getmembers_runtime
    }
)


def Struct_getmembers_runtime(item):
    result = set((name for name, _ in item.getproperties()))
    result.update(["obj_offset", "obj_type", "obj_name"])
    return result


# This lets us do struct.member. If the struct does not have the member, we
# return a NoneObject. This allows us to gracefully dereference structs with
# missing fields depending on the profile.
structured.IStructured.implement(
    for_type=obj.Struct,
    implementations={
        structured.resolve: lambda x, y: getattr(x, y, obj.NoneObject("")),
        structured.getmembers_runtime: Struct_getmembers_runtime,
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
