# Rekall Memory Forensics
# Copyright (C) 2012 Michael Cohen
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
#

"""Plugins allow the core rekall system to be extended."""

__author__ = "Michael Cohen <scudette@gmail.com>"

import collections
import copy
import re
import StringIO

from rekall import config
from rekall import obj
from rekall import registry
from rekall import utils
from rekall.ui import text as text_renderer


class Error(Exception):
    """Raised for plugin errors."""


class PluginError(Error):
    """An error occured in a plugin."""


class InvalidArgs(Error):
    """Invalid arguments."""


class Abort(Error):
    """Signal aborting of the plugin."""


class CommandOption(object):
    """An option specification."""

    def __init__(self, name=None, default=None, type="String", choices=None,
                 help="", positional=False, required=False, override=False,
                 hidden=False):
        self.name = name
        self.default = default
        self.type = type
        self.help = help
        self._choices = choices
        self.required = required
        self.positional = positional
        self.override = override
        self.hidden = hidden

    @utils.safe_property
    def choices(self):
        if callable(self._choices):
            return list(self._choices())

        return self._choices

    def add_argument(self, parser):
        """Add ourselves to the parser."""
        prefix = "" if self.positional else "--"
        parser.add_argument(prefix + self.name, default=self.default,
                            type=self.type, help=self.help,
                            positional=self.positional, hidden=self.hidden,
                            required=self.required, choices=self.choices)

    def parse(self, value, session):
        """Parse the value as passed."""
        if value is None:
            if self.default is None:
                # Default values for various types.
                if self.type == "AddressSpace":
                    return session.GetParameter("default_address_space")

                if self.type in ["ArrayStringParser", "ArrayString",
                                 "ArrayIntParser", "Array"]:
                    return []

                if self.type in ["Bool", "Boolean"]:
                    return False

            elif self.type == "RegEx":
                if isinstance(self.default, basestring):
                    return re.compile(self.default)

            return self.default

        # Validate the parsed type. We only support a small set of types right
        # now, so this is good enough.

        # Handle addresses specifically though the address resolver.
        if self.type == "Address" or self.type == "SymbolAddress":
            value = session.address_resolver.get_address_by_name(value)

        elif self.type == "IntParser":
            if isinstance(value, basestring):
                value = int(value, 0)
            else:
                value = int(value)

        elif self.type == "Choices":
            if value not in self.choices:
                raise TypeError("Arg %s must be one of %s" % (
                    self.name, self.choices))

        elif self.type == "ChoiceArray":
            if isinstance(value, basestring):
                value = [value]  # pylint: disable=redefined-variable-type

            for item in value:
                if item not in self.choices:
                    raise TypeError("Arg %s must be one of %s" % (
                        self.name, self.choices))

        elif self.type in ["ArrayString", "ArrayStringParser"]:
            if isinstance(value, basestring):
                value = [value]

            if not isinstance(value, collections.Iterable):
                raise TypeError("Arg %s must be a list of strings" % self.name)

            for item in value:
                if not isinstance(item, basestring):
                    raise TypeError("Arg %s must be a list of strings" %
                                    self.name)

        elif self.type == "Array":
            if isinstance(value, basestring):
                value = [value]

            if not isinstance(value, collections.Iterable):
                raise TypeError("Arg %s must be a list of strings" % self.name)

        elif self.type == "RegEx":
            if isinstance(value, basestring):
                value = re.compile(value, re.I)

        elif self.type == "ArrayIntParser":
            try:
                value = [int(value)]  # pylint: disable=redefined-variable-type
            except (ValueError, TypeError):
                result = []
                for x in value:
                    # RowTuple are treated especially in order to simplify
                    # Efilter syntax.
                    if x.__class__.__name__ == "RowTuple":
                        if len(x) != 1:
                            raise PluginError(
                                "Subselect must only select a single row when "
                                "expanding into a list.")
                        x = int(x[0])
                    else:
                        x = int(x)
                    result.append(x)
                value = result

        # Allow address space to be specified.
        elif self.type == "AddressSpace":
            load_as = session.plugins.load_as(session=session)
            value = load_as.ResolveAddressSpace(value)

        return value


class ModeBasedActiveMixin(object):
    # Specify this mode to decleratively activate this class. To make this work,
    # you will need to define a kb.ParameterHook() that can calculate if the
    # session is running in the specified mode.
    mode = None

    @classmethod
    def is_active(cls, session):
        """Checks we are active.

        This method will be called with the session to check if this specific
        class is active. This mechanism allows multiple implementations to all
        share the same name, as long as only one is actually active. For
        example, we can have a linux, windows and mac version of plugins with
        the "pslist" name.

        This mixin provides the mixed class with a basic is_active() method
        which honors a mode member defined on the class and all its
        subclasses. The mode is additive (meaning each class and its subclasses
        are only active if the mode is active).
        """
        for subclass in cls.__mro__:
            mode = getattr(subclass, "mode", None)

            if isinstance(mode, basestring):
                if not session.GetParameter(mode):
                    return False

            elif isinstance(mode, (list, tuple)):
                for i in mode:
                    if not session.GetParameter(i):
                        return False

        return True



class Command(ModeBasedActiveMixin):
    """A command can be run from the rekall command line.

    Commands can be automatically imported into the shell's namespace and are
    expected to produce textual (or other) output.

    In order to define a new command simply extend this class.
    """

    # these attribute are not inherited.

    # The name of this command (The command will be registered under this
    # name). If empty, the command will not be imported into the namespace but
    # will still be available from the Factory below.
    __name = ""

    # Name of the category of this command. This is used when showing help and
    # in the UI.
    __category = ""

    # This class will not be registered (but extensions will).
    __abstract = True
    __metaclass__ = registry.MetaclassRegistry

    # This declares that this plugin only exists in the interactive session.
    interactive = False

    # This declares that the plugin should not be called upon to collect
    # structs - the default behavior.
    producer = False

    # This will hold the error status from running this plugin.
    error_status = None

    mode = None

    @classmethod
    def args(cls, parser):
        """Declare the command line args this plugin needs."""

    @classmethod
    def GetPrototype(cls, session):
        """Return an instance of this plugin with suitable default arguments.

        In most general applications, types are declared at compile time and
        remain immutable, or at least available throughout the program's
        lifecycle. Rekall, on the other hand, leave many of the decisions
        usually made at type declaration time until late in the runtime,
        when the profile data is available. For this reason, in many of the
        cases when other applications would interrogate classes (for attributes
        and properties, among other things), in Rekall we must interrogate
        their instances, which have access to profile data. In order to
        make this possible slightly earlier in the runtime than when running
        the plugin, we introduce the concept of prototypes, which are
        instances of the plugin or struct with the current session and profile
        available, but with no data or arguments set.

        Arguments:
            session

        Returns:
            And instance of this Command with suitable default arguments.
        """
        try:
            return cls(session=session, ignore_required=True)
        except (TypeError, ValueError):
            raise NotImplementedError("Subclasses must override GetPrototype "
                                      "if they require arguments.")

    @registry.classproperty
    def name(cls):  # pylint: disable=no-self-argument
        return getattr(cls, "_%s__name" % cls.__name__, None)

    def __init__(self, ignore_required=False, **kwargs):
        """The constructor for this command.

        Commands can take arbitrary named args and have access to the running
        session.

        Args:
          session: The session we will use. Many options are taken from the
            session by default, if not provided. This allows users to omit
            specifying many options.

          ignore_required: If this is true plugin constructors must allow the
            plugin to be instantiated with no parameters. All parameter
            validation shall be disabled and construction must succeed.
        """
        session = kwargs.pop("session", None)
        if kwargs:
            raise InvalidArgs("Invalid arguments: %s" % unicode(kwargs.keys()))

        super(Command, self).__init__(**kwargs)

        if session == None:
            raise InvalidArgs("A session must be provided.")

        self.session = session
        self.ignore_required = ignore_required

    def get_plugin(self, name, **kwargs):
        """Returns an instance of the named plugin.

        The new plugin will initialized with the current session and optional
        kwargs.
        Args:
          name: The generic name of the plugin (i.e. the __name attribute,
             e.g. pslist).
          kwargs: Extra args to use for instantiating the plugin.
        """
        for cls in self.classes.values():
            if cls.name == name and cls.is_active(self.session):
                return cls(session=self.session, profile=self.profile,
                           **kwargs)

    def __str__(self):
        """Render into a string using the text renderer."""
        fd = StringIO.StringIO()
        ui_renderer = text_renderer.TextRenderer(
            session=self.session, fd=fd)

        with ui_renderer.start(plugin_name=self.name):
            self.render(ui_renderer)

        return fd.getvalue()

    def __repr__(self):
        return "Plugin: %s (%s)" % (self.name, self.__class__.__name__)

    def __iter__(self):
        """Make plugins that define collect iterable, as convenience.

        Because this:
            for x in session.plugins.get_some_data():
                # do stuff

        Is nicer than this:
            for x in session.plugins.get_some_data().collect():
                # do stuff
        """
        if callable(getattr(self, "collect", None)):
            for x in self.collect():
                if x:
                    yield x

        else:
            raise TypeError("%r is not iterable." % self)

    def render(self, renderer):
        """Produce results on the renderer given.

        Each plugin should implement this method to produce output on the
        renderer. The framework will initialize the plugin and provide it with
        some kind of renderer to write output on. The plugin should not assume
        that the renderer is actually TextRenderer, only that the methods
        defined in the BaseRenderer exist.

        Args:
          renderer: A renderer based at rekall.ui.renderer.BaseRenderer.
        """

    @classmethod
    def GetActiveClasses(cls, session):
        """Return only the active commands based on config."""
        for command_cls in cls.classes.values():
            if command_cls.is_active(session):
                yield command_cls


class ProfileCommand(Command):
    """A baseclass for all commands which require a profile."""

    __abstract = True

    PROFILE_REQUIRED = True

    @classmethod
    def args(cls, metadata):
        # Top level args.
        metadata.add_argument(
            "-p", "--profile", critical=True, hidden=True,
            help="Name of the profile to load. This is the "
            "filename of the profile found in the profiles "
            "directory. Profiles are searched in the profile "
            "path order.")

        metadata.add_requirement("profile")

    @classmethod
    def is_active(cls, session):
        if cls.PROFILE_REQUIRED:
            # Note! This will trigger profile autodetection if this plugin is
            # needed. This might be slightly unexpected: When command line
            # completing the available plugins we will trigger profile
            # autodetection in order to determine which plugins are active.
            profile = (session.profile != None and
                       super(ProfileCommand, cls).is_active(session))

            return profile

        else:
            return super(ProfileCommand, cls).is_active(session)

    def __init__(self, profile=None, **kwargs):
        """Baseclass for all plugins which accept a profile.

        Args:
          profile: The kernel profile to use for this command.
        """
        super(ProfileCommand, self).__init__(**kwargs)

        # If a profile was provided we must set it into the session and then use
        # it. (The new profile must control the presence of other dependent
        # plugins and so forms part of the session's state.).
        if profile is not None:
            self.session.profile = profile

        # If the session already has a profile, use it.
        if self.session.HasParameter("profile_obj"):
            self.profile = self.session.profile

        # If the profile is required but the session has nothing yet, force
        # autodetection.
        elif self.PROFILE_REQUIRED:
            # Force autodetection...
            self.profile = self.session.profile

            # Nothing found... bail out!
            if not self.profile:
                raise PluginError(
                    "Profile could not detected. "
                    "Try specifying one explicitly.")
        else:
            self.profile = obj.NoneObject("No profile")


class PluginHeader(object):
    header = None
    by_name = None

    def __init__(self, *columns):
        self.by_name = {}

        for column in columns:
            if not isinstance(column, dict):
                raise TypeError("Plugins declaring table header ahead of "
                                "time MUST do so using the new format ("
                                "using dicts, NOT tuples). Table header %r "
                                "is invalid." % columns)

            name = column.get("name")
            if not name:
                raise ValueError(
                    "Plugins declaring table headers ahead of "
                    "time MUST specify 'name' for each column. "
                    "Table header %r is invalid." % (columns,))

            self.by_name[name] = column

        self.header = copy.deepcopy(columns)

    @utils.safe_property
    def types_in_output(self):
        """What types of thing does this plugin output?

        Returns a set of declared types, each type being either a class object
        or a string name of the class (for profile types, mostly).

        This helps the self-documentation features find plugins based on their
        declared headers. It's also used by 'collect' to find producers.
        """
        for column in self.header:
            t = column.get("type")
            if t:
                yield t

    def __iter__(self):
        return iter(self.header)

    def __getitem__(self, idx):
        return self.header[idx]

    def fill_dict(self, row):
        """Fills out dict with all the declared columns."""
        for header in self.header:
            column_name = header["name"]
            if column_name not in row:
                row[column_name] = None

        return row

    def dictify(self, row):
        """Convert an ordered row into a dict.

        Uses the internal column order to map row names to the dict.
        """
        result = {}
        for idx, header in enumerate(self.header):
            column_name = header["name"]

            try:
                result[column_name] = row[idx]
            except IndexError:
                result[column_name] = None

        return result

    @utils.safe_property
    def all_names(self):
        return set(self.by_name.iterkeys())

    def find_column(self, name):
        """Get the column spec in 'name'."""
        return self.by_name.get(name)

class ArgsParserMixin(object):
    """A Mixin which provides argument parsing and validation."""
    # Each plugin mixin should define a list of CommandOption instances with
    # this name (__args). The constructor will collect these definitions into a
    # self.args parameter available for the plugins at runtime.
    __args = []

    # This will contain the parsed constructor args after the plugin is
    # instantiated.
    plugin_args = None

    def __init__(self, *pos_args, **kwargs):
        self.ignore_required = kwargs.get("ignore_required", False)

        # If this is set we do not enforce required args. This is useful when
        # callers want to instantiate a plugin in order to use its methods as a
        # utility.
        if self.plugin_args is None:
            self.plugin_args = utils.AttributeDict()

        # Collect args in the declared order (basically follow the mro
        # backwards).
        definitions = []
        definitions_classes = {}
        for cls in self.__class__.__mro__:
            args_definition = getattr(cls, "_%s__args" % cls.__name__, [])
            for definition in args_definition:
                # Definitions can be just simple dicts.
                if isinstance(definition, dict):
                    definition = CommandOption(**definition)

                # We have seen this arg before.
                previous_definition = definitions_classes.get(definition.name)
                if previous_definition:
                    # Since we traverse the definition in reverse MRO order,
                    # later definitions should be masked by earlier (more
                    # derived) definitions.
                    continue

                definitions_classes[definition.name] = cls
                definitions.append(definition)

        # Handle positional args by consuming them off the pos_args array in
        # definition order. This allows positional args to be specified either
        # by position, or by keyword.
        positional_args = [x for x in definitions if x.positional]
        if len(positional_args) < len(pos_args):
            raise TypeError("Too many positional args provided.")

        for pos_arg, definition in zip(pos_args, positional_args):
            # If the positional arg is also defined as a keyword arg this is a
            # bug.
            if definition.name in kwargs:
                raise TypeError(
                    "Positional Args %s is also supplied as a keyword arg." %
                    definition.name)

            kwargs[definition.name] = pos_arg

        # Collect all the declared args and parse them.
        for definition in definitions:
            value = kwargs.pop(definition.name, None)
            if (value is None and definition.required and
                    not self.ignore_required):
                raise InvalidArgs("%s is required." % definition.name)

            self.plugin_args[definition.name] = definition.parse(
                value, session=kwargs.get("session"))

        super(ArgsParserMixin, self).__init__(**kwargs)


class TypedProfileCommand(ArgsParserMixin):
    """Mixin that provides the plugin with standardized table output."""

    # Subclasses must override. Has to be a list of column specifications
    # (i.e. list of dicts specifying the columns).
    table_header = None
    table_options = {}

    __args = [
        dict(name="verbosity", default=1, type="IntParser",
             help="An integer reflecting the amount of desired output: "
             "0 = quiet, 10 = noisy."),
    ]

    def __init__(self, *pos_args, **kwargs):
        super(TypedProfileCommand, self).__init__(*pos_args, **kwargs)
        if isinstance(self.table_header, (list, tuple)):
            self.table_header = PluginHeader(*self.table_header)

        # Switch off hidden column when verbosity is high.
        if self.plugin_args.verbosity > 1:
            for descriptor in self.table_header:
                descriptor["hidden"] = False

        super(TypedProfileCommand, self).__init__(*pos_args, **kwargs)

    @classmethod
    def args(cls, parser):
        super(TypedProfileCommand, cls).args(parser)

        # Collect all the declared args and add them to the parser.
        for cls_i in cls.__mro__:
            args_definition = getattr(cls_i, "_%s__args" % cls_i.__name__, [])
            for definition in args_definition:
                if isinstance(definition, dict):
                    definition = CommandOption(**definition)

                # Allow derived classes to override args from base classes.
                if definition.name in parser.args:
                    continue

                definition.add_argument(parser)

    def column_types(self):
        """Returns instances for each column definition.

        The actual objects that are returned when the plugin runs are often
        determined at run time because they depend on the profile loaded.

        This method is used in order to introspect the types of each column
        without actually running the plugin. A plugin must provide an instance
        for each column without running any code. This allows interospectors to
        learn about the output format before running the actual plugin.

        Note that this method should almost always be overloaded. We try to do
        our best here but it is not ideal. Ultimately all plugins will override
        this method and just declare a column_types() method.
        """
        self.session.logging.warn(
            "FIXME: Plugin %s (%s) does not produce typed output. "
            "Please define a column_types() method.",
            self.name, self.__class__.__name__)

        result = {}
        columns = []
        for column in self.table_header:
            column_name = column["name"]

            columns.append(column_name)
            result[column_name] = None

        try:
            for row_count, row in enumerate(self.collect()):
                if isinstance(row, dict):
                    result.update(row)

                elif isinstance(row, (tuple, list)):
                    for item, column_name in zip(row, columns):
                        if result.get(column_name) is None:
                            result[column_name] = item

                # One row is sometimes sufficient to figure out types, but
                # sometimes a plugin will send None as some of its columns
                # so we try a few more rows.
                if None not in result.values() or row_count > 5:
                    break

        except (NotImplementedError, TypeError):
            pass

        return result

    def collect(self):
        """Collect data that will be passed to renderer.table_row."""
        raise NotImplementedError()

    def collect_as_dicts(self):
        for row in self.collect():
            # Its already a dict.
            if isinstance(row, dict):
                yield self.table_header.fill_dict(row)
            else:
                yield self.table_header.dictify(row)

    # Row members which control some output.
    ROW_OPTIONS = set(
        ["depth",
         "annotation",
         "highlight",
         "nowrap",
         "hex_width"]
    )
    def render(self, renderer, **options):
        table_options = self.table_options.copy()
        table_options.update(options)

        output_style = self.session.GetParameter("output_style")
        if output_style == "full":
            table_options["hidden"] = False

        renderer.table_header(self.table_header, **table_options)
        for row in self.collect():
            if isinstance(row, (list, tuple)):
                renderer.table_row(*row, **options)
            else:
                new_row = []
                for column in self.table_header:
                    new_row.append(
                        row.pop(column["name"], None)
                    )

                if set(row) - self.ROW_OPTIONS:
                    raise RuntimeError(
                        "Plugin produced more data than defined columns (%s)." %
                        (list(row),))

                renderer.table_row(*new_row, **row)

    def reflect(self, member):
        column = self.table_header.by_name.get(member)
        if not column:
            raise KeyError("Plugin %r has no column %r." % (self, member))

        t = column.get("type")

        if isinstance(t, type):
            return t

        if not t:
            return None

        if isinstance(t, basestring):
            return self.profile.object_classes.get(t)

    def getkeys(self):
        return self.table_header.keys()

    def get_column(self, name):
        for row in self.collect_as_dicts():
            yield row[name]

    def get_column_type(self, name):
        column = self.table_header.find_column(name)
        if not column:
            return

        type_name = column.get("type")

        # If we don't have a type then we have to actually get the instance from
        # the profile, which will cause a type to be generated at runtime.
        return self.session.profile.GetPrototype(type_name)


class Producer(TypedProfileCommand):
    """Finds and outputs structs of a particular type.

    Producers are very simple plugins that output only a single column
    which contains a struct of 'type_name'. A good example of a producer are
    the individual pslist enumeration methods.
    """

    # The type of the structs that's returned out of collect and render.
    type_name = None

    # Declare that this plugin may be called upon to collect structs.
    producer = True

    @registry.classproperty
    @registry.memoize
    def table_header(self):
        return PluginHeader(dict(type=self.type_name, name=self.type_name))

    def collect(self):
        raise NotImplementedError()

    def produce(self):
        """Like collect, but yields the first column instead of whole row."""
        for row in self.collect():
            yield row[0]


class CachedProducer(Producer):
    """A producer backed by a cached session parameter hook."""

    @utils.safe_property
    def hook_name(self):
        """By convention, the hook name should be the same as our name."""
        # Override if you really want to.
        return self.name

    def collect(self):
        for offset in self.session.GetParameter(self.hook_name):
            yield [self.session.profile.Object(
                type_name=self.type_name,
                offset=offset)]


class KernelASMixin(object):
    """A mixin for those plugins which require a valid kernel address space.

    This class ensures a valid kernel AS exists or an exception is raised.
    """

    __args = [
        dict(name="dtb", type="IntParser", default=None, hidden=True,
             help="The DTB physical address.")
    ]

    def __init__(self, *args, **kwargs):
        """A mixin for plugins which require a valid kernel address space.

        Args:
          dtb: A potential dtb to be used.
        """
        super(KernelASMixin, self).__init__(*args, **kwargs)

        # If the dtb is specified use that as the kernel address space.
        if self.plugin_args.dtb is not None:
            self.kernel_address_space = (
                self.session.kernel_address_space.__class__(
                    base=self.physical_address_space,
                    dtb=self.plugin_args.dtb))
        else:
            # Try to load the AS from the session if possible.
            self.kernel_address_space = self.session.kernel_address_space

        if self.kernel_address_space == None:
            # Try to guess the AS
            self.session.plugins.load_as().GetVirtualAddressSpace()

            self.kernel_address_space = self.session.kernel_address_space

        if self.kernel_address_space == None:
            raise PluginError("kernel_address_space not specified.")


class PhysicalASMixin(object):
    """A mixin for those plugins which require a valid physical address space.

    This class ensures a valid physical AS exists or an exception is raised.
    """

    PHYSICAL_AS_REQUIRED = True

    @classmethod
    def args(cls, metadata):
        super(PhysicalASMixin, cls).args(metadata)
        metadata.add_requirement("physical_address_space")

    def __init__(self, *args, **kwargs):
        """A mixin for those plugins requiring a physical address space.

        Args:
          physical_address_space: The physical address space to use. If not
            specified we use the following options:

            1) session.physical_address_space,

            2) Guess using the load_as() plugin,

            3) Use session.kernel_address_space.base.

        """
        super(PhysicalASMixin, self).__init__(*args, **kwargs)
        self.physical_address_space = self.session.physical_address_space

        if not self.physical_address_space:
            # Try to guess the AS
            self.session.plugins.load_as().GetPhysicalAddressSpace()
            self.physical_address_space = self.session.physical_address_space

        if self.PHYSICAL_AS_REQUIRED and not self.physical_address_space:
            raise PluginError("Physical address space is not set. "
                              "(Try plugins.load_as)")


class PrivilegedMixIn(object):
    def __init__(self, **kwargs):
        super(PrivilegedMixIn, self).__init__(**kwargs)
        if not self.session.privileged:
            raise PluginError(
                "Live analysis is only available for interactive or "
                "privileged sessions.")


class DataInterfaceMixin(object):
    """This declares a plugin to present a table-like data interface."""

    COLUMNS = ()


class PluginOutput(dict):
    plugin_cls = DataInterfaceMixin


class PluginMetadataDatabase(object):
    """A database of all the currently registered plugin's metadata."""

    def __init__(self, session):
        if session == None:
            raise RuntimeError("Session must be set")

        self.session = session
        self.Rebuild()

    def Rebuild(self):
        self.db = {}

        for plugin_cls in Command.classes.itervalues():
            plugin_name = plugin_cls.name
            self.db.setdefault(plugin_name, []).append(
                config.CommandMetadata(plugin_cls))

    def MetadataByName(self, name):
        """Return all Implementations that implement command name."""
        for command_metadata in self.db[name]:
            yield command_metadata

    def GetActivePlugin(self, plugin_name):
        results = []
        for command_metadata in self.db.get(plugin_name, []):
            plugin_cls = command_metadata.plugin_cls
            if plugin_cls.is_active(self.session):
                results.append(command_metadata)

        # We assume there can only be one active plugin implementation. It
        # is an error to have multiple implementations active at the same
        # time.
        if len(results) > 1:
            raise RuntimeError("Multiple plugin implementations for %s: %s" % (
                plugin_name, [x.plugin_cls for x in results]))

        if results:
            return results[0]

        return obj.NoneObject("Plugin not active")

    def Serialize(self):
        result = {}
        for name in self.db:
            command_metadata = self.GetActivePlugin(name)
            if command_metadata:
                result[name] = command_metadata.Metadata()

        return result

    def GetRequirments(self, command_name):
        result = set()
        for metadata in self.db[command_name]:
            result.update(metadata.requirements)

        return result
