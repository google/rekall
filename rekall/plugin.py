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


import StringIO

from rekall import config
from rekall import obj
from rekall import registry
from rekall.ui import text as text_renderer


class Error(Exception):
    """Raised for plugin errors."""


class PluginError(Error):
    """An error occured in a plugin."""


class InvalidArgs(Error):
    """Invalid arguments."""


class Abort(Error):
    """Signal aborting of the plugin."""


class Command(object):
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

    # This will hold the error status from running this plugin.
    error_status = None

    @classmethod
    def args(cls, parser):
        """Declare the command line args this plugin needs."""

    @registry.classproperty
    def name(cls):  # pylint: disable=no-self-argument
        return getattr(cls, "_%s__name" % cls.__name__, None)

    def __init__(self, **kwargs):
        """The constructor for this command.

        Commands can take arbitrary named args and have access to the running
        session.

        Args:
          session: The session we will use. Many options are taken from the
            session by default, if not provided. This allows users to omit
            specifying many options.
        """
        session = kwargs.pop("session", None)
        if kwargs:
            raise InvalidArgs(unicode(kwargs.keys()))

        super(Command, self).__init__(**kwargs)

        if session is None:
            raise InvalidArgs("A session must be provided.")

        self.session = session

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
        return "Plugin: %s" % self.name

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
    def is_active(cls, session):
        """Checks we are active.

        This method will be called with the session to check if this specific
        class is active. This mechanism allows multiple implementations to all
        share the same name, as long as only one is actually active. For
        example, we can have a linux, windows and mac version of plugins with
        the "pslist" name.
        """
        _ = session
        return True

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
            "-p", "--profile", critical=True,
            help="Name of the profile to load. This is the "
            "filename of the profile found in the profiles "
            "directory. Profiles are searched in the profile "
            "path order.")

        metadata.add_requirement("profile")

    @classmethod
    def is_active(cls, session):
        # Note! This will trigger profile autodetection if this plugin is
        # needed. This might be slightly unexpected: When command line
        # completing the available plugins we will trigger profile autodetection
        # in order to determine which plugins are active.
        profile = (super(ProfileCommand, cls).is_active(session) and
                   session.profile != None)
        if cls.PROFILE_REQUIRED:
            return profile

        else:
            return True

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

        self.profile = self.session.profile
        if self.PROFILE_REQUIRED and not self.profile:
            raise PluginError("Profile not specified. (use vol(plugins.info) "
                              "to see available profiles.).")


class KernelASMixin(object):
    """A mixin for those plugins which require a valid kernel address space.

    This class ensures a valid kernel AS exists or an exception is raised.
    """

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(KernelASMixin, cls).args(parser)

        parser.add_argument("--dtb", type="IntParser",
                            help="The DTB physical address.")

    def __init__(self, dtb=None, **kwargs):
        """A mixin for plugins which require a valid kernel address space.

        Args:
          dtb: A potential dtb to be used.
        """
        super(KernelASMixin, self).__init__(**kwargs)

        # If the dtb is specified use that as the kernel address space.
        if dtb is not None:
            self.kernel_address_space = (
                self.session.kernel_address_space.__class__(
                    base=self.physical_address_space, dtb=dtb))
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

    def __init__(self, **kwargs):
        """A mixin for those plugins requiring a physical address space.

        Args:
          physical_address_space: The physical address space to use. If not
            specified we use the following options:

            1) session.physical_address_space,

            2) Guess using the load_as() plugin,

            3) Use session.kernel_address_space.base.

        """
        super(PhysicalASMixin, self).__init__(**kwargs)
        self.physical_address_space = self.session.physical_address_space

        if not self.physical_address_space:
            # Try to guess the AS
            self.session.plugins.load_as().GetPhysicalAddressSpace()
            self.physical_address_space = self.session.physical_address_space

        if self.PHYSICAL_AS_REQUIRED and not self.physical_address_space:
            raise PluginError("Physical address space is not set. "
                              "(Try plugins.load_as)")


class VerbosityMixIn(object):
    """Use this mixin to provide a --verbosity option to a plugin."""

    @classmethod
    def args(cls, parser):
        super(VerbosityMixIn, cls).args(parser)

        parser.add_argument(
            "-V", "--verbosity", default=1, type="IntParser",
            help="An integer reflecting the amount of desired output: "
            "0 = quiet, 10 = noisy. Default: 1")

    def __init__(self, *args, **kwargs):
        # Do not interfere with positional args, since this is a mixin.
        self.verbosity = kwargs.pop("verbosity", 1)
        super(VerbosityMixIn, self).__init__(*args, **kwargs)



class PluginMetadataDatabase(object):
    """A database of all the currently registered plugin's metadata."""

    def __init__(self, session):
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
                               plugin_name, results))

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
