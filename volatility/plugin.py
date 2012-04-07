# Volatility
# Copyright (C) 2012 Michael Cohen
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

__author__ = "Michael Cohen <scudette@gmail.com>"

"""Plugins allow the core volatility system to be extended."""
import logging

from volatility import conf
from volatility import registry
from volatility import obj


class Error(Exception):
    """Raised for plugin errors."""


class PluginError(Error):
    """An error occured in a plugin."""


class Command(object):
    """A command can be run from the volatility command line.

    Commands can be automatically imported into the shell's namespace and are
    expected to produce textual (or other) output.

    In order to define a new command simply extend this class.
    """

    # these attribute are not inherited.

    # The name of this command (The command will be registered under this
    # name). If empty, the command will not be imported into the namespace but
    # will still be available from the Factory below.
    __name = ""

    # This class will not be registered (but extensions will).
    __abstract = True
    __metaclass__ = registry.MetaclassRegistry

    @obj.classproperty
    def name(cls):
        try:
            return getattr(cls, "_%s__name" % cls.__name__)
        except AttributeError:
            return ""

    def __init__(self, session=None, **kwargs):
        """The constructor for this command.

        Commands can take arbitrary named args and have access to the running
        session.

        Args:
          session: The session we will use. Many options are taken from the
            session by default, if not provided. This allows users to omit
            specifying many options.
        """
        self.session = session or conf.GLOBAL_SESSION
        if kwargs:
            logging.warning("Unknown kwargs %s ignored.", kwargs.keys())

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
            if cls.name == name:
                return cls(session=self.session, **kwargs)

    def render(self, fd = None):
        """Produce results on the fd given."""

    @classmethod
    def is_active(cls, config):
        """Checks we are active.

        This method will be with a configuration variable to check if this
        specific class is active. This mechanism allows multiple implementations
        to all share the same name, as long as only one is actually active. For
        example, we can have a linux, windows and mac version of plugins with
        the "pslist" name.
        """
        return True

    @classmethod
    def GetActiveClasses(cls, config):
        """Return only the active commands based on config."""
        for command_cls in cls.classes.values():
            if command_cls.is_active(config):
                yield command_cls



class ProfileCommand(Command):
    """A baseclass for all commands which require a profile."""

    __abstract = True

    def __init__(self, profile=None, **kwargs):
        """Baseclass for all plugins which accept a profile.

        Args:
          profile: The kernel profile to use for this command.
        """
        super(ProfileCommand, self).__init__(**kwargs)

        # Require a valid profile.
        self.profile = profile or self.session.profile
        if self.profile is None:
            raise PluginError("Profile not specified. (use vol(plugins.info) "
                              "to see available profiles.).")


class KernelASMixin(object):
    """A mixin for those plugins which require a valid kernel address space.

    This class ensures a valid kernel AS exists or an exception is raised.
    """
    def __init__(self, kernel_address_space=None, **kwargs):
        """A mixin for plugins which require a valid kernel address space.

        Args:
          kernel_address_space: The kernel address space to use. If not
            specified, we use the session.
        """
        super(KernelASMixin, self).__init__(**kwargs)

        # Try to load the AS from the session if possible.
        self.kernel_address_space = (kernel_address_space or
                                     self.session.kernel_address_space)

        if self.kernel_address_space is None:
            # Try to guess the AS
            self.session.plugins.load_as(session=self.session)
            self.kernel_address_space = self.session.kernel_address_space

        if self.kernel_address_space is None:
            raise PluginError("kernel_address_space not specified.")


class PhysicalASMixin(object):
    """A mixin for those plugins which require a valid physical address space.

    This class ensures a valid physical AS exists or an exception is raised.
    """
    def __init__(self, physical_address_space=None, **kwargs):
        """A mixin for those plugins requiring a physical address space.

        Args:
          physical_address_space: The physical address space to use. If not
            specified we use the following options: 1)
            session.physical_address_space, 2) Guess using the load_as() plugin,
            3) Use session.kernel_address_space.base.
        """
        super(PhysicalASMixin, self).__init__(**kwargs)

        self.physical_address_space = (physical_address_space or
                                       self.session.physical_address_space)

        if self.physical_address_space is None:
            # Try to guess the AS
            self.session.plugins.load_as(session=self.session)
            self.physical_address_space = self.session.physical_address_space

        if self.physical_address_space is None:
            raise plugin.PluginError("Physical address space is not set. "
                                     "(Try plugins.load_as)")


def CommandFactory(command_name = None, config = None, class_name = None, **kwargs):
    """Creates a new instance of a command.

    Args:
      command_name: The optional name as advertised by the command.

      config: A configuration object which will be used to resolve the right
         class for this name.p

      command_cls: The name of the command's class (used to get specific
         classes).

      kwargs: Will be passed to the command's constructor.

    Return:
     A command instance created with the kwargs.
    """
    # Find the corresponding command class.
    if command_name:
        command_classes = []
        for name, command_cls in Command.GetActiveClasses(config):
            if command_cls.name == command_name:
                command_classes.append(command_cls)

        # Do we have too many active commands?
        if len(command_classes) > 1:
            logging.error("There are multiple active implementations for "
                          "'%s' %s, will pick %s for now." % (
                    command_name, [x.__name__ for x in command_classes],
                    command_classes[0].__name__))

        if command_classes:
            command_classes[0](**kwargs)

    else:
        try:
            return Command.classes[class_name](**kwargs)
        except KeyError:
            pass

    raise Error("No such plugin.")
