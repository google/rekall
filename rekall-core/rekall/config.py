#!/usr/bin/python

# Rekall
# Copyright (C) 2012 Michael Cohen <scudette@gmail.com>
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

"""This is the Rekall configuration system.

Rekall maintains a persistent file with global settings in the user's home
directory. This makes it easy for users to retain commonly used Rekall
parameters.

Note that the configuration file is only used in interactive mode. When used as
a library the configuration file has no effect.
"""

__author__ = "Michael Cohen <scudette@gmail.com>"

import collections
import logging
import os
import sys
import tempfile
import yaml

from rekall import constants


class CommandMetadata(object):
    """A class that carried a plugin's configuration.

    A plugin is responsible for declaring its metadata by calling this
    configuration object's methods from the args() class method.

    There are two things that plugin must declare:

    add_*_arg(): Calling these functions declares an argument for this
       plugin. See the documentation for that method for details.

    add_metadata(): This method provides additional metadata about this plugin.
    """

    def __init__(self, plugin_cls=None):
        self.args = collections.OrderedDict()
        self.requirements = set()
        self.plugin_cls = plugin_cls
        if plugin_cls:
            plugin_cls.args(self)

        self.description = (plugin_cls.__doc__ or
                            plugin_cls.__init__.__doc__ or "")

    def set_description(self, description):
        self.description = description

    def add_positional_arg(self, name, type="string"):
        """Declare a positional arg."""
        self.args[name] = dict(type=type)

    def add_argument(self, short_opt, long_opt=None, **options):
        """Add a new argument to the command.

        This method is used in the args() class method to add a new command line
        arg to the plugin. It is similar to the argparse add_argument() method
        but it adds a type parameter which conveys higher level information
        about the argument. Currently supported types:

        - ArrayIntParser: A list of integers (possibly encoded as hex strings).
        - ArrayStringParser: A list of strings.
        - Float: A float.
        - IntParser: An integer (possibly encoded as a hex string).
        - Boolean: A flag - true/false.
        - ChoiceArray: A comma separated list of strings which must be from the
            choices parameter.
        """
        if "action" in options:
            raise RuntimeError("Action keyword is deprecated.")

        if not isinstance(options.get("type", ""), str):
            raise RuntimeError("Type must be a string.")

        # Is this a positional arg?
        positional = options.pop("positional", False)

        # For now we support option names with leading --.
        if long_opt is None:
            long_opt = short_opt
            short_opt = ""

        if long_opt.startswith("-"):
            long_opt = long_opt.lstrip("-")
            short_opt = short_opt.lstrip("-")
            positional = False

        name = long_opt
        options["short_opt"] = short_opt
        options["positional"] = positional
        options["name"] = name

        self.args[name] = options

    def add_requirement(self, requirement):
        """Add a requirement for this plugin.

        Currently supported requirements:
         - profile: A profile must exist for this plugin to run.

         - physical_address_space: A Physical Address Space (i.e. an image file)
           must exist for this plugin to work.
        """
        self.requirements.add(requirement)

    def Metadata(self):
        return dict(requirements=list(self.requirements),
                    arguments=self.args.values(), name=self.plugin_cls.name,
                    description=self.description)

    def ApplyDefaults(self, args):
        """Update args with the defaults.

        If an option in args is None, we update it with the default value for
        this option.
        """
        for name, options in self.args.iteritems():
            if options.get("dest") == "SUPPRESS":
                continue

            name = name.replace("-", "_")
            if args[name] is None:
                args[name] = options.get("default")

        return args


def GetHomeDir(session):
    return (
        session.GetParameter("home", cached=False) or
        os.environ.get("HOME") or      # Unix
        os.environ.get("USERPROFILE") or # Windows
        tempfile.gettempdir() or  # Fallback tmp dir.
        ".")


# This is the configuration file template which will be created if the user does
# not have an existing file. The aim is not to exhaustively list all possible
# options, rather to ensure that reasonable defaults are specified initially.
DEFAULT_CONFIGURATION = dict(
    repository_path=constants.PROFILE_REPOSITORIES,

    # This is the path of the cache directory - given relative to the config
    # file (or it can be specified as an absolute path).
    cache_dir=".rekall_cache",
    )

# Global options control the framework's own flags. They are not associated with
# any one plugin.
OPTIONS = CommandMetadata()


def GetConfigFile(session):
    """Gets the configuration stored in the config file.

    Searches for the config file in reasonable locations.

    Return:
      configuration stored in the config file. If the file is not found, returns
      an empty configuration.
    """
    search_path = [
        # Next to the main binary (in case of pyinstaller - rekall.exe).
        os.path.join(os.path.dirname(sys.executable), ".rekallrc"),
        ".rekallrc",   # Current directory.
        os.path.join(GetHomeDir(session), ".rekallrc"), # Home directory overrides system.
        "/etc/rekallrc",
    ]

    for path in search_path:
        try:
            with open(path, "rb") as fd:
                result = yaml.safe_load(fd)
                logging.debug("Loaded configuration from %s", path)

                # Allow the config file to update the
                # environment. This is handy in standalone deployment
                # where one can update %HOME% and ensure Rekall does
                # not touch the drive.
                os.environ.update(result.get("environment", {}))

                return result

        except (IOError, ValueError):
            pass

    return {}


def CreateDefaultConfigFile(session):
    """Creates a default config file."""
    homedir = GetHomeDir(session)
    if homedir:
        try:
            filename = "%s/.rekallrc" % homedir
            with open(filename, "wb") as fd:
                yaml.dump(DEFAULT_CONFIGURATION, fd)

            logging.info("Created new configuration file %s", filename)
            cache_dir = os.path.join(
                homedir, DEFAULT_CONFIGURATION["cache_dir"])

            os.makedirs(cache_dir)
            logging.info("Created new cache directory %s", cache_dir)

            return DEFAULT_CONFIGURATION
        except (IOError, OSError):
            pass

    # Can not write it anywhere but at least we start with something sensible.
    return DEFAULT_CONFIGURATION


def MergeConfigOptions(state, session):
    """Read the config file and apply the config options to the session."""
    config_data = GetConfigFile(session)
    # An empty configuration file - we try to initialize a new one.
    if not config_data:
        config_data = CreateDefaultConfigFile(session)

    # First apply the defaults:
    for name, options in OPTIONS.args.iteritems():
        if name not in config_data:
            config_data[name] = options.get("default")

    for k, v in config_data.items():
        state.Set(k, v)


def RemoveGlobalOptions(state):
    """Remove all global options from state dictionary."""
    state.pop("SUPPRESS", None)

    for name in OPTIONS.args:
        state.pop(name, None)

    return state


def DeclareOption(*args, **kwargs):
    """Declare a config option for command line and config file."""
    # Options can not be positional!
    kwargs["positional"] = False
    default = kwargs.get("default")
    if default is not None and isinstance(default, str):
        kwargs["default"] = unicode(default)

    OPTIONS.add_argument(*args, **kwargs)
