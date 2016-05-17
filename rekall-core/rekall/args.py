#!/usr/bin/python

# Rekall Memory Forensics
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
"""This module manages the command line parsing logic.

Rekall uses the argparse module for command line parsing, however this module
contains so many bugs it might be worth to implement our own parser in future.
"""

__author__ = "Michael Cohen <scudette@gmail.com>"

import argparse
import logging
import re
import os
import sys
import zipfile

from rekall import config
from rekall import constants
from rekall import plugin
from rekall import utils


config.DeclareOption("--plugin", default=[], type="ArrayStringParser",
                     help="Load user provided plugin bundle.")

config.DeclareOption(
    "-h", "--help", default=False, type="Boolean",
    help="Show help about global paramters.")


class RekallHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def add_argument(self, action):
        # Allow us to suppress an arg from the --help output for those options
        # which do not make sense on the command line.
        if action.dest != "SUPPRESS":
            super(RekallHelpFormatter, self).add_argument(action)


class RekallArgParser(argparse.ArgumentParser):
    ignore_errors = False

    def __init__(self, session=None, **kwargs):
        kwargs["formatter_class"] = RekallHelpFormatter
        if session == None:
            raise RuntimeError("Session must be set")
        self.session = session
        super(RekallArgParser, self).__init__(**kwargs)

    def error(self, message):
        if self.ignore_errors:
            return

        # We trap this error especially since we launch the volshell.
        if message == "too few arguments":
            return

        super(RekallArgParser, self).error(message)

    def parse_known_args(self, args=None, namespace=None, force=False, **_):
        self.ignore_errors = force

        result = super(RekallArgParser, self).parse_known_args(
            args=args, namespace=namespace)

        return result

    def print_help(self, file=None):
        if self.ignore_errors:
            return

        return super(RekallArgParser, self).print_help(file=file)

    def exit(self, *args, **kwargs):
        if self.ignore_errors:
            return

        return super(RekallArgParser, self).exit(*args, **kwargs)


def LoadPlugins(paths=None):
    PYTHON_EXTENSIONS = [".py", ".pyo", ".pyc"]

    for path in paths:
        if not os.access(path, os.R_OK):
            logging.error("Unable to find %s", path)
            continue

        path = os.path.abspath(path)
        directory, filename = os.path.split(path)
        module_name, ext = os.path.splitext(filename)

        # Its a python file.
        if ext in PYTHON_EXTENSIONS:
            # Make sure python can find the file.
            sys.path.insert(0, directory)

            try:
                logging.info("Loading user plugin %s", path)
                __import__(module_name)
            except Exception as e:
                logging.error("Error loading user plugin %s: %s", path, e)
            finally:
                sys.path.pop(0)

        elif ext == ".zip":
            zfile = zipfile.ZipFile(path)

            # Make sure python can find the file.
            sys.path.insert(0, path)
            try:
                logging.info("Loading user plugin archive %s", path)
                for name in zfile.namelist():
                    # Change from filename to python package name.
                    module_name, ext = os.path.splitext(name)
                    if ext in PYTHON_EXTENSIONS:
                        module_name = module_name.replace("/", ".").replace(
                            "\\", ".")

                        try:
                            __import__(module_name.strip("\\/"))
                        except Exception as e:
                            logging.error("Error loading user plugin %s: %s",
                                          path, e)

            finally:
                sys.path.pop(0)

        else:
            logging.error("Plugin %s has incorrect extension.", path)


def _TruncateARGV(argv):
    """Truncate the argv list at the first sign of a plugin name.

    At this stage we do not know which module is valid, or its options. The
    syntax of the command line is:

    rekal -x -y -z plugin_name -a -b -c

    Where -x -y -z are global options, and -a -b -c are plugin option.  We only
    want to parse up to the plugin name.
    """
    short_argv = [argv[0]]
    for item in argv[1:]:
        for plugin_cls in plugin.Command.classes.values():
            if plugin_cls.name == item:
                return short_argv

        short_argv.append(item)

    return short_argv


# Argparser stupidly matches short options for options it does not know yet
# (with parse_known_args()). This list allows us to declare placeholders to
# avoid the partial option matching behaviour in some cases.
DISAMBIGUATE_OPTIONS = [
    "profile",
]


def ParseGlobalArgs(parser, argv, user_session):
    """Parse some session wide args which must be done before anything else."""
    # Register global args.
    ConfigureCommandLineParser(config.OPTIONS, parser)

    # Parse the known args.
    known_args, unknown_args = parser.parse_known_args(args=argv)

    with user_session.state as state:
        for arg, value in vars(known_args).items():
            # Argparser erroneously parses flags as str objects, but they are
            # really unicode objects.
            if isinstance(value, str):
                value = utils.SmartUnicode(value)

            # Argparse tries to interpolate defaults into the parsed data in the
            # event that the args are not present - even when calling
            # parse_known_args. Before we get to this point, the config system
            # has already set the state from the config file, so if we allow
            # argparse to set the default we would override the config file
            # (with the defaults). We solve this by never allowing argparse
            # itself to handle the defaults. We always set default=None, when
            # configuring the parser, and rely on the
            # config.MergeConfigOptions() to set the defaults.
            if value is not None:
                state.Set(arg, value)

        # Enforce the appropriate logging level if user supplies the --verbose
        # or --quiet command line flags.
        verbose_flag = getattr(known_args, "verbose", None)
        quiet_flag = getattr(known_args, "quiet", None)

        if verbose_flag and quiet_flag:
            raise ValueError("Cannot set both --verbose and --quiet!")

        if verbose_flag:
            state.Set("logging_level", "DEBUG")
        elif quiet_flag:
            state.Set("logging_level", "CRITICAL")

    # Now load the third party user plugins. These may introduce additional
    # plugins with args.
    if user_session.state.plugin:
        LoadPlugins(user_session.state.plugin)

        # External files might have introduced new plugins - rebuild the plugin
        # DB.
        user_session.plugins.plugin_db.Rebuild()

    return known_args, unknown_args


def FindPlugin(argv=None, user_session=None):
    """Search the argv for the first occurrence of a valid plugin name.

    Returns a mutated argv where the plugin is moved to the front. If a plugin
    is not found we assume the plugin is "shell" (i.e. the interactive session).

    This maintains backwards compatibility with the old global/plugin specific
    options. In the current implementation, the plugin name should probably come
    first:

    rekal pslist -v -f foo.elf --pid 4

    but this still works:

    rekal -v -f foo.elf pslist --pid 4
    """
    result = argv[:]
    for i, item in enumerate(argv):
        if item in user_session.plugins.plugin_db.db:
            result.pop(i)
            return item, result

    return "shell", result


def ConfigureCommandLineParser(command_metadata, parser, critical=False):
    """Apply the plugin configuration to an argparse parser.

    This method is the essential glue between the abstract plugin metadata and
    argparse.

    The main intention is to de-couple the plugin's args definition from arg
    parser's specific implementation. The plugin then conveys semantic meanings
    about its arguments rather than argparse implementation specific
    details. Note that args are parsed through other mechanisms in a number of
    cases so this gives us flexibility to implement arbitrary parsing:

    - Directly provided to the plugin in the constructor.
    - Parsed from json from the web console.
    """
    # This is used to allow the user to break the command line arbitrarily.
    parser.add_argument('-', dest='__dummy', action="store_true",
                        help="A do nothing arg. Useful to separate options "
                        "which take multiple args from positional. Can be "
                        "specified many times.")

    try:
        groups = parser.groups
    except AttributeError:
        groups = parser.groups = {
            "None": parser.add_argument_group("Global options")
        }

    if command_metadata.plugin_cls:
        groups[command_metadata.plugin_cls.name] = parser.add_argument_group(
            "Plugin %s options" % command_metadata.plugin_cls.name)

    for name, options in command_metadata.args.iteritems():
        # Prevent None getting into the kwargs because it upsets argparser.
        kwargs = dict((k, v) for k, v in options.items() if v is not None)
        name = kwargs.pop("name", None) or name

        # If default is specified we assume the parameter is not required.
        # However, defaults are not passed on to argparse in most cases, and
        # instead applied separately through ApplyDefaults. For exceptions,
        # see below.
        default = kwargs.pop("default", None)
        try:
            required = kwargs.pop("required")
        except KeyError:
            required = default is None

        group_name = kwargs.pop("group", None)
        if group_name is None and command_metadata.plugin_cls:
            group_name = command_metadata.plugin_cls.name

        group = groups.get(group_name)
        if group is None:
            groups[group_name] = group = parser.add_argument_group(group_name)

        positional_args = []

        short_opt = kwargs.pop("short_opt", None)

        # A positional arg is allowed to be specified without a flag.
        if kwargs.pop("positional", None):
            positional_args.append(name)

            # If a position arg is optional we need to specify nargs=?
            if not required:
                kwargs["nargs"] = "?"

        # Otherwise argparse wants to have - in front of the arg.
        else:
            if short_opt:
                positional_args.append("-" + short_opt)

            positional_args.append("--" + name)

        arg_type = kwargs.pop("type", None)
        if arg_type == "ArrayIntParser":
            kwargs["action"] = ArrayIntParser
            kwargs["nargs"] = "+" if required else "*"

        if arg_type == "ArrayStringParser":
            kwargs["action"] = ArrayStringParser
            kwargs["nargs"] = "+" if required else "*"

        elif arg_type == "IntParser":
            kwargs["action"] = IntParser

        elif arg_type == "Float":
            kwargs["type"] = float

        elif arg_type == "Boolean" or arg_type == "Bool":
            # Argparse will assume default False for flags and not return
            # None, which is required by ApplyDefaults to recognize an unset
            # argument. To solve this issue, we just pass the default on.
            kwargs["default"] = default
            kwargs["action"] = "store_true"

        # Multiple entries of choices (requires a choices paramter).
        elif arg_type == "ChoiceArray":
            kwargs["nargs"] = "+" if required else "*"
            kwargs["choices"] = list(kwargs["choices"])

        elif arg_type == "Choices":
            kwargs["choices"] = list(kwargs["choices"])

        # Skip option if not critical.
        critical_arg = kwargs.pop("critical", False)
        if critical and critical_arg:
            group.add_argument(*positional_args, **kwargs)
            continue

        if not (critical or critical_arg):
            group.add_argument(*positional_args, **kwargs)


def parse_args(argv=None, user_session=None, global_arg_cb=None):
    """Parse the args from the command line argv.

    Args:
      argv: The args to process.
      user_session: The session we work with.
      global_arg_cb: A callback that will be used to process global
         args. Global args are those which affect the state of the
         Rekall framework and must be processed prior to any plugin
         specific args. In essence these flags control which plugins
         can be available.
    """
    if argv is None:
        argv = sys.argv[1:]

    parser = RekallArgParser(
        description=constants.BANNER,
        conflict_handler='resolve',
        add_help=True,
        session=user_session,
        epilog="When no module is provided, drops into interactive mode",
        formatter_class=RekallHelpFormatter)

    # Parse the global and critical args from the command line.
    global_flags, unknown_flags = ParseGlobalArgs(parser, argv, user_session)
    if global_arg_cb:
        global_arg_cb(global_flags, unknown_flags)

    # The plugin name is taken from the command line, but it is not enough to
    # know which specific implementation will be used. For example there are 3
    # classes implementing the pslist plugin WinPsList, LinPsList and OSXPsList.
    plugin_name, argv = FindPlugin(argv, user_session)

    # Add all critical parameters. Critical parameters are those which are
    # common to all implementations of a certain plugin and are required in
    # order to choose from these implementations. For example, the profile or
    # filename are usually used to select the specific implementation of a
    # plugin.
    for metadata in user_session.plugins.plugin_db.MetadataByName(plugin_name):
        ConfigureCommandLineParser(metadata, parser, critical=True)

    # Parse the global and critical args from the command line.
    ParseGlobalArgs(parser, argv, user_session)

    # Find the specific implementation of the plugin that applies here. For
    # example, we have 3 different pslist implementations depending on the
    # specific profile loaded.
    command_metadata = user_session.plugins.Metadata(plugin_name)
    if not command_metadata:
        raise plugin.PluginError(
            "Plugin %s is not available for this configuration" % plugin_name)

    # Configure the arg parser for this command's options.
    plugin_cls = command_metadata.plugin_cls
    ConfigureCommandLineParser(command_metadata, parser)

    # We handle help especially.
    if global_flags.help:
        parser.print_help()
        sys.exit(-1)

    # Parse the final command line.
    result = parser.parse_args(argv)

    # Apply the defaults to the parsed args.
    result = utils.AttributeDict(vars(result))
    result.pop("__dummy", None)

    command_metadata.ApplyDefaults(result)

    return plugin_cls, result


## Parser for special args.

class IntParser(argparse.Action):
    """Class to parse ints either in hex or as ints."""
    def parse_int(self, value):
        # Support suffixes
        multiplier = 1
        m = re.search("(.*)(Mb|mb|kb|m|M|k|g|G|Gb)", value)
        if m:
            value = m.group(1)
            suffix = m.group(2).lower()
            if suffix in ("gb", "g"):
                multiplier = 1024 * 1024 * 1024
            elif suffix in ("mb", "m"):
                multiplier = 1024 * 1024
            elif suffix in ("kb", "k"):
                multiplier = 1024

        try:
            if value.startswith("0x"):
                value = int(value, 16) * multiplier
            else:
                value = int(value) * multiplier
        except ValueError:
            raise argparse.ArgumentError(self, "Invalid integer value")

        return value

    def __call__(self, parser, namespace, values, option_string=None):
        if isinstance(values, basestring):
            values = self.parse_int(values)
        setattr(namespace, self.dest, values)


class ArrayIntParser(IntParser):
    """Parse input as a comma separated list of integers.

    We support input in the following forms:

    --pid 1,2,3,4,5

    --pid 1 2 3 4 5

    --pid 0x1 0x2 0x3
    """

    def Validate(self, value):
        return self.parse_int(value)

    def __call__(self, parser, namespace, values, option_string=None):
        result = []
        if isinstance(values, basestring):
            values = [values]

        for value in values:
            result.extend([self.Validate(x) for x in value.split(",")])

        setattr(namespace, self.dest, result or None)


class ArrayStringParser(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        result = []

        if isinstance(values, basestring):
            values = [values]

        for value in values:
            result.extend([x for x in value.split(",")])

        setattr(namespace, self.dest, result)
