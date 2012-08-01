#!/usr/bin/python

# Volatility
# Copyright (C) 2012 Michael Cohen <scudette@gmail.com>
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

"""This module manages the command line parsing logic."""

import argparse
import logging
import os
import sys
import zipfile

from volatility import constants
from volatility import plugin


class IntParser(argparse.Action):
    """Class to parse ints either in hex or as ints."""
    def parse_int(self, value):
        try:
            if value.startswith("0x"):
                value = int(value, 16)
            else:
                value = int(value)
        except ValueError:
            raise argparse.ArgumentError(self, "Invalid integer value")

        return value

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, self.parse_int(values))


class ArrayIntParser(IntParser):
    """Parse input as a comma separated list of integers.

    We support input in the following forms:

    --pid 1,2,3,4,5

    --pid 1 2 3 4 5

    --pid 0x1 0x2 0x3
    """

    def __call__(self, parser, namespace, values, option_string=None):
        result = []
        if isinstance(values, basestring):
            values = [values]

        for value in values:
            result.extend([self.parse_int(x) for x in value.split(",")])

        setattr(namespace, self.dest, result)


class MockArgParser(object):
    def add_argument(self, short_flag=None, long_flag=None, dest=None, **kwargs):
        if short_flag.startswith("--"):
            flag = short_flag
        elif long_flag.startswith("--"):
            flag = long_flag
        else:
            flag = dest

        # This function will be called by the args() class method, and we just
        # keep track of the args this module defines.
        arg_name = flag.strip("-").replace("-", "_")

        self.args[arg_name] = None

    def build_args_dict(self, cls, namespace):
        """Build a dict suitable for **kwargs from the namespace."""
        self.args = {}

        # Discover all the args this module uses.
        cls.args(self)

        for key in self.args:
            self.args[key] = getattr(namespace, key)

        return self.args


class VolatilityArgParser(argparse.ArgumentParser):
    ignore_errors = False

    def error(self, message):
        if self.ignore_errors:
            return

        # We trap this error especially since we launch the volshell.
        if message == "too few arguments":
            return

        super(VolatilityArgParser, self).error(message)

    def parse_known_args(self, args=None, namespace=None, force=False):
        self.ignore_errors = force

        result = super(VolatilityArgParser, self).parse_known_args(
            args=args, namespace=namespace)

        return result

    def print_help(self, file=None):
        if self.ignore_errors:
            return

        return super(VolatilityArgParser, self).print_help(file=file)

    def exit(self, *args, **kwargs):
        if self.ignore_errors:
            return

        return super(VolatilityArgParser, self).exit(*args, **kwargs)


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
            except Exception, e:
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


def parse_args(argv=None):
    """Parse the args from the command line argv."""
    parser =  VolatilityArgParser(description=constants.BANNER,
                                  conflict_handler='resolve',
                                  epilog='When no module is provided, '
                                  'drops into interactive mode')

    # Top level args.
    parser.add_argument("--pager", default=os.environ.get("PAGER"),
                        help="The pager to use when output is larger than a "
                        "screen full.")

    parser.add_argument("--logging", default="error", choices=[
            "debug", "info", "warning",  "critical", "error"],
                        help="Logging level to show messages.")

    parser.add_argument("--debug", default=None, action="store_true",
                        help="If set we break into the debugger on error "
                        "conditions.")

    parser.add_argument("-p", "--profile", default=None,
                        help="Name of the profile to load.")

    parser.add_argument("-f", "--filename", default=None,
                        help="The raw image to load.")

    parser.add_argument("--renderer", default="TextRenderer",
                        help="The renderer to use. e.g. (TextRenderer, "
                        "JsonRenderer).")

    parser.add_argument("--plugin", default=[], nargs="+",
                        help="Load user provided plugin bundle.")

    parser.add_argument("--output", default=None,
                        help="Write to this output file.")

    parser.add_argument("--overwrite", action="store_true", default=False,
                        help="Allow overwriting of output files.")

    # Module specific args.
    subparsers = parser.add_subparsers(
        description="The following plugins can be selected.",
        metavar='Plugin',
        )

    parsers = {}

    # Check for additional user modules first since they may introduce more
    # options and plugins.
    namespace = argparse.Namespace()

    # The parser may complain here if we are using options etc that are
    # introduced by user plugins - so we suppress it for this run.
    parser.parse_known_args(argv, namespace, force=True)

    # This is the earliest point we can initialize the logger:
    logging.getLogger().setLevel(getattr(logging, namespace.logging.upper()))

    # Now load the user plugins.
    LoadPlugins(namespace.plugin)

    # Add module specific parser for each module.
    for cls in plugin.Command.classes.values():
        if cls.name:
            doc = cls.__doc__.splitlines()[0]
            name = cls.name
            try:
                module_parser = parsers[name]
            except KeyError:
                parsers[name] = module_parser = subparsers.add_parser(
                    cls.name, help=doc, description=cls.__doc__)

            cls.args(module_parser)
            module_parser.set_defaults(module=cls.name)

    # Parse the command line.
    result = parser.parse_args(argv)

    result.plugin = None

    return result
