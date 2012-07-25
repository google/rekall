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
import sys

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

    def error(self, message):
        # We trap this error especially since we launch the volshell.
        if message == "too few arguments":
            return

        super(VolatilityArgParser, self).error(message)


def parse_args(argv=None):
    """Parse the args from the command line argv."""
    parser =  VolatilityArgParser(
        description='The Volatility Memory Forensic Framework.',
        conflict_handler='resolve',
        epilog='When no module is provided, '
        'drops into interactive mode')

    # Top level args.
    parser.add_argument("-e", "--exec", default=None,
                        help="execute a python volatility script.")

    parser.add_argument("-i", "--interactive", default=False,
                        action="store_true",
                        help="For compatibility, if a plugin name is specified "
                        "on the command line, we exit immediately after running"
                        " it. If this flag is specified we drop into the "
                        "interactive shell instead.")

    parser.add_argument("--logging", default=None,
                        help="Logging level (lower is more verbose).")

    parser.add_argument("--debug", default=None, action="store_true",
                        help="If set we break into the debugger on some "
                        "conditions.")

    parser.add_argument("-p", "--profile", default=None,
                        help="Name of the profile to load.")


    parser.add_argument("-f", "--filename", default=None,
                        help="The raw image to load.")


    parser.add_argument("--renderer", default="TextRenderer",
                        help="The renderer to use. e.g. (TextRenderer, "
                        "JsonRenderer).")

    # Module specific args.
    subparsers = parser.add_subparsers(
        description="The following plugins can be selected.",
        metavar='Plugin',
        )

    parsers = {}

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

    return result
