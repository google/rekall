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

import argparse
import logging
import re
import yaml
import os

from rekall import constants

def GetHomeDir():
    return (os.environ.get("HOME") or      # Unix
            os.environ.get("USERPROFILE")) # Windows


# This is the configuration file template which will be created if the user does
# not have an existing file. The aim is not to exhaustively list all possible
# options, rather to ensure that reasonable defaults are specified initially.
DEFAULT_CONFIGURATION = dict(
    profile_path=constants.PROFILE_REPOSITORIES,

    # By default we just drop the notebooks at the home directory.
    notebook_dir=GetHomeDir(),
    )


OPTIONS = []


def GetConfigFile():
    """Gets the configuration stored in the config file.

    Searches for the config file in reasonable locations.

    Return:
      configuration stored in the config file. If the file is not found, returns
      an empty configuration.
    """
    search_path = [".rekallrc"]  # Current directory.
    homedir = GetHomeDir()
    if homedir:
        search_path.append("%s/.rekallrc" % homedir)

    search_path.append("/etc/rekallrc")

    for path in search_path:
        try:
            with open(path, "rb") as fd:
                return yaml.safe_load(fd)
        except (IOError, ValueError):
            pass

    return {}


def MergeConfigOptions(state):
    """Read the config file and apply the config options to the session."""
    # First apply the defaults:
    for _, _, name, default, _ in OPTIONS:
        state.Set(name, default)

    config_data = GetConfigFile()
    # An empty configuration file - we try to initialize a new one.
    if not config_data:
        homedir = GetHomeDir()
        if homedir:
            try:
                filename = "%s/.rekallrc" % homedir
                with open(filename, "wb") as fd:
                    yaml.dump(DEFAULT_CONFIGURATION, fd)

                logging.info("Created new configuration file %s", filename)
                config_data = DEFAULT_CONFIGURATION
            except IOError:
                pass

    # Can not write it anywhere but at least we start with something sensible.
    if not config_data:
        config_data = DEFAULT_CONFIGURATION

    for k, v in config_data.items():
        state.Set(k, v)


def DeclareOption(short_name=None, name=None, default=None, group=None,
                  **kwargs):
    """Record the options."""
    if name is None:
        name = short_name
        short_name = None

    name = name.strip("-")
    if short_name:
        short_name = short_name.strip("-")

    OPTIONS.append((group, short_name, name, default, kwargs))


def RegisterArgParser(parser):
    """Register the options into the parser."""
    groups = {}

    for group, short_name, name, _, kwargs in sorted(OPTIONS):
        if not name.startswith("--"):
            name = "--" + name

        if short_name and not short_name.startswith("-"):
            short_name = "-" + short_name

        kwargs["default"] = argparse.SUPPRESS
        if group:
            try:
                arg_group = groups[group]
            except KeyError:
                groups[group] = arg_group = parser.add_argument_group(group)

            if short_name:
                arg_group.add_argument(short_name, name, **kwargs)
            else:
                arg_group.add_argument(name, **kwargs)

        else:
            if short_name:
                parser.add_argument(short_name, name, **kwargs)
            else:
                parser.add_argument(name, **kwargs)


class IntParser(argparse.Action):
    """Class to parse ints either in hex or as ints."""
    def parse_int(self, value):
        # Support suffixes
        multiplier = 1
        m = re.search("(.*)(mb|kb|m|k)", value)
        if m:
            value = m.group(1)
            suffix = m.group(2).lower()
            if suffix in ("mb", "m"):
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


class ArrayStringParser(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        result = []
        if isinstance(values, basestring):
            values = [values]

        for value in values:
            result.extend([x for x in value.split(",")])

        setattr(namespace, self.dest, result)
