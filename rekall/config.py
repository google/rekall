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
import json
import os


# This is the configuration file template which will be created if the user does
# not have an existing file. The aim is not to exhaustively list all possible
# options, rather to ensure that reasonable defaults are specified initially.
DEFAULT_CONFIGURATION = dict(
    profile_path=["http://profiles.rekall.googlecode.com/git/"]
    )


OPTIONS = []


def GetConfigFile():

    search_path = [".rekallrc"]  # Current directory.
    homedir = os.environ.get("HOME")
    if homedir:
        search_path.append("%s/.rekallrc" % homedir)

    search_path.append("/etc/rekallrc")

    for path in search_path:
        try:
            with open(path, "rb") as fd:
                return json.load(fd)
        except IOError:
            pass


def MergeConfigOptions(state):
    """Read the config file and apply the config options to the session."""
    # First apply the defaults:
    for _, _, name, default, _ in OPTIONS:
        state.Set(name, default)

    config_data = GetConfigFile()
    if config_data is None:
        homedir = os.environ.get("HOME")
        if homedir:
            try:
                filename = "%s/.rekallrc" % homedir
                with open(filename, "wb") as fd:
                    json.dump(DEFAULT_CONFIGURATION, fd, indent=4)

                logging.info("Created new configuration file %s", filename)
                config_data = DEFAULT_CONFIGURATION
            except IOError:
                pass

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
