# Rekall Memory Forensics
#
# Copyright 2014 Google Inc. All Rights Reserved.
#
# Authors:
# Copyright (C) 2012 Michael Cohen <scudette@users.sourceforge.net>
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

"""Rebuild documentation stubs for plugins.

This script automatically builds documentation pages for Rekall plugins.
"""
import argparse
import collections
import os
import textwrap
import utils

from rekall import plugins # pylint: disable=unused-import
from rekall import plugin


PARSER = argparse.ArgumentParser()
PARSER.add_argument("plugins", default=None, nargs="*",
                    help="The name of the plugin to re-write.")


class DummyParser(object):
    """A dummy object used to collect all defined args."""

    def __init__(self):
        self.args = {}

    def add_requirement(*_, **__):
        pass

    def set_description(*_, **__):
        pass

    def add_positional_arg(*_, **__):
        pass

    def add_argument(self, short_option, long_opt="", help=None, **_):
        name = long_opt.lstrip("-") or short_option.lstrip("-")

        # Normalize the option name to use _.
        name = name.replace("-", "_")

        self.args[name] = help or ""


def GetPluginArgs(cls):
    """Get plugin args and their documentation.

    Return:
      A list of tuples (name, documentation) for each arg.
    """
    result = collections.OrderedDict()
    dummy_parser = DummyParser()
    cls.args(dummy_parser)

    # Now introspect the parameters of each level of the constructor according
    # to the order in the __mro__.
    for base_cls in cls.__mro__:
        try:
            arg_count = base_cls.__init__.im_func.func_code.co_argcount
            args = base_cls.__init__.im_func.func_code.co_varnames[:arg_count]

            for arg in args:
                # Ignore these parameters since they are provided automatically.
                if arg in ["self", "kwargs", "profile", "session"]:
                    continue

                result[arg] = dummy_parser.args.get(arg, "")
        except AttributeError:
            pass

    return result

def RebuildAllDocs():
    for plugin_name in plugin.Command.classes:
        RebuildMissingDocs(plugin_name)

def RebuildMissingDocs(filename):
    plugin_name = os.path.basename(filename).split(".")[0]
    try:
        cls = plugin.Command.classes[plugin_name]
    except KeyError:
        return

    print "Updating docs for plugin %s" % filename
    doc = textwrap.dedent(cls.__doc__ or "")
    result = dict(layout="plugin", title=cls.name,
                  abstract=doc, args=GetPluginArgs(cls), raw_content="",
                  epydoc="%s.%s-class.html" % (
                      cls.__module__, cls.__name__))

    page = utils.ParsePage(filename) or {}
    for k in result.keys():
        # Always overwrite the args description since the code is authoritative.
        if k not in ["args"] and k in page:
            result[k] = page[k]

    raw_args = "args:\n"
    for arg, arg_doc in result['args'].items():
        raw_args += "  %s: '%s'\n" % (arg, arg_doc)

    result['raw_args'] = raw_args

    result['abstract'] = "\n".join(
        ["  %s" % x for x in result['abstract'].strip().splitlines()])

    with open("%s.md" % filename, "wb") as fd:
        data = """---
layout: plugin
title: %(title)s
abstract: |
%(abstract)s

epydoc: %(epydoc)s
%(raw_args)s
---
%(raw_content)s
""" % result
        fd.write(data)

if __name__ == "__main__":
    FLAGS = PARSER.parse_args()
    if not FLAGS.plugins:
        RebuildAllDocs()
    else:
        for _plugin in FLAGS.plugins:
            RebuildMissingDocs(_plugin)
