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
import os
import re
import textwrap
import yaml
import utils

from rekall import config
from rekall import plugins # pylint: disable=unused-import
from rekall import plugin


PARSER = argparse.ArgumentParser()
PARSER.add_argument("plugins", default=None, nargs="*",
                    help="The name of the plugin to re-write.")


SEPERATOR = "^---\n"

class PluginDescription(object):
    """Describes a plugin."""

    @classmethod
    def FromPlugin(cls, plugin_cls):
        self = cls()
        self.data = dict(
            layout="plugin",
            title=plugin_cls.name,
            module=plugin_cls.__module__,
            class_name=plugin_cls.__name__,
            epydoc="%s.%s-class.html" % (
                plugin_cls.__module__, plugin_cls.__name__),
            args={},
        )
        self.raw_content = ""
        self.class_name = plugin_cls.__name__

        command = config.CommandMetadata(plugin_cls)
        self.data["abstract"] = command.description

        for arg in command.Metadata()["arguments"]:
            desc = arg.get("help", "")
            if "type" in arg:
                desc += " (type: %s)\n" % arg["type"]

            if arg.get("choices"):
                desc += "\n\n* Valid Choices:"
                for choice in arg["choices"]:
                    desc += "\n    - " + choice
                desc += "\n"

            if "default" in arg:
                default = arg["default"]
                if default is not None:
                    if isinstance(default, list):
                        default = ", ".join([str(x) for x in default])
                    desc += "\n\n* Default: %s" % (default)

            # Ignore some common parameters.
            if arg["name"] not in set(["profile", "dtb"]):
                self.data["args"][arg["name"]] = desc

        return self

    @classmethod
    def FromPathname(cls, pathname):
        self = cls()

        self.text = open(pathname).read()
        parts = re.split(SEPERATOR, self.text, 2, flags=re.M)

        self.data = yaml.load(parts[1])
        if self.data["layout"] != "plugin" or "abstract" not in self.data:
            raise RuntimeError("Not a plugin")

        # The raw_content is preserved. The YAML part is regenerated from the
        # current plugin class. This should update any new args.
        self.raw_content = parts[-1]
        self.data["filename"] = self.filename = pathname

        # The class that is described by this filename.
        self.class_name = os.path.basename(pathname).split(".")[0]

        return self

    def write(self, path):
        with open(path, "wb") as fd:
            fd.write("---\n")
            fd.write(yaml.dump(self.data))
            fd.write("---\n")
            fd.write(self.raw_content)


def GetExistingPluginDescriptions(plugin_path):
    """Reads all the existing plugin descriptions."""
    result = {}

    for root, _, files in os.walk(plugin_path, True):
        for f in files:
            if f.endswith(".md"):
                try:
                    desc = PluginDescription.FromPathname(os.path.join(root, f))
                    result[desc.class_name] = desc
                except RuntimeError:
                    pass
    return result


def RebuildAllDocs():
    """Rebuild all stubs for plugins.

    Old plugins no longer recognized are moved to the Attic.
    New plugins are added to the Incoming directory.
    Existing plugins retain their raw data but the YAML section is rewritten.
    """

    plugins_path = "docs/Manual/Plugins/"

    plugin_descriptions = GetExistingPluginDescriptions(plugins_path)

    # Find all the outdated plugins and move them to the Attic.
    for plugin_class, desc in plugin_descriptions.iteritems():
        if plugin_class not in plugin.Command.classes:
            dest_path = os.path.join(
                plugins_path, "Attic", plugin_class + ".md")
            if dest_path != desc.filename:
                print ("Plugin %s is outdated. Moving to the Attic." %
                       plugin_class)
                os.rename(desc.filename, dest_path)

    # Add new plugins to Incoming.
    for plugin_cls_name, plugin_class in plugin.Command.classes.iteritems():
        if plugin_cls_name not in plugin_descriptions:
            desc = PluginDescription.FromPlugin(plugin_class)
            plugin_descriptions[plugin_cls_name] = desc
            print "New Plugin %s" % plugin_cls_name
            desc.write(os.path.join(plugins_path, "Incoming",
                                    plugin_cls_name + ".md"))

        else:
            new_desc = PluginDescription.FromPlugin(plugin_class)
            old_desc = plugin_descriptions[plugin_cls_name]
            if desc.data != old_desc.data:
                print "Updating plugin %s" % plugin_cls_name
                new_desc.raw_content = old_desc.raw_content
                new_desc.write(old_desc.filename)


if __name__ == "__main__":
    RebuildAllDocs()
