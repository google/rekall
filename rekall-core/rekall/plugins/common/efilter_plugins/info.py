# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
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

"""Informational plugins for assistance of efilter operations."""
from efilter.protocols import structured

from rekall import plugin
from rekall import session
from rekall import testlib


class Describe(plugin.TypedProfileCommand, plugin.ProfileCommand):
    """Describe the output of a plugin."""

    name = "describe"

    PROFILE_REQUIRED = False

    __args = [
        dict(name="plugin_name", required=True, positional=True,
             help="A plugin or plugin name to describe."),
        dict(name="max_depth", positional=True, required=False,
             type="IntParser", default=0,
             help="The maximum depth to follow mappings."),
    ]

    table_header = [
        dict(name="Field", type="TreeNode", max_depth=5, width=50),
        dict(name="Type"),
    ]

    def collect_members(self, item, depth):
        if depth > self.plugin_args.max_depth:
            return

        try:
            for member in sorted(structured.getmembers(item)):
                type_instance = structured.resolve(item, member)
                # If it was given as a type, we need an instance here.
                yield dict(
                    Field=member,
                    Type=self._determine_type_name(type_instance),
                    depth=depth,
                )
                for x in self.collect_members(type_instance, depth + 1):
                    yield x

        except (TypeError, NotImplementedError):
            pass

    def _determine_type_name(self, column_type_instance):
        if isinstance(column_type_instance, type):
            column_type_instance = column_type_instance()

        object_type = None
        try:
            object_type = column_type_instance.obj_type
        except AttributeError:
            pass

        if object_type is None:
            object_type = type(column_type_instance).__name__

        return object_type

    def collect(self):
        plugin_name = self.plugin_args.plugin_name
        if isinstance(plugin_name, session.PluginRunner):
            plugin_name = self.plugin_args.plugin_name.plugin_name

        plugin_cls = self.session.plugins.GetPluginClass(plugin_name)
        if not plugin_cls:
            raise plugin.PluginError("Please specify a valid plugin.")

        instance = plugin_cls(session=self.session, ignore_required=True)
        table_header = getattr(instance, "table_header", None)
        if not table_header:
            raise plugin.PluginError(
                "Plugin %s is not a Typed Plugin. It can not be used in "
                "searches." % plugin_name)

        column_types = instance.column_types()
        for i, column in enumerate(table_header):
            column_name = column["name"]
            if isinstance(column_types, dict):
                column_type_instance = column_types.get(column_name)
            else:
                column_type_instance = column_types[i]

            yield dict(
                Field=column_name,
                Type=self._determine_type_name(column_type_instance),
            )

            for x in self.collect_members(column_type_instance, 1):
                yield x


class TestDescribe(testlib.SimpleTestCase):
    PARAMETERS = dict(commandline="describe pslist")
