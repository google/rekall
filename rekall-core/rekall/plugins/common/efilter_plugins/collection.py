# Rekall Memory Forensics
# Copyright 2017 Google Inc. All Rights Reserved.
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

"""Plugins for introspecting certain types of information.

This code is experimental and might be removed.
"""
import six

from rekall import obj
from rekall import plugin
from rekall import testlib

class TestFindPlugins(testlib.SimpleTestCase):
    PLUGIN = "which_plugin"
    PARAMETERS = dict(
        commandline="which_plugin %(struct)s",
        struct="proc"
    )


class TestCollect(testlib.SimpleTestCase):
    PLUGIN = "collect"
    PARAMETERS = dict(
        commandline="collect %(struct)s",
        struct="proc"
    )


class FindPlugins(plugin.TypedProfileCommand, plugin.ProfileCommand):
    """Find which plugin(s) are available to produce the desired output."""

    name = "which_plugin"

    type_name = None
    producers_only = False

    __args = [
        dict(name="type_name", required=True, positional=True,
             help="The name of the type we're looking for. "
             "E.g.: 'proc' will find psxview, pslist, etc."),

        dict(name="producers_only", required=False, type="Boolean",
             help="Only include producers: plugins that output "
             "only this struct and have no side effects.")
    ]

    def collect(self):
        if self.plugin_args.producers_only:
            pertinent_cls = plugin.Producer
        else:
            pertinent_cls = plugin.TypedProfileCommand

        for plugin_cls in six.itervalues(plugin.Command.classes):
            if not plugin_cls.is_active(self.session):
                continue

            if not issubclass(plugin_cls, pertinent_cls):
                continue

            table_header = plugin_cls.table_header
            if table_header:
                if isinstance(table_header, list):
                    table_header = plugin.PluginHeader(*table_header)

                try:
                    for t in table_header.types_in_output:
                        if (isinstance(t, type) and
                                self.plugin_args.type_name == t.__name__):
                            yield plugin_cls(session=self.session)
                        elif self.plugin_args.type_name == t:
                            yield plugin_cls(session=self.session)
                except plugin.Error:
                    # We were unable to instantiate this plugin to figure out
                    # what it wants to emit. We did our best so move on.
                    continue

    def render(self, renderer):
        renderer.table_header([
            dict(name="plugin", type="Plugin", style="compact", width=30)
        ])

        for command in self.collect():
            renderer.table_row(command)


class Collect(plugin.TypedProfileCommand, plugin.ProfileCommand):
    """Collect instances of struct of type 'type_name'.
    This plugin will find all other plugins that produce 'type_name' and merge
    all their output. For example, running collect 'proc' will give you a
    rudimentary psxview.
    This plugin is mostly used by other plugins, like netstat and psxview.
    """

    name = "collect"

    type_name = None

    __args = [
        dict(name="type_name", required=True, positional=True,
             help="The type (struct) to collect.")
    ]

    @classmethod
    def GetPrototype(cls, session):
        """Instantiate with suitable default arguments."""
        return cls(None, session=session)

    def collect(self):
        which = self.session.plugins.which_plugin(
            type_name=self.plugin_args.type_name,
            producers_only=True)

        results = {}
        for producer in which.collect():
            # We know the producer plugin implements 'produce' because
            # 'which_plugin' guarantees it.
            self.session.logging.debug("Producing %s from producer %r",
                                       self.type_name, producer)
            for result in producer.produce():
                previous = results.get(result.indices)
                if previous:
                    previous.obj_producers.add(producer.name)
                else:
                    result.obj_producers = set([producer.name])
                    results[result.indices] = result

        return six.itervalues(results)

    def render(self, renderer):
        renderer.table_header([
            dict(name=self.plugin_args.type_name,
                 type=self.plugin_args.type_name),
            dict(name="producers")
        ])

        for result in self.collect():
            renderer.table_row(result, tuple(sorted(result.obj_producers)))
