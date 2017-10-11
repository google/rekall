# Rekall Memory Forensics
# Copyright (C) 2016 Michael Cohen
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

"""Rekall specifies an external API where plugins can be invoked."""
from past.builtins import basestring
import copy
import six
import textwrap

from rekall import config
from rekall import plugin
from rekall_lib import yaml_utils


class APIGenerator(plugin.TypedProfileCommand,
                   plugin.Command):
    """Generate the plugin API document."""
    name = "api"

    __args = [
        dict(name="output_file",
             help="If specified we write the API into this file in YAML."),
    ]

    table_header = [
        dict(name="plugin", width=40),
        dict(name="api", width=80),
        dict(name="raw_api", hidden=True),
    ]

    def get_active_modes(self, cls):
        """Calculate the declared modes under which the plugin is active."""
        modes = set()
        for subclass in cls.__mro__:
            mode = getattr(subclass, "mode", None)

            if isinstance(mode, basestring):
                modes.add(mode)

            elif isinstance(mode, (list, tuple)):
                modes.update(mode)

        return sorted(modes)

    def get_command_dict(self, option):
        """Describes CommandOption instance as a dict."""
        result = yaml_utils.OrderedYamlDict(type=option.type)
        for attr in ["default", "choices", "help"]:
            value = getattr(option, attr, None)
            if value is not None:
                result[attr] = copy.copy(value)

        for attr in ["positional", "required", "hidden"]:
            value = getattr(option, attr, False)
            if value:
                result[attr] = copy.copy(value)

        return result

    def get_plugin_args(self, cls):
        """Collects the args from the plugin."""
        args = yaml_utils.OrderedYamlDict()
        for subclass in cls.__mro__:
            for definition in getattr(
                    subclass, "_%s__args" % subclass.__name__, []):
                # Definitions can be just simple dicts.
                if isinstance(definition, dict):
                    definition = plugin.CommandOption(**definition)

                # We have seen this arg before.
                previous_definition = args.get(definition.name)
                if previous_definition:
                    # Since we traverse the definition in reverse MRO order,
                    # later definitions should be masked by earlier (more
                    # derived) definitions.
                    continue

                args[definition.name] = self.get_command_dict(definition)

        return args

    def _clean_up_doc(self, doc):
        title = body = ""
        doc = doc.strip()
        if doc:
            lines = doc.splitlines()
            title = lines[0]
            if len(lines) > 1:
                body = "\n".join(lines[1:])
                body = textwrap.dedent(body)

        return "%s\n%s" % (title, body)

    def generate_api(self):
        # All plugins are registered with the base plugin.
        for plugin_name, cls in sorted(six.iteritems(self.classes)):
            if not cls.name:
                continue

            docstring = self._clean_up_doc(
                cls.__doc__ or cls.__init__.__doc__ or "")

            # Control the order of entries in the yaml file.
            result = yaml_utils.OrderedYamlDict()
            result["plugin"] = plugin_name
            result["name"] = cls.name
            result["description"] = docstring
            args = self.get_plugin_args(cls)
            if args:
                result["args"] = args

            result["active_modes"] = self.get_active_modes(cls)

            yield result

    def collect(self):
        apis = []
        for plugin_api in self.generate_api():
            apis.append(plugin_api)
            yield dict(plugin=plugin_api["plugin"],
                       api=yaml_utils.safe_dump(plugin_api),
                       raw_api=plugin_api)

        if self.plugin_args.output_file:
            with open(self.plugin_args.output_file, "wb") as fd:
                fd.write(yaml_utils.safe_dump(apis))


class APISessionGenerator(APIGenerator):
    name = "session_api"

    table_header = [
        dict(name="option", width=40),
        dict(name="api", width=80),
        dict(name="raw_api", hidden=True),
    ]

    def collect(self):
        apis = []
        for option, api in six.iteritems(config.OPTIONS.args):
            for k, v in list(api.items()):
                if callable(v):
                    api[k] = v()

            apis.append(api)
            yield dict(option=option,
                       api=yaml_utils.safe_dump(api),
                       raw_api=api)

        if self.plugin_args.output_file:
            with open(self.plugin_args.output_file, "wb") as fd:
                fd.write(yaml_utils.safe_dump(apis))
