#!/usr/bin/env python2

# Rekall Memory Forensics
# Copyright 2014 Google Inc. All Rights Reserved.
#
# Author: Michael Cohen scudette@google.com
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

"""Tools for manipulating json output.

When decoding json output, the decoder may not have access to the original
image. Therefore we can not simply recreate the original encoded objects
(because they will need to read from the original image). We must therefore
create a standin for these objects which looks similar to the original but is
able to be used directly - i.e. without reading the original image.
"""

__author__ = "Michael Cohen <scudette@google.com>"

import json
from rekall import plugin
from rekall import testlib

from rekall.ui import json_renderer


class JSONParser(plugin.TypedProfileCommand, plugin.Command):
    """Renders a json rendering file, as produced by the JsonRenderer.

    The output of any plugin can be stored to a JSON file using:

    rekall -f img.dd --format json plugin_name --output test.json

    Then it can be rendered again using:

    rekall json_render test.json

    This plugin implements the proper decoding of the JSON encoded output.
    """

    name = "json_render"

    __args = [
        dict(name="file", positional=True, required=True,
             help="The filename to parse.")
    ]

    def RenderStatement(self, statement, renderer):
        """Renders one json decoded data command at a time."""
        command = statement[0]
        options = {}
        if command == "l":
            self.json_renderer.decoder.SetLexicon(statement[1])

        elif command == "m":
            renderer.section("Plugin %s" % statement[1]["plugin_name"])

        elif command == "s":
            renderer.section(
                **self.json_renderer.decoder.Decode(statement[1], options))

        elif command == "e":
            renderer.report_error(statement[1])

        elif command == "f":
            args = [self.json_renderer.decoder.Decode(x, options)
                    for x in statement[1:]]
            renderer.format(*args)

        elif command == "t":
            renderer.table_header(columns=statement[1])

        elif command == "r":
            row = [self.json_renderer.decoder.Decode(x, options)
                   for x in statement[1]]
            renderer.table_row(*row, **options)

    def render(self, renderer):
        """Renders the stored JSON file using the default renderer.

        To decode the json file we replay the statements into the renderer after
        decompressing them.
        """
        # Make a json renderer to decode the json stream with.
        self.json_renderer = json_renderer.JsonRenderer(session=self.session)

        self.fd = renderer.open(filename=self.plugin_args.file, mode="rb")
        data = json.load(self.fd)

        for statement in data:
            self.RenderStatement(statement, renderer)


class TestJSONParser(testlib.SimpleTestCase):
    """Test the JSON renderer/parser."""
    PLUGIN = "json_render"

    PARAMETERS = dict(
        # The plugin to test json rendering with.
        commandline="pslist"
        )


    def BuildBaselineData(self, config_options):
        # We want to actually run the plugin first with JsonRenderer, then run
        # json_render on its json output - That will be the baseline.
        config_options["commandline"] = (
            "--format json -v --output %(tempdir)s_output.json " +
            config_options["commandline"])

        baseline = super(TestJSONParser, self).BuildBaselineData(config_options)

        output_file = self.temp_directory + "_output.json"
        config_options["commandline"] = "json_render %s" % output_file

        baseline = super(TestJSONParser, self).BuildBaselineData(config_options)
        return baseline
