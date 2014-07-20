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


class JSONParser(plugin.Command):
    """Renders a json rendering file, as produced by the JsonRenderer.

    The output of any plugin can be stored to a JSON file using:

    rekall -f img.dd --renderer JsonRenderer plugin_name --output test.json

    Then it can be rendered again using:

    rekall json_render test.json

    This plugin implements the proper decoding of the JSON encoded output.
    """

    name = "json_render"


    @classmethod
    def args(cls, parser):
        super(JSONParser, cls).args(parser)

        parser.add_argument("file", default=None,
                            help="The filename to parse.")

    def __init__(self, file=None, fd=None, **kwargs):
        super(JSONParser, self).__init__(**kwargs)

        # Make a json renderer to decode the json stream with.
        self.json_renderer = json_renderer.JsonRenderer(session=self.session)

        self.file = file
        self.fd = fd

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
            renderer.table_header(**statement[1])

        elif command == "r":
            row = [self.json_renderer.decoder.Decode(x, options)
                   for x in statement[1]]
            renderer.table_row(*row, **options)

    def render(self, renderer):
        """Renders the stored JSON file using the default renderer.

        To decode the json file we replay the statements into the renderer after
        decompressing them.
        """
        if self.file:
            self.fd = renderer.open(filename=self.file, mode="rb")

        if self.fd is None:
            raise ValueError("Need a filename or a file descriptor.")

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
            "--renderer JsonRenderer --output %(tempdir)s_output.json " +
            config_options["commandline"])

        baseline = super(TestJSONParser, self).BuildBaselineData(config_options)

        output_file = self.temp_directory + "_output.json"
        config_options["commandline"] = "json_render %s" % output_file

        baseline = super(TestJSONParser, self).BuildBaselineData(config_options)
        return baseline


class Sampler(object):
    handlers = {}

    def __init__(self, f):
        self.f = f
        Sampler.handlers[f.__name__] = f

    def __call__(self):
        self.f()


class RenderingSampler(plugin.Command):
    name = "render_sample"

    @classmethod
    def args(cls, parser):
        super(RenderingSampler, cls).args(parser)

        parser.add_argument("sample", choices=Sampler.handlers.keys(),
                            help="Sample to render.")

    @Sampler
    def Nothing(self, renderer):
        _ = renderer

    @Sampler
    def Format(self, renderer):
        renderer.format("This is a formatted string: %s %d %s", "foo", 42,
                        "bar")

    @Sampler
    def UnnamedSection(self, renderer):
        renderer.section()

    @Sampler
    def NamedSection(self, renderer):
        renderer.section("Named Section")

    @Sampler
    def OneRowTable(self, renderer):
        renderer.table_header([('Parameter', 'parameter', '30'),
                               (' Documentation', 'doc', '70')])
        renderer.table_row("important-parameter", 42)

    def __init__(self, sample=None, **kwargs):
        super(RenderingSampler, self).__init__(**kwargs)

        if sample is None:
            raise ValueError("sample argument can't be None")
        self.sample = sample

    def render(self, renderer):
        Sampler.handlers[self.sample](self, renderer)
