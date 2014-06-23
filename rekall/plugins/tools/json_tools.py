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

"""Tools for manipulating json output."""

__author__ = "Michael Cohen <scudette@google.com>"

import json
import time
from rekall import plugin
from rekall import testlib
from rekall import utils


from rekall.ui import json_renderer


class StructFormatter(object):
    def __init__(self, state):
        self.state = state

    def __int__(self):
        return self.state["offset"]


class LiteralFormatter(StructFormatter):
    def __unicode__(self):
        return utils.SmartUnicode(self.state["value"])

    def __int__(self):
        return self.state["value"]

    def __float__(self):
        return float(self.state["value"])


class EnumFormatter(StructFormatter):
    def __unicode__(self):
        return utils.SmartUnicode(self.state["repr"])

    def __int__(self):
        return self.state["value"]


class AddressSpaceFormatter(StructFormatter):
    def __unicode__(self):
        return self.state["name"]


class NoneObjectFormatter(StructFormatter):
    def __unicode__(self):
        return "-"


class DatetimeFormatter(StructFormatter):
    def __unicode__(self):
        return time.ctime(float(self.state["epoch"]))


class RendererCombiner(object):
    def __init__(self):
        self.children = []

    def AddRenderer(self, child):
        self.children.append(child)

    def _FirstOf(self, method):
        # First child with the method wins.
        for child in self.children:
            try:
                return getattr(child, method)()
            except AttributeError:
                continue

    def __int__(self):
        return self._FirstOf("__int__")

    def __float__(self):
        return self._FirstOf("__float__")

    def __len__(self):
        return len(self.children)

    def __unicode__(self):
        return self._FirstOf("__unicode__")


class RendererDecoder(json_renderer.JsonDecoder):
    """A decoder which produces proxy objects for the real thing.

    This is suitable to be run with no access to the real image, we simply use
    the proxy objects to render the available data in a type specific way.
    """

    COMBINER = RendererCombiner

    # This is a mapping between the semantic name of the BaseObject
    # serialization and a suitable Formatter. The idea is that the GUI framework
    # can identify semantically similar objects and map them to a rendering
    # class suitable for that specific type. For example, the same renderer
    # should work for all "Struct" semantic types, while a different one should
    # be applied to "DateTime" semantic types.
    semantic_map = dict(
        Enumeration=EnumFormatter,
        Struct=StructFormatter,
        BaseObject=LiteralFormatter,
        NativeType=LiteralFormatter,
        Pointer=LiteralFormatter,
        BaseAddressSpace=AddressSpaceFormatter,
        NoneObject=NoneObjectFormatter,
        UnixTimeStamp=DatetimeFormatter,
        )

    def Factory(self, state):
        # Try to find a class to wrap the type with. We traverse the object's
        # MRO and try to find a specialized formatter for each type.
        mro = state.get("type")
        if not mro:
            return state

        result = self.COMBINER()
        for semantic_type in mro.split(","):
            item_renderer = self.semantic_map.get(semantic_type)
            if item_renderer is not None:
                result.AddRenderer(item_renderer(state))

        if not result:
            # If we get here we have no idea how to render this object. Maybe we
            # should have a default renderer?
            raise json_renderer.DecodingError(
                "Unsupported Semantic type %s" % mro)

        return result


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
        self.decoder = RendererDecoder(session=self.session)
        self.file = file
        self.fd = fd

    def RenderStatement(self, statement, renderer):
        """Renders one json decoded data command at a time."""
        command = statement[0]
        if command == "l":
            self.decoder.SetLexicon(statement[1])

        elif command == "m":
            renderer.section("Plugin %s" % statement[1]["plugin_name"])

        elif command == "s":
            renderer.section(**self.decoder.Decode(statement[1]))

        elif command == "e":
            renderer.report_error(statement[1])

        elif command == "f":
            args = [self.decoder.Decode(x) for x in statement[1:]]
            renderer.format(*args)

        elif command == "t":
            renderer.table_header(**statement[1])

        elif command == "r":
            renderer.table_row(
                *[self.decoder.Decode(x) for x in statement[1]])

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
