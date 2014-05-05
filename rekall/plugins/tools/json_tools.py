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
from rekall import utils

class DecodingError(KeyError):
    """Raised if there is a decoding error."""


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


class AddressSpaceFormatter(StructFormatter):
    def __unicode__(self):
        return self.state["name"]


class NoneObjectFormatter(StructFormatter):
    def __unicode__(self):
        return "-"


class DatetimeFormatter(StructFormatter):
    def __unicode__(self):
        return time.ctime(self.state["epoch"])


class JSONParser(plugin.Command):
    """Renders a json rendering file, as produced by the JsonRenderer.

    The output of any plugin can be stored to a JSON file using:

    rekall -f img.dd --renderer JsonRenderer plugin_name --output test.json

    Then it can be rendered again using:

    rekall json_render test.json

    This plugin implements the proper decoding of the JSON encoded output.
    """

    name = "json_render"


    # This is a mapping between the semantic name of the BaseObject
    # serialization and a suitable Formatter. The idea is that the GUI framework
    # can identify semantically similar objects and map them to a rendering
    # class suitable for that specific type. For example, the same renderer
    # should work for all "Struct" semantic types, while a different one should
    # be applied to "DateTime" semantic types.
    semantic_map = dict(
        Literal=LiteralFormatter,
        Struct=StructFormatter,
        NativeType=LiteralFormatter,
        Pointer=LiteralFormatter,
        AddressSpace=AddressSpaceFormatter,
        NoneObject=NoneObjectFormatter,
        DateTime=DatetimeFormatter,
        )

    @classmethod
    def args(cls, parser):
        super(JSONParser, cls).args(parser)

        parser.add_argument("file", default=None,
                            help="The filename to parse.")

    def __init__(self, file=None, fd=None, **kwargs):
        super(JSONParser, self).__init__(**kwargs)
        self.lexicon = {}
        self.file = file
        self.fd = fd

    def _decode_value(self, value):
        if isinstance(value, dict):
            return self._decode(value)

        try:
            result = self.lexicon[str(value)]
            # Check if this is a string encoded as a list.
            if (isinstance(result, list) and
                len(result) == 2 and
                self.lexicon[str(result[1])] == 1):
                return self.lexicon[str(result[0])].decode("base64")

            return result
        except KeyError:
            raise DecodingError("Lexicon corruption: Tag %s" % value)

    def _decode(self, item):
        if not isinstance(item, dict):
            return self._decode_value(item)

        elif isinstance(item, str):
            return self._decode_value(item)

        state = {}
        for k, v in item.items():
            decoded_key = self._decode_value(k)
            decoded_value = self._decode_value(v)
            if isinstance(decoded_value, dict):
                decoded_value = self._decode(decoded_value)

            state[decoded_key] = decoded_value

        semantic_type = state.get("type")
        if semantic_type is None:
            return state

        item_renderer = self.semantic_map.get(semantic_type)
        if item_renderer is None:
            raise DecodingError("Unsupported Semantic type %s" % semantic_type)

        # Instantiate the BaseObject this refers to.
        return item_renderer(state)

    def RenderStatement(self, statement, renderer):
        """Renders one json decoded data command at a time."""
        command = statement[0]
        if command == "l":
            self.lexicon = statement[1]

        elif command == "m":
            renderer.section("Plugin %s" % statement[1]["plugin_name"])

        elif command == "s":
            renderer.section(**self._decode(statement[1]))

        elif command == "e":
            renderer.report_error(statement[1])

        elif command == "f":
            args = [self._decode(x) for x in statement[1:]]
            renderer.format(*args)

        elif command == "t":
            renderer.table_header(**statement[1])

        elif command == "r":
            renderer.table_row(
                *[self._decode(x) for x in statement[1]])

    def render(self, renderer):
        """Renders the stored JSON file using the default renderer.

        To decode the json file we replay the statements into the renderer after
        decompressing them.
        """
        if self.file:
            self.fd = open(self.file)

        if self.fd is None:
            raise ValueError("Need a filename or a file descriptor.")

        data = json.load(self.fd)

        for statement in data:
            self.RenderStatement(statement, renderer)
