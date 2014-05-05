# Rekall Memory Forensics
# Copyright (C) 2012 Michael Cohen
# Copyright 2014 Google Inc. All Rights Reserved.
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

"""This module implements a JSON render.

A renderer is used by plugins to produce formatted output.
"""

import json

from rekall import constants
from rekall.ui import renderer


class JsonRenderer(renderer.BaseRenderer):
    """Render the output as a json object.

    The JSON output is designed to be streamed to a remote end - that is results
    are sent incrementally as soon as they are available. The receiver can then
    process the results as they come, rendering them to screen or GUI.

    The data is essentially a list of commands.

    Each command is a list. The first parameter is the command name, further
    parameters are the args to the command.

    Currently the following commands are supported:

    l: Reset the lexicon. Followed by a lexicon dict. Following entries will be
       decoded with this lexicon.

    m: This is a metadata, followed by a dict of various metadata.

    s: Start a new section. Followed by section name.

    f: A free format text line. Followed by format string and a list of
       parameters. Parameters are dicts encoded using the lexicon.

    t: Start a new table. Followed by Table headers. Followed by a list of lists
       (human_name, name, formatstring).

    r: A table row. Followed by a list of dicts for each row cell. Each row cell
       is encoded using the lexicon for both keys and values.

    p: A progress message. Followed by a single string which is the formatted
       message.
    """

    progress_interval = 1

    # This will hold a list of JSON commands to buffer them before they are
    # written to the json file.
    data = None

    def start(self, plugin_name=None, kwargs=None):
        super(JsonRenderer, self).start(plugin_name=plugin_name, kwargs=kwargs)
        self.flush()

        # Save some metadata.
        self.SendMessage(
            ["m", dict(plugin_name=plugin_name,
                       tool_name="rekall",
                       tool_version=constants.VERSION,
                       )])

        return self

    def SendMessage(self, statement):
        self.data.append(statement)

    def _encode_value(self, value):
        if isinstance(value, dict):
            return self._encode(value)

        if isinstance(value, str):

            encoded_id = self.lexicon.get(value)
            b64 = unicode(value.encode("base64")).rstrip("\n")

            # The hash of the object is not in the lexicon.
            if encoded_id is None:
                # Create a new ID to store the list encoded string.
                encoded_id = self.lexicon_counter = self.lexicon_counter + 1
                # Store the list encoded string under this new ID.
                self.reverse_lexicon[encoded_id] = self._encode([b64, 1])

                # Also add a shortcut reference original value -> encoded list.
                self.lexicon[value] = encoded_id

            return encoded_id

        # If value is a serializable object, we can store it by id in the
        # lexicon.
        if hasattr(value, "__getstate__"):
            value_id = id(value)

            encoded_value_id = self.lexicon.get(value_id)

            # The hash of the object is not in the lexicon.
            if encoded_value_id is None:
                # Create a new ID to encode the new object under.
                encoded_value_id = self._get_encoded_id(value_id)
                encoded_value = self._encode(value.__getstate__())

                # Store the object under this new ID.
                self.reverse_lexicon[encoded_value_id] = encoded_value

            return encoded_value_id

        return self._get_encoded_id(value)

    def _get_encoded_id(self, value):
        encoded_id = self.lexicon.get(value)
        if encoded_id is None:
            encoded_id = self.lexicon_counter = self.lexicon_counter + 1
            self.lexicon[value] = encoded_id
            self.reverse_lexicon[encoded_id] = value

        return encoded_id

    def _encode(self, item):
        # If it is a state dict we just use it as is.
        if isinstance(item, dict):
            state = item

        elif isinstance(item, list):
            return [self._encode_value(x) for x in item]

        # If value is a serializable object, we can store it by id in the
        # lexicon.
        elif hasattr(item, "__getstate__"):
            state = item.__getstate__()

        # Encode json safe items literally.
        elif isinstance(item, (unicode, int, long, float)):
            return self._get_encoded_id(item)

        elif isinstance(item, str):
            return self._encode_value(item)

        else:
            raise RuntimeError("Unable to encode objects of type %s" %
                               type(item))

        result = {}
        for k, v in state.items():
            result[self._encode_value(k)] = self._encode_value(v)

        return result

    def format(self, formatstring, *args):
        statement = ["f", self._encode(formatstring)]
        for arg in args:
            # Just store the statement in the output.
            statement.append(self._encode(arg))

        self.SendMessage(statement)

    def section(self, name=None, **kwargs):
        kwargs["name"] = name
        self.SendMessage(["s", self._encode(kwargs)])

    def report_error(self, message):
        self.SendMessage(["e", message])

    def table_header(self, columns=None, **kwargs):
        # TODO: Remove this when all calls are done with kwargs.
        kwargs["columns"] = columns

        self.SendMessage(["t", kwargs])

    def table_row(self, *args, **kwargs):
        self.SendMessage(["r", [self._encode(x) for x in args], kwargs])

    def write_data_stream(self):
        if self.data:
            # Just dump out the json object.
            self.fd.write(json.dumps(self.data, separators=(',', ':')))
            self.fd.flush()

    def flush(self):
        self.write_data_stream()

        self.lexicon = {}
        self.reverse_lexicon = {}
        self.lexicon_counter = 0

        # We store the data here.
        self.data = []

        # NOTE: The lexicon will continue to be modified, but will be sent as
        # port of the first statement.
        self.SendMessage(["l", self.reverse_lexicon])

    def _RenderProgress(self, message):
        self.SendMessage(["p", message])
