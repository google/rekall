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

This code is tested in plugins/tools/render_test.py
"""

import json
import sys

from rekall import addrspace
from rekall import constants
from rekall import obj
from rekall import utils
from rekall.ui import renderer


class DecodingError(KeyError):
    """Raised if there is a decoding error."""


class JsonEncoder(object):
    def __init__(self):
        self.lexicon = {}
        self.reverse_lexicon = {}
        self.lexicon_counter = 0

    def GetLexicon(self):
        return self.reverse_lexicon

    def flush(self):
        self.lexicon.clear()
        self.reverse_lexicon.clear()
        self.lexicon_counter = 0

    def _encode_value(self, value):
        if value.__class__ is dict:
            return self.Encode(value)

        # If value is a serializable object, we can store it by id in the
        # lexicon.
        if hasattr(value, "__getstate__"):
            value_id = id(value)

            encoded_value_id = self.lexicon.get(value_id)

            # The hash of the object is not in the lexicon.
            if encoded_value_id is None:
                # Create a new ID to encode the new object under.
                encoded_value_id = self._get_encoded_id(value_id)
                encoded_value = self.Encode(value.__getstate__())

                # Store the object under this new ID.
                self.reverse_lexicon[encoded_value_id] = encoded_value

            return encoded_value_id

        return self._get_encoded_id(value)

    def _get_encoded_id(self, value):
        encoded_id = self.lexicon.get(value)
        if encoded_id is None:
            self.lexicon_counter += 1
            encoded_id = str(self.lexicon_counter)
            self.lexicon[value] = encoded_id
            self.reverse_lexicon[encoded_id] = value

        return encoded_id

    def Encode(self, item):
        if item == None:
            return None

        # If it is a state dict we just use it as is.
        if item.__class__ is dict:
            state = item

        # Mark encoded lists so we know they are encoded.
        elif isinstance(item, list):
            return ["_"] + [self._encode_value(x) for x in item]

        # If value is a serializable object, we can store it by id in the
        # lexicon.
        elif hasattr(item, "__getstate__"):
            state = item.__getstate__()

        # Encode json safe items literally.
        elif isinstance(item, (unicode, int, long, float)):
            return self._get_encoded_id(item)

        # JSON can not encode raw strings so we must base64 escape them. We
        # encode a bare string as a list starting with "+".
        elif isinstance(item, str):
            b64 = unicode(item.encode("base64")).rstrip("\n")
            return ["+", self._encode_value(b64)]

        elif item.__class__ is set:
            state = dict(
                type="set",
                data=list(item))

        else:
            raise RuntimeError("Unable to encode objects of type %s" %
                               type(item))

        # Mark encoded dicts so we know they are encoded.
        result = {"_": 1}
        for k, v in state.items():
            result[self._encode_value(k)] = self.Encode(v)

        return result


class _Empty(object):
    """An empty class to access the real instance later."""
    def __init__(self, session):
        self.session = session


class JsonDecoder(object):
    """A Decoder for JSON encoded data."""

    def __init__(self, session):
        self.session = session
        self.lexicon = {}

    def SetLexicon(self, lexicon):
        self.lexicon = lexicon

    def Factory(self, state):
        """Parses the state dict into an object."""
        # Determine which registry it comes from.
        registry = state.pop('registry', None)
        obj_type = state.pop("type", None)

        # If this has no type its just a regular encoded dict.
        if not registry and not obj_type:
            return state

        result = _Empty(session=self.session)

        # This is an address space object.
        if registry == "BaseAddressSpace":
            cls = addrspace.BaseAddressSpace.classes[obj_type]

            # Change the type of the result to this class.
            result.__class__ = cls

            # Now call the class's __setstate__ method to initialize it. Note
            # this does not call the constructor.
            result.__setstate__(state)

        # Structs are fetched from the profile.
        elif registry == "BaseObject":
            state["profile"] = self.session.LoadProfile(state["profile"])

            result = state["profile"].Object(**state)

        elif obj_type == "AttributeDict":
            result = utils.AttributeDict()
            result.__setstate__(state)

        elif registry == "Profile":
            result = self.session.LoadProfile(state["name"])

        elif obj_type == "set":
            result = set(state["data"])

        elif obj_type == "NoneObject":
            result = obj.NoneObject(state["reason"])

        else:
            raise DecodingError("Unable to decode objects of type %s" %
                                obj_type)

        return result

    def _decode_value(self, value):
        if value == None:
            return None

        if value.__class__ is dict:
            return self.Decode(value)

        elif value.__class__ is list:
            # Decode marked lists.
            if value[0] == "_":
                return [self._decode_value(x) for x in value[1:]]
            elif value[0] == "+":
                return self.lexicon[value[1]].decode("base64")

        try:
            result = self.lexicon[str(value)]

            return result
        except KeyError:
            raise DecodingError("Lexicon corruption: Tag %s" % value)

    def Decode(self, item):
        if item.__class__ is dict:
            # Encoded dicts are marked with a key "_" so we can tell the
            # difference between an encoded dict and one that is not encoded.
            if item.pop("_", None):
                state = {}
                for k, v in item.items():
                    decoded_key = self._decode_value(k)
                    decoded_value = self._decode_value(v)
                    if decoded_value.__class__ is dict:
                        decoded_value = self.Decode(decoded_value)

                    state[decoded_key] = decoded_value

                return self.Factory(state)

            return item

        return self._decode_value(item)


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

    def __init__(self, output=None, **kwargs):
        super(JsonRenderer, self).__init__(**kwargs)

        # Allow the user to dump all output to a file.
        self.output = output or self.session.GetParameter("output")

        fd = None
        if self.output:
            # This overwrites the output file with a new json message.
            fd = open(self.output, "wb")

        if fd is None:
            fd = self.session.fd

        if fd is None:
            fd = sys.stdout

        self.fd = fd
        self.encoder = JsonEncoder()

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

    def format(self, formatstring, *args):
        statement = ["f", self.encoder.Encode(formatstring)]
        for arg in args:
            # Just store the statement in the output.
            statement.append(self.encoder.Encode(arg))

        self.SendMessage(statement)

    def section(self, name=None, **kwargs):
        kwargs["name"] = name
        self.SendMessage(["s", self.encoder.Encode(kwargs)])

    def report_error(self, message):
        self.SendMessage(["e", message])

    def table_header(self, columns=None, **kwargs):
        # TODO: Remove this when all calls are done with kwargs.
        kwargs["columns"] = columns

        self.SendMessage(["t", kwargs])

    def table_row(self, *args, **kwargs):
        self.SendMessage(
            ["r", [self.encoder.Encode(x) for x in args], kwargs])

    def write_data_stream(self):
        if self.data:
            # Just dump out the json object.
            self.fd.write(json.dumps(self.data, separators=(',', ':')))
            self.fd.flush()

    def flush(self):
        self.write_data_stream()
        self.encoder.flush()

        # We store the data here.
        self.data = []

        # NOTE: The lexicon will continue to be modified, but will be sent as
        # part of the first statement.
        self.SendMessage(["l", self.encoder.GetLexicon()])

    def RenderProgress(self, message=" %(spinner)s", *args, **kwargs):
        if super(JsonRenderer, self).RenderProgress(**kwargs):
            self.SendMessage(["p", message, args, kwargs])
