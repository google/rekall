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
import copy
import json
import pdb
import sys

from rekall import constants
from rekall import utils
from rekall.ui import renderer as renderer_module


class DecodingError(KeyError):
    """Raised if there is a decoding error."""


class EncodingError(KeyError):
    """Raised if we can not encode the object properly."""


class RobustEncoder(json.JSONEncoder):
    def __init__(self, logging=None, **_):
        super(RobustEncoder, self).__init__(separators=(',', ':'))
        if logging is None:
            self.logging = None
        else:
            self.logging = logging.getChild("json.encoder.robust")

    def default(self, o):
        if self.logging:
            self.logging.error(
                "Unable to encode %r (%s) as json, replacing with None", o,
                type(o))
        return None


def CacheableState(func):
    """A decorator which caches objects in the renderer's LRU.

    This applies to StateBasedObjectRenderer state dicts, which must have a
    unique id member.
    """

    def DecodeFromJsonSafe(self, value, options):
        obj_id = None
        try:
            obj_id = value.get("id")
            result = self.renderer.cache.Get(obj_id)
        except KeyError:
            result = func(self, value, options)
            if obj_id is not None:
                self.renderer.cache.Put(obj_id, result)

        return result

    return DecodeFromJsonSafe


class JsonObjectRenderer(renderer_module.ObjectRenderer):
    """An ObjectRenderer for Json encoding.

    For the JsonRenderer we convert objects into json safe python primitives
    (These must be json serializable).
    """
    renderers = ["JsonRenderer"]

    @classmethod
    def cache_key_from_object(cls, item):
        """Get the cache key from the object."""
        try:
            return item._object_id  # pylint: disable=protected-access
        except AttributeError:
            # For unregistered objects we can not cache them (Note: The python
            # id() method is useless because it does not actually guarantee
            # unique id.).
            return None

    @classmethod
    def FromEncoded(cls, item, renderer):
        """Get an JsonObjectRenderer class to parse the encoded item."""
        if isinstance(item, dict):
            obj_renderer = item.get("obj_renderer")
            if obj_renderer is not None:
                return cls.ImplementationByClass(obj_renderer)

            mro = item.get("mro")
            if mro is not None:
                return cls.FromMRO(mro, renderer)

        return cls.ForTarget(item, renderer)

    @staticmethod
    def GetImplementationFromMRO(base_class, value):
        """Get the class referred to by the head of the value's MRO."""
        class_name = value["mro"].split(":")[0]

        for cls in base_class.__subclasses__():
            if class_name == cls.__name__:
                return cls

    def _encode_value(self, item, **options):
        object_renderer_cls = self.ForTarget(item, self.renderer)

        result = object_renderer_cls(
            session=self.session,
            renderer=self.renderer).EncodeToJsonSafe(item, **options)

        return result

    def _decode_value(self, item, options):
        object_renderer_cls = self.FromEncoded(item, self.renderer)

        return object_renderer_cls(
            session=self.session,
            renderer=self.renderer).DecodeFromJsonSafe(item, options)

    def render_row(self, item, **options):
        """The Json object renderer returns a json safe object for encoding."""
        self.EncodeToJsonSafe(item, **options)

    def Summary(self, item, **options):
        """Returns the object formatted as a string."""
        _ = item
        _ = options
        return ""

    def EncodeToJsonSafe(self, item, **options):
        """Convert the item into a JSON safe item.

        JSON is only capable of encoding some simple types (dict, list, int,
        float, unicode strings etc). This method is called to convert the item
        to one of these representations. Note that this method will be called on
        the ObjectRenderer instance with a renders_type attribute which appears
        on the item's MRO.

        Args:
          item: A python object derived from the class mentioned in the
            renders_type attribite.

        Returns:
          A JSON serializable object (e.g. dict, list, unicode string etc).
        """
        if item == None:
            return None

        # If it is a plain dict we just use it as is.
        elif item.__class__ is dict:
            # Assume keys are strings.
            result = {}
            for k, v in item.items():
                result[k] = self._encode_value(v, **options)

            return result

        # Mark encoded lists so we know they are encoded.
        elif isinstance(item, list):
            return list(self._encode_value(x, **options) for x in item)

        elif isinstance(item, tuple):
            return tuple(self._encode_value(x, **options) for x in item)

        # Encode json safe items literally.
        if isinstance(item, (unicode, int, long, float)):
            return item

        # This will encode unknown objects as None. We do not raise an error
        # here in order to succeed in the encoding of arbitrary data. For
        # example, the session object may contain all kinds of unserializable
        # objects but we want to ensure we can serialize the session (albeit
        # with the loss of some of the attributes).
        self.session.logging.error(
            "Unable to encode objects of type %s", type(item))
        if "strict" in options:
            raise EncodingError(
                "Unable to encode objects of type %s" % type(item))

        return None

    def DecodeFromJsonSafe(self, value, options):
        """Decode the item from its Json safe representation.

        This should essentially be the reverse of EncodeToJsonSafe(). Each
        ObjectRenderer class should implement this method to invert
        EncodeToJsonSafe().

        Args:
          value: The json safe object to decode.
          options: A dict which will receive any options encoded by the encoder.

        Returns:
          A python object.
        """
        if value == None:
            return None

        if value.__class__ is dict:
            result = dict()
            for k, v in value.iteritems():
                result[k] = self._decode_value(v, options)

            return result

        if value.__class__ is list:
            return list(self._decode_value(x, options) for x in value)

        if value.__class__ is tuple:
            return tuple(self._decode_value(x, options) for x in value)

        # Decode json safe items literally.
        if isinstance(value, (unicode, int, long, float)):
            return value

        return value


class StateBasedObjectRenderer(JsonObjectRenderer):
    """An object renderer which serializes an object to a dict."""
    renders_type = ""  # Baseclass - does not act by itself.

    @classmethod
    def cache_key(cls, item):
        """Get the decoding cache key from the json safe encoding."""
        return item.get("id")

    def GetState(self, item, **_):
        _ = item
        return {}

    @CacheableState
    def DecodeFromJsonSafe(self, value, options):
        value.pop("id", None)
        return super(StateBasedObjectRenderer, self).DecodeFromJsonSafe(
            value, options)

    def EncodeToJsonSafe(self, item, details=False, **options):
        state = self.GetState(item, **options)
        if state.__class__ is not dict:
            raise EncodingError(
                "%s.GetState method must return a plain dict." %
                self.__class__.__name__)

        # Store the mro of the item.
        if not "mro" in state:
            # Respect what the object renderer asserts about the object's MRO
            # (mainly to make delegation work).
            state["mro"] = ":".join(self.get_mro(item))

        # Store an object ID for this item to ensure that the decoder can re-use
        # objects if possible. The ID is globally unique for this object and
        # does not change.
        try:
            object_id = item._object_id  # pylint: disable=protected-access
            state["id"] = object_id
        except AttributeError:
            pass

        # Add the details view if required.
        if details:
            state["details"] = unicode(repr(item))

        return super(StateBasedObjectRenderer, self).EncodeToJsonSafe(
            state, **options)


class StringRenderer(StateBasedObjectRenderer):
    # Json is not able to encode strings, we therefore must implement a proper
    # encoder/decoder.
    renders_type = "str"

    def DecodeFromJsonSafe(self, value, options):
        result = value.get("str")
        if result is None:
            result = value.get("b64").decode("base64")
        else:
            return result.encode("utf8")

        return result

    def GetState(self, item, **_):
        try:
            # If the string happens to be unicode safe we dont need to
            # encode it, but we still must mark it with a "*" to ensure the
            # decoder replaces it with a plain string.
            return dict(str=unicode(item, "utf8"))
        except UnicodeError:
            # If we failed to encode it into utf8 we must base64 encode it.
            return dict(b64=unicode(item.encode("base64")).rstrip("\n"))

    def EncodeToJsonSafe(self, item, **options):
        # In many cases we receive a string but it can be represented as unicode
        # object. To make it easier all round its better to continue handling it
        # as a unicode object for JSON purposes.
        try:
            return item.decode("utf8", "strict")
        except UnicodeError:
            return super(StringRenderer, self).EncodeToJsonSafe(
                item, **options)


class BaseObjectRenderer(StateBasedObjectRenderer):
    renders_type = "BaseObject"

    @CacheableState
    def DecodeFromJsonSafe(self, value, options):
        value = super(BaseObjectRenderer, self).DecodeFromJsonSafe(
            value, options)

        profile = value.pop("profile", None)
        value.pop("mro", None)

        return profile.Object(**value)

    def GetState(self, item, **_):
        return dict(offset=item.obj_offset,
                    type_name=unicode(item.obj_type),
                    name=unicode(item.obj_name),
                    vm=item.obj_vm,
                    profile=item.obj_profile)


class JSTreeNodeRenderer(StateBasedObjectRenderer):
    renders_type = "TreeNode"

    def DecodeFromJsonSafe(self, state, options):
        state = super(JSTreeNodeRenderer, self).DecodeFromJsonSafe(
            state, options)

        result = state.pop("child")
        options.update(state)

        return result

    def GetState(self, item, **options):
        result = options
        result["child"] = item
        result["type_name"] = u"TreeNode"

        return result


class JsonEncoder(object):
    def __init__(self, session=None, renderer=None):
        self.renderer = renderer
        self.session = session

        self.cache = utils.FastStore(100)

    def Encode(self, item, **options):
        """Convert item to a json safe object."""
        # Get a Json Safe item.
        object_renderer = JsonObjectRenderer.ForTarget(item, self.renderer)(
            session=self.session, renderer=self.renderer)

        # First check the cache.
        cache_key = object_renderer.cache_key_from_object(item)
        try:
            # The contents of this cache are guaranteed to be json safe so we
            # can copy them.
            if cache_key is not None:
                return copy.deepcopy(self.cache.Get(cache_key))
        except KeyError:
            pass

        json_safe_item = object_renderer.EncodeToJsonSafe(item, **options)

        self.cache.Put(cache_key, json_safe_item)
        return json_safe_item


class _Empty(object):
    """An empty class to access the real instance later."""

    def __init__(self, session):
        self.session = session


class JsonDecoder(object):
    """A Decoder for JSON encoded data."""

    def __init__(self, session, renderer):
        self.session = session
        self.renderer = renderer

    def Decode(self, item, options=None):
        if options is None:
            options = {}

        # Find the correct ObjectRenderer that we can use to decode this item.
        object_renderer_cls = None
        if isinstance(item, dict):
            obj_renderer = item.get("obj_renderer")
            if obj_renderer is not None:
                object_renderer_cls = JsonObjectRenderer.ImplementationByClass(
                    obj_renderer)

            else:
                mro = item.get("mro")
                if mro is not None:
                    object_renderer_cls = JsonObjectRenderer.FromMRO(
                        mro, self.renderer)

        if object_renderer_cls is None:
            object_renderer_cls = JsonObjectRenderer.ForTarget(
                item, self.renderer)

        object_renderer = object_renderer_cls(
            session=self.session,
            renderer=self.renderer)

        key = object_renderer_cls.cache_key(item)
        if key is None:
            return object_renderer.DecodeFromJsonSafe(item, options)

        try:
            result = self.renderer.cache.Get(key)
        except KeyError:
            try:
                result = object_renderer.DecodeFromJsonSafe(item, options)
            except Exception as e:
                pdb.post_mortem()

                self.session.logging.error(
                    "Failed to decode %s: %s", repr(item)[:1000], e)
                if self.session.GetParameter("debug"):
                    pdb.post_mortem()

                result = None

            self.renderer.cache.Put(key, result)

        return result


class JsonRenderer(renderer_module.BaseRenderer):
    """Render the output as a json object.

    The JSON output is designed to be streamed to a remote end - that is results
    are sent incrementally as soon as they are available. The receiver can then
    process the results as they come, rendering them to screen or GUI.

    The data is essentially a list of commands.

    Each command is a list. The first parameter is the command name, further
    parameters are the args to the command.

    Currently the following commands are supported:

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

    L: Log message sent via session.logging logger.
    """

    name = "json"

    progress_interval = 1

    # This will hold a list of JSON commands to buffer them before they are
    # written to the json file.
    data = None

    spinner = r"/-\|"
    last_spin = 0

    def __init__(self, output=None, send_message_callback=None, **kwargs):
        super(JsonRenderer, self).__init__(**kwargs)

        self.send_message_callback = send_message_callback

        # Allow the user to dump all output to a file.
        self.output = output

        # This keeps a list of object renderers which we will use for each
        # column.
        self.object_renderers = []

        fd = None
        if self.output:
            if hasattr(self.output, "write") and hasattr(self.output, "flush"):
                fd = self.output
            else:
                # This overwrites the output file with a new json message.
                fd = open(self.output, "wb")

        if fd == None:
            fd = self.session.fd

        if fd == None:
            fd = sys.stdout

        self.fd = fd
        self.encoder = JsonEncoder(session=self.session, renderer=self)
        self.decoder = JsonDecoder(session=self.session, renderer=self)

        # A general purpose cache for encoders and decoders.
        self.cache = utils.FastStore(100)
        self.data = []

    def start(self, plugin_name=None, kwargs=None):
        super(JsonRenderer, self).start(plugin_name=plugin_name, kwargs=kwargs)

        # Save some metadata.
        self.metadata = dict(plugin_name=unicode(plugin_name),
                             tool_name="rekall",
                             cookie=self._object_id,
                             tool_version=constants.VERSION,
                             session=self.encoder.Encode(self.session))
        self.SendMessage(
            ["m", self.metadata])

        return self

    def SendMessage(self, statement):
        self.data.append(statement)

    def format(self, formatstring, *args):
        statement = ["f", unicode(formatstring)]
        for arg in args:
            # Just store the statement in the output.
            statement.append(self.encoder.Encode(arg))

        self.SendMessage(statement)

    def section(self, name=None, **kwargs):
        kwargs["name"] = name
        self.SendMessage(["s", self.encoder.Encode(kwargs)])

    def report_error(self, message):
        self.SendMessage(["e", message])

    def table_header(self, columns=None, **options):
        super(JsonRenderer, self).table_header(columns=columns, **options)

        self.object_renderers = [
            column_spec.get("type") for column_spec in self.table.column_specs]

        self.SendMessage(["t", self.table.column_specs, options])

    def table_row(self, *args, **kwargs):
        result = []
        for i, arg in enumerate(args):
            result.append(self.encoder.Encode(
                arg, type=self.object_renderers[i]))

        self.SendMessage(["r", result, kwargs])

    def write_data_stream(self):
        if self.data:
            # Just dump out the json object.
            self.fd.write(json.dumps(self.data, cls=RobustEncoder,
                                     separators=(',', ':'),
                                     logging=self.session.logging))
            self.fd.flush()

    def flush(self):
        self.write_data_stream()

        # We store the data here.
        self.data = []

    def end(self):
        # Send a special message marking end of the rendering sequence.
        self.SendMessage(["x"])

        super(JsonRenderer, self).end()
        self.flush()

    def RenderProgress(self, message=" %(spinner)s", *args, **kwargs):
        if super(JsonRenderer, self).RenderProgress():
            if "%(" in message:
                self.last_spin += 1
                kwargs["spinner"] = self.spinner[
                    self.last_spin % len(self.spinner)]

                formatted_message = message % kwargs
            elif args:
                format_args = []
                for arg in args:
                    if callable(arg):
                        format_args.append(arg())
                    else:
                        format_args.append(arg)

                formatted_message = message % tuple(format_args)
            else:
                formatted_message = message

            self.SendMessage(["p", formatted_message])

            return True

    def Log(self, record):
        log_message = {
            "msg": record.getMessage(),
            "level": record.levelname,
            "name": record.name,
            "time": record.created,
        }
        self.SendMessage(["L", log_message])

    def encode(self, obj):
        """Convenience method for fast encoding of objects.

        Args:
           obj: An arbitrary object which should be encoded.

        Returns:
           a Json serializable data object.
        """
        return self.encoder.Encode(obj)

    def decode(self, data):
        """Decode a json representation into an object."""
        return self.decoder.Decode(data)
