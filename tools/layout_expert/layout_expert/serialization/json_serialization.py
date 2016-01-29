# -*- coding: utf-8 -*-

# Copyright (C) 2016 Google Inc. All Rights Reserved.
#
# Authors:
# Arkadiusz Socała <as277575@mimuw.edu.pl>
# Michael Cohen <scudette@google.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

"""This module provides JsonEncoder and JsonDecoder for data.Data subclasses.

Only constructors explicitly provided via set_safe_constructors(...) can be
explicitly invoked in the renderer.

Encoder encodes the object into JSON safe form via .Encode method.
Decoder decodes the object from JSON safe form via .Decode method.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import json

from rekall import session as session_module

from rekall.ui import json_renderer


def create_encoder(session=None):
    if not session:
        session = session_module.Session()

    renderer = json_renderer.JsonRenderer(
        session=session,
    )

    return renderer.encoder


def create_decoder(session=None):
    if not session:
        session = session_module.Session()
    json_renderer_obj = json_renderer.JsonRenderer(
        session=session,
    )
    return json_renderer_obj.decoder


def dump(obj):
    encoder = create_encoder()
    return encoder.Encode(obj)


def load(data):
    decoder = create_decoder()
    return decoder.Decode(data)


def load_file(fd):
    return load(json.load(fd))


def dump_file(obj, fd):
    json.dump(dump(obj), fd)


class DataContainerObjectRenderer(json_renderer.StateBasedObjectRenderer):
    """A renderer for DataContainer class and its subclasses."""
    renders_type = 'DataContainer', 'Enum'
    safe_constructors = {}  # class_name -> constructor

    @classmethod
    def set_safe_constructors(cls, *args, **kwargs):
        exclusive = kwargs.pop("exclusive", False)
        if exclusive:
            cls.safe_constructors.clear()

        constructors = kwargs
        for class_constructor in args:
            constructors[class_constructor.__name__] = class_constructor
        cls.safe_constructors.update(constructors)

    def DecodeFromJsonSafe(self, value, options):
        value = super(DataContainerObjectRenderer, self).DecodeFromJsonSafe(
            value,
            options,
        )
        cls_name = value.pop('mro').split(':')[0]
        cls = self.safe_constructors[cls_name]
        return cls(**value)

    def GetState(self, item, **_):
        return dict(item.state)


class ParseResultsObjectRenderer(json_renderer.JsonObjectRenderer):
    renders_type = "ParseResults"

    def EncodeToJsonSafe(self, item, **options):
        result = item.asList()
        return super(ParseResultsObjectRenderer, self).EncodeToJsonSafe(
            result, **options)
