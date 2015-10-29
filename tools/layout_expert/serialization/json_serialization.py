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
from rekall import session as session_module

from rekall.ui import json_renderer


def create_encoder(session=None):
  return json_renderer.JsonEncoder(
      session=session,
      renderer='JsonRenderer',
  )


def create_decoder(session=None):
  if not session:
    session = session_module.Session()
  json_renderer_obj = json_renderer.JsonRenderer(
      session=session,
  )
  return json_renderer.JsonDecoder(
      session=session,
      renderer=json_renderer_obj,
  )


class DataContainerObjectRenderer(json_renderer.StateBasedObjectRenderer):
  """A class representing a renderer for DataContainer class and its subclasses.
  """
  renders_type = 'DataContainer', 'Enum'
  safe_constructors = {}  # class_name -> constructor

  @classmethod
  def set_safe_constructors(cls, *args, **kwargs):
    constructors = kwargs
    for class_constructor in args:
      constructors[class_constructor.__name__] = class_constructor
    cls.safe_constructors = constructors

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

