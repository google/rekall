from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

from rekall.layout_expert.common import data_container
from rekall.layout_expert.common import enum
from rekall.layout_expert.serialization import json_serialization


class TestJsonSerialization(unittest.TestCase):

  class MockSubclass(data_container.DataContainer):

    def __init__(self, field1, field2=None, field3=42):
      super(TestJsonSerialization.MockSubclass, self).__init__()
      self.field1 = field1
      self.field2 = field2
      self.field3 = field3

  class MockEnum(enum.Enum):
    ONE = 1
    TWO = 2
    THREE = 3

  def setUp(self):
    self.encoder = json_serialization.create_encoder()
    self.decoder = json_serialization.create_decoder()
    json_serialization.DataContainerObjectRenderer.set_safe_constructors(
        data_container.DataContainer,
        self.MockSubclass,
        self.MockEnum,
    )

  def test_construction(self):
    self.assertIsNotNone(self.encoder)
    self.assertIsNotNone(self.decoder)

  def test_serialize_data(self):
    original = data_container.DataContainer()
    encoded = self.encoder.Encode(original)
    decoded = self.decoder.Decode(encoded)
    self.assertEqual(decoded, original)

  def test_serialize_data_without_permission(self):
    json_serialization.DataContainerObjectRenderer.set_safe_constructors(
        self.MockSubclass,
    )
    original = data_container.DataContainer()
    encoded = self.encoder.Encode(original)
    with self.assertRaises(KeyError):
      self.decoder.Decode(encoded)

  def test_serialize_mock_subclass(self):
    original = self.MockSubclass('some_value', field3=33)
    encoded = self.encoder.Encode(original)
    decoded = self.decoder.Decode(encoded)
    self.assertEqual(decoded, original)

  def test_serialize_mock_subclass_without_permission(self):
    json_serialization.DataContainerObjectRenderer.set_safe_constructors(
        data_container.DataContainer,
    )
    original = self.MockSubclass('some_value', field3=33)
    encoded = self.encoder.Encode(original)
    with self.assertRaises(KeyError):
      self.decoder.Decode(encoded)

  def test_serialize_data_without_permission_for_subclass(self):
    json_serialization.DataContainerObjectRenderer.set_safe_constructors(
        data_container.DataContainer,
    )
    original = data_container.DataContainer()
    encoded = self.encoder.Encode(original)
    decoded = self.decoder.Decode(encoded)
    self.assertEqual(decoded, original)

  def test_serialize_mock_subclass_without_permission_for_superclass(self):
    json_serialization.DataContainerObjectRenderer.set_safe_constructors(
        self.MockSubclass,
    )
    original = self.MockSubclass('some_other_value', field3=24)
    encoded = self.encoder.Encode(original)
    decoded = self.decoder.Decode(encoded)
    self.assertEqual(decoded, original)

  def test_serialize_mock_subclass_with_nested_data(self):
    data1 = data_container.DataContainer()
    original = self.MockSubclass(data1, 33, field3=24)
    encoded = self.encoder.Encode(original)
    decoded = self.decoder.Decode(encoded)
    self.assertEqual(decoded, original)

  def test_serialize_mock_subclass_with_nested_mock_subclass(self):
    nested = self.MockSubclass('value1')
    original = self.MockSubclass('some value', nested)
    encoded = self.encoder.Encode(original)
    decoded = self.decoder.Decode(encoded)
    self.assertEqual(decoded, original)

  def test_serialize_mock_subclass_with_nested_shared_mock_subclass(self):
    nested = self.MockSubclass('value1')
    original = self.MockSubclass(nested, nested)
    encoded = self.encoder.Encode(original)
    decoded = self.decoder.Decode(encoded)
    self.assertEqual(decoded, original)

  def test_serialize_mock_subclass_with_nested_two_instances_of_mock_subclass(
      self,
  ):
    nested1 = self.MockSubclass('value1')
    nested2 = self.MockSubclass('value2', field3=33)
    original = self.MockSubclass(nested1, nested2, 24)
    encoded = self.encoder.Encode(original)
    decoded = self.decoder.Decode(encoded)
    self.assertEqual(decoded, original)

  def test_serialize_mock_subclass_with_three_nested_and_with_shared(
      self,
  ):
    nested1 = self.MockSubclass('some value', True, 24)
    nested2 = self.MockSubclass(nested1, field3=33)
    nested3 = self.MockSubclass('some other value', nested1, nested2)
    original = self.MockSubclass(nested1, nested2, nested3)
    encoded = self.encoder.Encode(original)
    decoded = self.decoder.Decode(encoded)
    self.assertEqual(decoded, original)

  def test_serialize_mock_subclass_with_list_field_and_three_nested_and_shared(
      self,
  ):
    nested1 = self.MockSubclass('some value', True, 24)
    nested2 = self.MockSubclass(nested1, field3=33)
    nested3 = self.MockSubclass('some other value', [nested1, nested2])
    original = self.MockSubclass(nested1, nested2, nested3)
    encoded = self.encoder.Encode(original)
    decoded = self.decoder.Decode(encoded)
    self.assertEqual(decoded, original)

  def test_serialize_mock_subclass_with_dict_field_and_three_nested_and_shared(
      self,
  ):
    nested1 = self.MockSubclass('some value', True, 24)
    nested2 = self.MockSubclass(nested1, field3=33)
    dict_field = {
        'entry1': nested1,
        'entry2': nested2
    }
    nested3 = self.MockSubclass('some other value', dict_field)
    original = self.MockSubclass(nested1, nested2, nested3)
    encoded = self.encoder.Encode(original)
    decoded = self.decoder.Decode(encoded)
    self.assertEqual(decoded, original)

  def test_serialize_enum(self):
    for original in self.MockEnum:
      encoded = self.encoder.Encode(original)
      decoded = self.decoder.Decode(encoded)
      self.assertEqual(decoded, original)


if __name__ == '__main__':
  unittest.main()
