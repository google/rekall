#!/usr/bin/env python
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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

from layout_expert.common import data_container
from layout_expert.serialization import json_serialization


class MockSubclass(data_container.DataContainer):
    def __init__(self, field1, field2=None, field3=42):
        super(MockSubclass, self).__init__()
        self.field1 = field1
        self.field2 = field2
        self.field3 = field3


class TestJsonSerialization(unittest.TestCase):

    def setUp(self):
        self.encoder = json_serialization.create_encoder()
        self.decoder = json_serialization.create_decoder()
        json_serialization.DataContainerObjectRenderer.set_safe_constructors(
            data_container.DataContainer, MockSubclass, exclusive=True)

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
            MockSubclass, exclusive=True)
        original = data_container.DataContainer()
        encoded = self.encoder.Encode(original)
        with self.assertRaises(KeyError):
            self.decoder.Decode(encoded)

    def test_serialize_mock_subclass(self):
        original = MockSubclass('some_value', field3=33)
        encoded = self.encoder.Encode(original)
        decoded = self.decoder.Decode(encoded)
        self.assertEqual(decoded, original)

    def test_serialize_mock_subclass_without_permission(self):
        json_serialization.DataContainerObjectRenderer.set_safe_constructors(
            data_container.DataContainer, exclusive=True)
        original = MockSubclass('some_value', field3=33)
        encoded = self.encoder.Encode(original)
        with self.assertRaises(KeyError):
            self.decoder.Decode(encoded)

    def test_serialize_data_without_permission_for_subclass(self):
        json_serialization.DataContainerObjectRenderer.set_safe_constructors(
            data_container.DataContainer, exclusive=True)
        original = data_container.DataContainer()
        encoded = self.encoder.Encode(original)
        decoded = self.decoder.Decode(encoded)
        self.assertEqual(decoded, original)

    def test_serialize_mock_subclass_without_permission_for_superclass(self):
        json_serialization.DataContainerObjectRenderer.set_safe_constructors(
            MockSubclass, exclusive=True)
        original = MockSubclass('some_other_value', field3=24)
        encoded = self.encoder.Encode(original)
        decoded = self.decoder.Decode(encoded)
        self.assertEqual(decoded, original)

    def test_serialize_mock_subclass_with_nested_data(self):
        data1 = data_container.DataContainer()
        original = MockSubclass(data1, 33, field3=24)
        encoded = self.encoder.Encode(original)
        decoded = self.decoder.Decode(encoded)
        self.assertEqual(decoded, original)

    def test_serialize_mock_subclass_with_nested_mock_subclass(self):
        nested = MockSubclass('value1')
        original = MockSubclass('some value', nested)
        encoded = self.encoder.Encode(original)
        decoded = self.decoder.Decode(encoded)
        self.assertEqual(decoded, original)

    def test_serialize_mock_subclass_with_nested_shared_mock_subclass(self):
        nested = MockSubclass('value1')
        original = MockSubclass(nested, nested)
        encoded = self.encoder.Encode(original)
        decoded = self.decoder.Decode(encoded)
        self.assertEqual(decoded, original)

    def test_serialize_mock_subclass_with_nested_two_instances_of_mock_subclass(
            self):
        nested1 = MockSubclass('value1')
        nested2 = MockSubclass('value2', field3=33)
        original = MockSubclass(nested1, nested2, 24)
        encoded = self.encoder.Encode(original)
        decoded = self.decoder.Decode(encoded)
        self.assertEqual(decoded, original)

    def test_serialize_mock_subclass_with_three_nested_and_with_shared(
            self):
        nested1 = MockSubclass('some value', True, 24)
        nested2 = MockSubclass(nested1, field3=33)
        nested3 = MockSubclass('some other value', nested1, nested2)
        original = MockSubclass(nested1, nested2, nested3)
        encoded = self.encoder.Encode(original)
        decoded = self.decoder.Decode(encoded)
        self.assertEqual(decoded, original)

    def test_serialize_mock_subclass_with_list_field_and_three_nested_and_shared(
            self):
        nested1 = MockSubclass('some value', True, 24)
        nested2 = MockSubclass(nested1, field3=33)
        nested3 = MockSubclass('some other value', [nested1, nested2])
        original = MockSubclass(nested1, nested2, nested3)
        encoded = self.encoder.Encode(original)
        decoded = self.decoder.Decode(encoded)
        self.assertEqual(decoded, original)

    def test_serialize_mock_subclass_with_dict_field_and_three_nested_and_shared(
            self):
        nested1 = MockSubclass('some value', True, 24)
        nested2 = MockSubclass(nested1, field3=33)
        dict_field = {
            'entry1': nested1,
            'entry2': nested2
        }
        nested3 = MockSubclass('some other value', dict_field)
        original = MockSubclass(nested1, nested2, nested3)
        encoded = self.encoder.Encode(original)
        decoded = self.decoder.Decode(encoded)
        self.assertEqual(decoded, original)


if __name__ == '__main__':
    unittest.main()
