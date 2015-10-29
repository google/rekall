from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest


from rekall.layout_expert.common import data_container as data_container_module


class TestDataContainer(unittest.TestCase):

  def test_getattr_with_fields(self):
    data_container = data_container_module.DataContainer(
        field1='value1',
        field2=42,
    )
    self.assertEqual(data_container.field1, 'value1')
    self.assertEqual(data_container.field2, 42)

  def test_getattr_with_state(self):
    data_container = data_container_module.DataContainer(
        field1='value1',
        field2=42,
    )
    expected = {
        'field1': 'value1',
        'field2': 42,
    }
    self.assertEqual(data_container.state, expected)

  def test_setattr_and_getattr_with_existing_field(self):
    data_container = data_container_module.DataContainer(
        field1='value1',
        field2=42,
    )
    data_container.field2 = 33
    self.assertEqual(data_container.field1, 'value1')
    self.assertEqual(data_container.field2, 33)

  def test_setattr_and_getattr_state_with_existing_field(self):
    data_container = data_container_module.DataContainer(
        field1='value1',
        field2=42,
    )
    data_container.field2 = 33
    expected = {
        'field1': 'value1',
        'field2': 33,
    }
    self.assertEqual(data_container.state, expected)

  def test_setattr_and_getattr_with_new_field(self):
    data_container = data_container_module.DataContainer(
        field1='value1',
        field2=42,
    )
    data_container.field3 = 33
    self.assertEqual(data_container.field1, 'value1')
    self.assertEqual(data_container.field2, 42)
    self.assertEqual(data_container.field3, 33)

  def test_setattr_and_getattr_state_with_new_field(self):
    data_container = data_container_module.DataContainer(
        field1='value1',
        field2=42,
    )
    data_container.field3 = 33
    expected = {
        'field1': 'value1',
        'field2': 42,
        'field3': 33,
    }
    self.assertEqual(data_container.state, expected)

  def test_eq_with_empty_objects(self):
    data_container_1 = data_container_module.DataContainer()
    data_container_2 = data_container_module.DataContainer()
    self.assertEqual(data_container_1, data_container_2)

  def test_eq_with_same_fields(self):
    data_container_1 = data_container_module.DataContainer(
        field1='a',
        field2='b',
    )
    data_container_2 = data_container_module.DataContainer(
        field1='a',
        field2='b',
    )
    self.assertEqual(data_container_1, data_container_2)

  def test_eq_with_different_fields(self):
    data_container_1 = data_container_module.DataContainer(
        field1='a',
        field2='b',
    )
    data_container_2 = data_container_module.DataContainer(
        field1='a',
        field2='a',
    )
    self.assertNotEqual(data_container_1, data_container_2)

  def test_neq_with_different_fields(self):
    data_container_1 = data_container_module.DataContainer(
        field1='a',
        field2='b',
    )
    data_container_2 = data_container_module.DataContainer(
        field1='b',
        field2='b',
    )
    self.assertNotEqual(data_container_1, data_container_2)

  def test_repr_with_empty_object(self):
    data_container = data_container_module.DataContainer()
    actual = str(data_container)
    expected = 'DataContainer{}'
    self.assertEquals(actual, expected)

  def test_str_with_fields(self):
    data_container = data_container_module.DataContainer(
        field1='a',
        field2='b',
    )
    actual = str(data_container)
    expected1 = 'DataContainer{field1: a, field2: b}'
    expected2 = 'DataContainer{field2: b, field1: a}'
    self.assertTrue(actual == expected1 or actual == expected2)


if __name__ == '__main__':
  unittest.main()
