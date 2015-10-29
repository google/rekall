from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest


from rekall.layout_expert.builtins import types
from rekall.layout_expert.c_ast import c_ast


class TestGet64BitTypes(unittest.TestCase):

  def setUp(self):
    self.types = types.get_64bit_types()

  def test_get_64bit_types_with_chars(self):
    for type_name in 'char', 'unsigned char', 'signed char':
      actual = self.types[type_name]
      expected = c_ast.CSimpleType(8, 8)
      self.assertEqual(actual, expected)

  def test_get_64bit_types_with_shorts(self):
    shorts = [
        'short',
        'unsigned short',
        'signed short',
        'short int',
        'unsigned short int',
        'signed short int',
    ]
    for type_name in shorts:
      actual = self.types[type_name]
      expected = c_ast.CSimpleType(16, 16)
      self.assertEqual(actual, expected)

  def test_get_64bit_types_with_ints(self):
    ints = [
        'int',
        'unsigned',
        'unsigned int',
        'signed',
        'signed int',
    ]
    for type_name in ints:
      actual = self.types[type_name]
      expected = c_ast.CSimpleType(32, 32)
      self.assertEqual(actual, expected)

  def test_get_64bit_types_with_longs(self):
    longs = [
        'long',
        'unsigned long',
        'signed long',
        'long int',
        'unsigned long int',
        'signed long int',
    ]
    for type_name in longs:
      actual = self.types[type_name]
      expected = c_ast.CSimpleType(64, 64)
      self.assertEqual(actual, expected)

  def test_get_64bit_types_with_long_longs(self):
    long_longs = [
        'long long',
        'unsigned long long',
        'signed long long',
        'long long int',
        'unsigned long long int',
        'signed long long int',
    ]
    for type_name in long_longs:
      actual = self.types[type_name]
      expected = c_ast.CSimpleType(64, 64)
      self.assertEqual(actual, expected)

  def test_get_64bit_types_with_bool(self):
    actual = self.types['_Bool']
    expected = c_ast.CSimpleType(8, 8)
    self.assertEqual(actual, expected)

  def test_get_64_bit_types_with_size_t(self):
    actual = self.types['size_t']
    expected = c_ast.CSimpleType(64, 64)
    self.assertEqual(actual, expected)

if __name__ == '__main__':
  unittest.main()
