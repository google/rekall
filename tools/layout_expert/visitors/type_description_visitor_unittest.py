from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest


import mock

from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.visitors import type_description_visitor


class TestTypeDescriptionVisitorUnittest(unittest.TestCase):

  def setUp(self):
    self.typedef_resolver = mock.MagicMock()
    self.type_description_visitor = (
        type_description_visitor.TypeDescriptionVisitor(
            self.typedef_resolver,
        )
    )
    self.types = {}

  def test_get_descripiton_with_enum(self):
    type_definition = c_ast.CEnum()
    actual = self.type_description_visitor.get_description(
        type_definition,
        self.types,
    )
    expected = ['__enum']
    self.assertEqual(actual, expected)

  def test_get_descripiton_with_struct(self):
    type_definition = c_ast.CStruct([])
    actual = self.type_description_visitor.get_description(
        type_definition,
        self.types,
    )
    expected = ['__struct']
    self.assertEqual(actual, expected)

  def test_get_descripiton_with_union(self):
    type_definition = c_ast.CUnion([])
    actual = self.type_description_visitor.get_description(
        type_definition,
        self.types,
    )
    expected = ['__union']
    self.assertEqual(actual, expected)

  def test_get_descripiton_with_array_of_structs(self):
    type_definition = c_ast.CArray(
        length=c_ast.CNumber(33),
        type_definition=c_ast.CTypeReference('struct some_struct'),
        evaluated_length=33,
    )
    self.typedef_resolver.resolve.return_value = (
        c_ast.CTypeReference('struct some_struct')
    )
    actual = self.type_description_visitor.get_description(
        type_definition,
        self.types,
    )
    expected = [
        'Array', {
            'count': 33,
            'target_args': None,
            'target': 'some_struct'
        }
    ]
    self.assertEqual(actual, expected)

  def test_get_descripiton_with_array_of_pointers_to_struct(self):
    type_definition = c_ast.CArray(
        length=c_ast.CNumber(42),
        type_definition=c_ast.CPointer(c_ast.CTypeReference('struct s')),
        evaluated_length=42,
    )
    self.typedef_resolver.resolve.return_value = (
        c_ast.CTypeReference('struct s')
    )
    actual = self.type_description_visitor.get_description(
        type_definition,
        self.types,
    )
    expected = [
        'Array', {
            'count': 42,
            'target_args': {
                'target_args': None,
                'target': 's',
            },
            'target': 'Pointer'
        }
    ]
    self.assertEqual(actual, expected)

  def test_get_description_with_pointer(self):
    type_definition = c_ast.CPointer(c_ast.CTypeReference('some_type'))
    self.typedef_resolver.resolve.return_value = (
        c_ast.CTypeReference('some_type')
    )
    actual = self.type_description_visitor.get_description(
        type_definition,
        self.types,
    )
    expected = ['Pointer', {'target_args': None, 'target': 'some_type'}]
    self.assertEqual(actual, expected)

  def test_get_description_with_pointer_to_void(self):
    type_definition = c_ast.CPointer(c_ast.CTypeReference('void'))
    self.typedef_resolver.resolve.return_value = (
        c_ast.CTypeReference('void')
    )
    actual = self.type_description_visitor.get_description(
        type_definition,
        self.types,
    )
    expected = ['Pointer', {'target_args': None, 'target': 'Void'}]
    self.assertEqual(actual, expected)

  def test_get_descripiton_with_pointer_to_function(self):
    type_definition = c_ast.CPointerToFunction()
    actual = self.type_description_visitor.get_description(
        type_definition,
        self.types,
    )
    expected = ['Pointer', {'target_args': None, 'target': 'void'}]
    self.assertEqual(actual, expected)

  def test_get_description_with_type_reference(self):
    type_definition = c_ast.CTypeReference('some_type')
    self.typedef_resolver.resolve.return_value = type_definition
    actual = self.type_description_visitor.get_description(
        type_definition,
        self.types,
    )
    expected = ['some_type']
    self.assertEqual(actual, expected)

  def test_get_description_with_type_reference_resolving_to_other_reference(
      self,
  ):
    type_definition = c_ast.CTypeReference('some_type')
    self.typedef_resolver.resolve.return_value = (
        c_ast.CTypeReference('some_other_type')
    )
    actual = self.type_description_visitor.get_description(
        type_definition,
        self.types,
    )
    expected = ['some_other_type']
    self.assertEqual(actual, expected)

  def test_get_description_with_type_reference_resolving_to_type_definition(
      self,
  ):
    type_definition = c_ast.CTypeReference('some_type')
    self.typedef_resolver.resolve.return_value = c_ast.CTypeDefinition(
        type_name='some_other_name',
        type_definition='some_definition',
    )
    actual = self.type_description_visitor.get_description(
        type_definition,
        self.types,
    )
    expected = ['some_other_name']
    self.assertEqual(actual, expected)

  def test_get_description_with_type_reference_to_enum(self):
    type_definition = c_ast.CTypeReference('enum some_enum')
    self.typedef_resolver.resolve.return_value = type_definition
    actual = self.type_description_visitor.get_description(
        type_definition,
        self.types,
    )
    expected = ['Enumeration', {'target': 'long', 'enum_name': 'some_enum'}]
    self.assertEqual(actual, expected)

  def test_get_description_with_type_reference_to_struct(self):
    type_definition = c_ast.CTypeReference('struct some_struct')
    self.typedef_resolver.resolve.return_value = type_definition
    actual = self.type_description_visitor.get_description(
        type_definition,
        self.types,
    )
    expected = ['some_struct']
    self.assertEqual(actual, expected)

  def test_get_description_with_type_reference_to_union(self):
    type_definition = c_ast.CTypeReference('struct some_union')
    self.typedef_resolver.resolve.return_value = type_definition
    actual = self.type_description_visitor.get_description(
        type_definition,
        self.types,
    )
    expected = ['some_union']
    self.assertEqual(actual, expected)


if __name__ == '__main__':
  unittest.main()
