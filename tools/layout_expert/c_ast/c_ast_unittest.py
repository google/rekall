from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest


from rekall.layout_expert.c_ast import c_ast


class TestTypeContainer(unittest.TestCase):

  def test_insert_type_definition_with_no_such_field(self):
    type_container = c_ast._CTypeContainer()
    type_container.insert_type_definition('type1')
    self.assertEqual(type_container.type_definition, 'type1')

  def test_insert_type_definition_with_such_field_equals_none(self):
    type_container = c_ast._CTypeContainer()
    type_container.type_definition = None
    type_container.insert_type_definition('type2')
    self.assertEqual(type_container.type_definition, 'type2')

  def test_insert_type_definition_with_nested_type_containers(self):
    type_container1 = c_ast._CTypeContainer()
    type_container2 = c_ast._CTypeContainer()
    type_container3 = c_ast._CTypeContainer()
    type_container1.insert_type_definition(type_container2)
    type_container1.insert_type_definition(type_container3)
    type_container1.insert_type_definition('type3')
    self.assertIs(type_container1.type_definition, type_container2)
    self.assertIs(type_container2.type_definition, type_container3)
    self.assertEqual(type_container3.type_definition, 'type3')


class TestPointerToFunction(unittest.TestCase):

  def test_insert_type_definition(self):
    pointer_to_function = c_ast.CPointerToFunction()
    pointer_to_function.insert_type_definition('type_definition')
    self.assertFalse(hasattr(pointer_to_function, 'type_definition'))


class TestFunctionCall(unittest.TestCase):

  def test_str_with_function_with_no_arguments(self):
    function_call = c_ast.CFunctionCall(
        function_name='foo',
        arguments=[],
    )
    actual = str(function_call)
    expected = 'foo()'
    self.assertEqual(actual, expected)

  def test_str_with_function_with_one_argument(self):
    function_call = c_ast.CFunctionCall(
        function_name='foo',
        arguments=[42],
    )
    actual = str(function_call)
    expected = 'foo(42)'
    self.assertEqual(actual, expected)

  def test_str_with_function_with_multiple_arguments(self):
    function_call = c_ast.CFunctionCall(
        function_name='foo',
        arguments=[24, 33, 42],
    )
    actual = str(function_call)
    expected = 'foo(24, 33, 42)'
    self.assertEqual(actual, expected)

  def test_str_with_function_with_unary_operator(self):
    function_call = c_ast.CFunctionCall(
        function_name='+',
        arguments=[42],
    )
    actual = str(function_call)
    expected = '+42'
    self.assertEqual(actual, expected)

  def test_str_with_function_with_binary_operator(self):
    function_call = c_ast.CFunctionCall(
        function_name='+',
        arguments=[33, 42],
    )
    actual = str(function_call)
    expected = '33 + 42'
    self.assertEqual(actual, expected)

  def test_str_with_function_with_multicharacter_binary_operator(self):
    function_call = c_ast.CFunctionCall(
        function_name='<=',
        arguments=[33, 42],
    )
    actual = str(function_call)
    expected = '33 <= 42'
    self.assertEqual(actual, expected)

  def test_str_with_function_with_ternary_operator(self):
    function_call = c_ast.CFunctionCall(
        function_name='?:',
        arguments=[24, 33, 42],
    )
    actual = str(function_call)
    expected = '24 ? 33 : 42'
    self.assertEqual(actual, expected)

  def test_str_with_cast_operator(self):
    function_call = c_ast.CFunctionCall(
        function_name='()',
        arguments=[33, 42],
    )
    actual = str(function_call)
    expected = '(33) 42'
    self.assertEqual(actual, expected)

  def test_str_with_array_operator(self):
    function_call = c_ast.CFunctionCall(
        function_name='[]',
        arguments=[33, 42],
    )
    actual = str(function_call)
    expected = '33[42]'
    self.assertEqual(actual, expected)


class TestNestedExpression(unittest.TestCase):

  def test_str(self):
    nested_expression = c_ast.CNestedExpression(
        opener='(',
        content=42,
        closer='}',
    )
    actual = str(nested_expression)
    expected = '(42}'
    self.assertEqual(actual, expected)


if __name__ == '__main__':
  unittest.main()
