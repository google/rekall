from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

import mock

from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.c_ast import pre_ast
from rekall.layout_expert.visitors import type_collecting_visitor


class TestTypeCollectingVisitor(unittest.TestCase):

  def setUp(self):
    self.expression_evaluator = mock.MagicMock()
    self.type_collector = type_collecting_visitor.TypeCollectingVisitor(
        self.expression_evaluator
    )

  def test_collect_types(self):
    typedef = c_ast.CTypedef(
        name='type_name_3',
        type_definition=c_ast.CTypeDefinition(
            type_name='type_name_4',
            type_definition='type_definition_3',
        )
    )
    program = c_ast.CProgram([
        c_ast.CTypeDefinition('type_name_1', 'type_definition_1'),
        c_ast.CTypeDefinition('type_name_2', 'type_definition_2'),
        typedef,
    ])
    actual = self.type_collector.collect_types(program)
    expected = {
        'type_name_1': 'type_definition_1',
        'type_name_2': 'type_definition_2',
        'type_name_3': typedef,
        'type_name_4': 'type_definition_3',
    }
    self.assertEqual(actual, expected)

  def test_collect_types_with_type_name_collision(self):
    program = c_ast.CProgram([
        c_ast.CTypeDefinition('type_name_1', 'type_definition_1'),
        c_ast.CTypeDefinition('type_name_2', 'type_definition_2'),
        c_ast.CTypedef(
            name='type_name_3',
            type_definition=c_ast.CTypeDefinition(
                type_name='type_name_2',
                type_definition='type_definition_3',
            )
        ),
    ])
    with self.assertRaises(
        type_collecting_visitor.TwoDefinitionsOfTheSameTypeException,
    ):
      self.type_collector.collect_types(program)

  def test_collect_types_with_program(self):
    program = c_ast.CProgram([
        c_ast.CTypeDefinition('type_name_1', 'type_definition_1'),
        c_ast.CTypeDefinition('type_name_2', 'type_definition_2'),
        c_ast.CTypeDefinition('type_name_3', 'type_definition_3'),
    ])
    actual = self.type_collector.collect_types(program)
    expected = {
        'type_name_1': 'type_definition_1',
        'type_name_2': 'type_definition_2',
        'type_name_3': 'type_definition_3',
    }
    self.assertEqual(actual, expected)

  def test_collect_types_with_if(self):
    content1 = [
        c_ast.CTypeDefinition('type_name_1', 'type_definition_1'),
    ]
    content2 = [
        c_ast.CTypeDefinition('type_name_2', 'type_definition_2'),
        c_ast.CTypeDefinition('type_name_3', 'type_definition_3'),
    ]
    content3 = [
        c_ast.CTypeDefinition('type_name_4', 'type_definition_4'),
    ]
    else_content = [
        c_ast.CTypeDefinition('type_name_5', 'type_definition_5'),
    ]
    if_ = pre_ast.If(
        conditional_blocks=[
            pre_ast.ConditionalBlock('expression1', content1),
            pre_ast.ConditionalBlock('expression2', content2),
            pre_ast.ConditionalBlock('expression3', content3),
        ],
        else_content=else_content,
    )
    self.expression_evaluator.evaluate.side_effect = (
        c_ast.CNumber(0),
        c_ast.CNumber(1),
    )
    actual = self.type_collector.visit_if(if_)
    expected = {
        'type_name_2': 'type_definition_2',
        'type_name_3': 'type_definition_3',
    }
    self.assertEqual(actual, expected)

  def test_collect_types_with_type_definition(self):
    type_definition = c_ast.CTypeDefinition(
        type_name='type_name_1',
        type_definition='type_definition_1',
        following_fields='following_fields',
    )
    actual = self.type_collector.collect_types(type_definition)
    expected = {
        'type_name_1': 'type_definition_1',
    }
    self.assertEqual(actual, expected)

  def test_collect_types_with_field(self):
    field = c_ast.CField('name', 'type_definiiton')
    actual = self.type_collector.collect_types(field)
    self.assertEqual(actual, {})

  def test_collect_types_with_typedef(self):
    typedef = c_ast.CTypedef(
        name='type_name_1',
        type_definition=c_ast.CTypeDefinition(
            type_name='type_name_2',
            type_definition='type_definition_2',
        ),
        attributes='attributes',
    )
    actual = self.type_collector.collect_types(typedef)
    expected = {
        'type_name_1': typedef,
        'type_name_2': 'type_definition_2',
    }
    self.assertEqual(actual, expected)

  def test_collect_types_with_type_reference(self):
    type_reference = c_ast.CTypeReference('type_name')
    actual = self.type_collector.collect_types(type_reference)
    self.assertEqual(actual, {})

  def test_collect_types_with_enum(self):
    enum = c_ast.CEnum('attributes')
    actual = self.type_collector.collect_types(enum)
    self.assertEqual(actual, {})

  def test_collect_types_with_struct(self):
    struct = c_ast.CStruct('content', 'attributes')
    actual = self.type_collector.collect_types(struct)
    self.assertEqual(actual, {})

  def test_collect_types_with_union(self):
    union = c_ast.CUnion('content', 'attributes')
    actual = self.type_collector.collect_types(union)
    self.assertEqual(actual, {})

  def test_collect_types_with_pointer(self):
    pointer = c_ast.CPointer('type_definition')
    actual = self.type_collector.collect_types(pointer)
    self.assertEqual(actual, {})

  def test_collect_types_with_pointer_to_function(self):
    pointer_to_function = c_ast.CPointerToFunction()
    actual = self.type_collector.collect_types(pointer_to_function)
    self.assertEqual(actual, {})

  def test_collect_types_with_array(self):
    array = c_ast.CArray(
        length=42,
        type_definition='type_definition',
    )
    actual = self.type_collector.collect_types(array)
    self.assertEqual(actual, {})


if __name__ == '__main__':
  unittest.main()


