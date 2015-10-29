from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

import mock

from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.c_ast import pre_ast


class TestIncludeQuotesType(unittest.TestCase):

  def test_state_with_angle_brackets(self):
    actual = pre_ast.Include.QuotesType.ANGLE_BRACKETS.state
    expected = {'value': 1}
    self.assertEqual(actual, expected)

  def test_state_with_double_quotes(self):
    actual = pre_ast.Include.QuotesType.DOUBLE_QUOTES.state
    expected = {'value': 2}
    self.assertEqual(actual, expected)


class TestPragmaArgument(unittest.TestCase):

  def test_if_functional_with_no_arguments(self):
    pragma_argument = pre_ast.PragmaArgument(
        name='foo',
        arguments=[],
        value=42,
    )
    self.assertTrue(pragma_argument.is_functional)

  def test_if_functional_with_arguments(self):
    pragma_argument = pre_ast.PragmaArgument(
        name='foo',
        arguments=['bar', 33],
        value=42,
    )
    self.assertTrue(pragma_argument.is_functional)

  def test_if_functional_with_no_functional(self):
    pragma_argument = pre_ast.PragmaArgument('foo')
    self.assertFalse(pragma_argument.is_functional)


class TestIf(unittest.TestCase):

  def test_get_active_content(self):
    conditional_blocks = [
        pre_ast.ConditionalBlock('expression1', 'content1'),
        pre_ast.ConditionalBlock('expression2', 'content2'),
        pre_ast.ConditionalBlock('expression3', 'content3'),
    ]
    if_ = pre_ast.If(conditional_blocks, 'else_content')
    expression_evaluator = mock.MagicMock()
    expression_evaluator.evaluate.side_effect = (
        c_ast.CNumber(0),
        c_ast.CNumber(1),
    )
    actual = if_.get_active_content(expression_evaluator)
    self.assertEqual(actual, 'content2')

  def test_get_active_content_with_else_content(self):
    conditional_blocks = [
        pre_ast.ConditionalBlock('expression1', 'content1'),
        pre_ast.ConditionalBlock('expression2', 'content2'),
        pre_ast.ConditionalBlock('expression3', 'content3'),
    ]
    if_ = pre_ast.If(conditional_blocks, 'else_content')
    expression_evaluator = mock.MagicMock()
    expression_evaluator.evaluate.side_effect = (
        c_ast.CNumber(0),
        c_ast.CNumber(0),
        c_ast.CNumber(0),
    )
    actual = if_.get_active_content(expression_evaluator)
    self.assertEqual(actual, 'else_content')

  def test_get_active_content_with_empty_else_content(self):
    conditional_blocks = [
        pre_ast.ConditionalBlock('expression1', 'content1'),
        pre_ast.ConditionalBlock('expression2', 'content2'),
        pre_ast.ConditionalBlock('expression3', 'content3'),
    ]
    if_ = pre_ast.If(conditional_blocks)
    expression_evaluator = mock.MagicMock()
    expression_evaluator.evaluate.side_effect = (
        c_ast.CNumber(0),
        c_ast.CNumber(0),
        c_ast.CNumber(0),
    )
    actual = if_.get_active_content(expression_evaluator)
    self.assertEqual(actual, pre_ast.CompositeBlock([]))


class TestCompositeBlock(unittest.TestCase):

  def test_str(self):
    composite_block = pre_ast.CompositeBlock(['foo', 42, 'bar'])
    actual = str(composite_block)
    expected = 'foo 42 bar'
    self.assertEqual(actual, expected)


if __name__ == '__main__':
  unittest.main()

