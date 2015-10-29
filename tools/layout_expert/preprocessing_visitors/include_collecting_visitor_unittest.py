from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest


import mock

from rekall.layout_expert.c_ast import pre_ast
from rekall.layout_expert.preprocessing_visitors import include_collecting_visitor


class TestIncludeCollectingVisitor(unittest.TestCase):

  def setUp(self):
    self.include_collector = (
        include_collecting_visitor.IncludeCollectingVisitor()
    )

  def test_collect_includes_with_file(self):
    mock_node = mock.MagicMock()
    node = pre_ast.File(mock_node)
    mock_node.accept.return_value = 42
    actual = self.include_collector.collect_includes(node)
    expected = 42
    self.assertEqual(actual, expected)

  def test_collect_includes_with_include(self):
    node = pre_ast.Include(
        path='some_path',
        quotes_type='some_qutes_type',
    )
    actual = self.include_collector.collect_includes(node)
    expected = [node]
    self.assertEqual(actual, expected)

  def test_collect_includes_with_pragma(self):
    node = pre_ast.Pragma('some_arguments')
    actual = self.include_collector.collect_includes(node)
    expected = []
    self.assertEqual(actual, expected)

  def test_collect_includes_with_error(self):
    node = pre_ast.Error('some_message')
    actual = self.include_collector.collect_includes(node)
    expected = []
    self.assertEqual(actual, expected)

  def test_collect_includes_with_define_object_like(self):
    node = pre_ast.DefineObjectLike(
        name='some_name',
        replacement='some_replacement',
        string_replacement='some_string_replacement',
    )
    actual = self.include_collector.collect_includes(node)
    expected = []
    self.assertEqual(actual, expected)

  def test_collect_includes_with_define_function_like(self):
    node = pre_ast.DefineFunctionLike(
        name='some_name',
        arguments='some_arguments',
        replacement='some_replacement',
        string_replacement='some_string_replacement',
    )
    actual = self.include_collector.collect_includes(node)
    expected = []
    self.assertEqual(actual, expected)

  def test_collect_includes_with_undef(self):
    node = pre_ast.Undef('some_name')
    actual = self.include_collector.collect_includes(node)
    expected = []
    self.assertEqual(actual, expected)

  def test_collect_includes_with_if(self):
    mock_conditiona_block_1 = mock.MagicMock()
    mock_conditiona_block_2 = mock.MagicMock()
    mock_conditiona_block_3 = mock.MagicMock()
    mock_else_block = mock.MagicMock()
    node = pre_ast.If(
        conditional_blocks=[
            mock_conditiona_block_1,
            mock_conditiona_block_2,
            mock_conditiona_block_3,
        ],
        else_content=mock_else_block,
    )
    mock_conditiona_block_1.accept.return_value = [33, 42]
    mock_conditiona_block_2.accept.return_value = []
    mock_conditiona_block_3.accept.return_value = ['foo', 'bar']
    mock_else_block.accept.return_value = ['baz', 24]
    actual = self.include_collector.collect_includes(node)
    expected = [33, 42, 'foo', 'bar', 'baz', 24]
    self.assertEqual(actual, expected)

  def test_collect_includes_with_conditional_block(self):
    mock_node = mock.MagicMock()
    node = pre_ast.ConditionalBlock(
        conditional_expression='some_expression',
        content=mock_node,
    )
    mock_node.accept.return_value = 33
    actual = self.include_collector.collect_includes(node)
    expected = 33
    self.assertEqual(actual, expected)

  def test_collect_includes_with_composite_block(self):
    mock_conditiona_block_1 = mock.MagicMock()
    mock_conditiona_block_2 = mock.MagicMock()
    mock_conditiona_block_3 = mock.MagicMock()
    node = pre_ast.CompositeBlock([
        mock_conditiona_block_1,
        mock_conditiona_block_2,
        mock_conditiona_block_3,
    ])
    mock_conditiona_block_1.accept.return_value = [33]
    mock_conditiona_block_2.accept.return_value = []
    mock_conditiona_block_3.accept.return_value = ['foo', 42]
    actual = self.include_collector.collect_includes(node)
    expected = [33, 'foo', 42]
    self.assertEqual(actual, expected)

  def test_collect_includes_with_text_block(self):
    node = pre_ast.TextBlock('some_content')
    actual = self.include_collector.collect_includes(node)
    expected = []
    self.assertEqual(actual, expected)


if __name__ == '__main__':
  unittest.main()
