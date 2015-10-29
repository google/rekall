from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest


import mock

from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.c_ast import pre_ast
from rekall.layout_expert.preprocessing_visitors import preprocessing_visitor


class TestPreprocessingVisitor(unittest.TestCase):

  def setUp(self):
    self.object_likes = {}
    self.function_likes = {}
    self.functions = {}
    self.expression_evaluator = mock.MagicMock()
    self.macro_expander = mock.MagicMock()
    self.preprocessing_visitor = preprocessing_visitor.PreprocessingVisitor(
        self.object_likes,
        self.function_likes,
        self.functions,
        self.expression_evaluator,
        self.macro_expander,
    )

  def test_preprocess_file(self):
    mock_node = mock.Mock()
    file_ = pre_ast.File(mock_node)
    mock_node.accept.return_value = 42
    actual = self.preprocessing_visitor.preprocess(file_)
    expected = pre_ast.File(42)
    self.assertEqual(actual, expected)

  def test_preprocess_include_with_content(self):
    mock_node = mock.MagicMock()
    include = pre_ast.Include(
        path='some_path',
        quotes_type='some_quotes_type',
        content=mock_node,
    )
    mock_node.accept.return_value = 33
    actual = self.preprocessing_visitor.preprocess(include)
    self.assertEqual(actual, 33)

  def test_preprocess_include_without_content(self):
    include = pre_ast.Include(
        path='some_path',
        quotes_type='some_quotes_type',
    )
    actual = self.preprocessing_visitor.preprocess(include)
    self.assertIsNone(actual)

  def test_preprocess_pragma(self):
    pragma = pre_ast.Pragma('some_arguments')
    actual = self.preprocessing_visitor.preprocess(pragma)
    self.assertEqual(actual, pragma)

  def test_preprocess_error(self):
    error = pre_ast.Error('some_message')
    with self.assertRaises(preprocessing_visitor.PreprocessingException) as cm:
      self.preprocessing_visitor.preprocess(error)
    self.assertEqual(cm.exception.args[0].message, 'some_message')

  def test_preproces_define_object_like_with_not_defined_name(self):
    define_object_like_1 = pre_ast.DefineObjectLike(
        name='some_name_1',
        replacement='some_replacement_1',
        string_replacement='some_string_replacement_1',
    )
    self.object_likes['some_name_1'] = define_object_like_1
    define_object_like_2 = pre_ast.DefineObjectLike(
        name='some_name_2',
        replacement='some_replacement_2',
        string_replacement='some_string_replacement_2',
    )
    actual = self.preprocessing_visitor.preprocess(define_object_like_2)
    self.assertIsNone(actual)
    self.assertEquals(self.object_likes['some_name_1'], define_object_like_1)
    self.assertEquals(self.object_likes['some_name_2'], define_object_like_2)

  def test_preproces_define_object_like_with_already_defined_name(self):
    define_object_like_1 = pre_ast.DefineObjectLike(
        name='some_name',
        replacement='some_replacement_1',
        string_replacement='some_string_replacement_2',
    )
    self.object_likes['some_name'] = define_object_like_1
    define_object_like_2 = pre_ast.DefineObjectLike(
        name='some_name',
        replacement='some_replacement_2',
        string_replacement='some_string_replacement_2',
    )
    actual = self.preprocessing_visitor.preprocess(define_object_like_2)
    self.assertIsNone(actual)
    self.assertEquals(self.object_likes['some_name'], define_object_like_2)

  def test_preproces_define_function_like_with_not_defined_name(self):
    define_function_like_1 = pre_ast.DefineFunctionLike(
        name='some_name_1',
        arguments='some_arguments_1',
        replacement='some_replacement_1',
        string_replacement='some_string_replacement_1',
    )
    self.function_likes['some_name_1'] = define_function_like_1
    define_function_like_2 = pre_ast.DefineFunctionLike(
        name='some_name_2',
        arguments='some_arguments_2',
        replacement='some_replacement_2',
        string_replacement='some_string_replacement_2',
    )
    actual = self.preprocessing_visitor.preprocess(define_function_like_2)
    self.assertIsNone(actual)
    self.assertEquals(
        self.function_likes['some_name_1'],
        define_function_like_1,
    )
    self.assertEquals(
        self.function_likes['some_name_2'],
        define_function_like_2,
    )

  def test_preproces_define_function_like_with_already_defined_name(self):
    define_function_like_1 = pre_ast.DefineFunctionLike(
        name='some_name',
        arguments='some_arguments_1',
        replacement='some_replacement_1',
        string_replacement='some_string_replacement_2',
    )
    self.function_likes['some_name'] = define_function_like_1
    define_function_like_2 = pre_ast.DefineFunctionLike(
        name='some_name',
        arguments='some_arguments_2',
        replacement='some_replacement_2',
        string_replacement='some_string_replacement_2',
    )
    actual = self.preprocessing_visitor.preprocess(define_function_like_2)
    self.assertIsNone(actual)
    self.assertEquals(self.function_likes['some_name'], define_function_like_2)

  def test_preproces_undef_with_existing_object_like(self):
    define_object_like = pre_ast.DefineObjectLike(
        name='some_name',
        replacement='some_replacement',
        string_replacement='some_string_replacement',
    )
    self.object_likes['some_name'] = define_object_like
    undef = pre_ast.Undef('some_name')
    actual = self.preprocessing_visitor.preprocess(undef)
    self.assertIsNone(actual)
    self.assertFalse('some_name' in self.object_likes)

  def test_preproces_undef_with_existing_function_like(self):
    define_function_like = pre_ast.DefineFunctionLike(
        name='some_name',
        arguments='some_arguments',
        replacement='some_replacement',
        string_replacement='some_string_replacement',
    )
    self.function_likes['some_name'] = define_function_like
    undef = pre_ast.Undef('some_name')
    actual = self.preprocessing_visitor.preprocess(undef)
    self.assertIsNone(actual)
    self.assertFalse('some_name' in self.function_likes)

  def test_preproces_undef_with_undefined_name(self):
    define_object_like = pre_ast.DefineObjectLike(
        name='some_name_1',
        replacement='some_replacement_1',
        string_replacement='some_string_replacement_1',
    )
    self.object_likes['some_name_1'] = define_object_like

    define_function_like = pre_ast.DefineFunctionLike(
        name='some_name_2',
        arguments='some_arguments_2',
        replacement='some_replacement_2',
        string_replacement='some_string_replacement_2',
    )
    self.function_likes['some_name_2'] = define_function_like

    undef = pre_ast.Undef('some_name_3')
    actual = self.preprocessing_visitor.preprocess(undef)
    self.assertIsNone(actual)
    self.assertEqual(self.object_likes['some_name_1'], define_object_like)
    self.assertEqual(self.function_likes['some_name_2'], define_function_like)
    self.assertFalse('some_name_3' in self.object_likes)
    self.assertFalse('some_name_3' in self.function_likes)

  def test_preprocess_with_if(self):
    some_content_2 = mock.MagicMock()
    if_ = pre_ast.If(
        conditional_blocks=[
            pre_ast.ConditionalBlock(
                conditional_expression='some_expression_1',
                content='some_content_1',
            ),
            pre_ast.ConditionalBlock(
                conditional_expression='some_expression_2',
                content=some_content_2,
            ),
            pre_ast.ConditionalBlock(
                conditional_expression='some_expression_3',
                content='some_content_3',
            ),
        ],
        else_content='else_content',
    )
    self.expression_evaluator.evaluate.side_effect = (
        c_ast.CNumber(0),
        c_ast.CNumber(1),
    )
    some_content_2.accept.return_value = 24
    actual = self.preprocessing_visitor.preprocess(if_)
    self.assertEqual(actual, 24)

  def test_preprocess_with_composite_block(self):
    mock_node_1 = mock.MagicMock()
    mock_node_2 = mock.MagicMock()
    mock_node_3 = mock.MagicMock()
    composite_block = pre_ast.CompositeBlock([
        mock_node_1,
        mock_node_2,
        mock_node_3,
    ])
    mock_node_1.accept.return_value = 42
    mock_node_2.accept.return_value = 33
    mock_node_3.accept.return_value = 24
    actual = self.preprocessing_visitor.preprocess(composite_block)
    expected = pre_ast.CompositeBlock([42, 33, 24])
    self.assertEqual(actual, expected)

  def test_preprocess_with_text_block(self):
    text_block = pre_ast.TextBlock('some_text')
    self.macro_expander.expand.return_value = 'some_other_text'
    actual = self.preprocessing_visitor.preprocess(text_block)
    expected = pre_ast.TextBlock('some_other_text')
    self.assertEqual(actual, expected)
    self.macro_expander.expand.assert_called_with('some_text')

if __name__ == '__main__':
  unittest.main()
