from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest


import mock

from rekall.layout_expert.builtins import lazy_functions
from rekall.layout_expert.c_ast import c_ast


class TestGetLazyAndStateDependentFunctions(unittest.TestCase):

  def setUp(self):
    self.object_likes = {}
    self.function_likes = {}
    self.lazy_and_state_dependent_functions = (
        lazy_functions.get_lazy_and_state_dependent_functions(
            object_likes=self.object_likes,
            function_likes=self.function_likes,
        )
    )

  def test_lazy_functions(self):
    for name, function in lazy_functions.get_lazy_functions().iteritems():
      self.assertEqual(
          self.lazy_and_state_dependent_functions[name],
          function,
      )

  def test_state_dependent_functions(self):
    state_dependent_functions = lazy_functions.get_state_dependent_functions(
        object_likes=self.object_likes,
        function_likes=self.function_likes,
    )
    for name, expected_function in state_dependent_functions.iteritems():
      actual_function = self.lazy_and_state_dependent_functions[name]
      self.assertEqual(
          actual_function.func,
          expected_function.func,
      )
      self.assertEqual(
          actual_function.args,
          expected_function.args,
      )
      self.assertEqual(
          actual_function.keywords,
          expected_function.keywords,
      )


class TestGetLazyFuncions(unittest.TestCase):

  def setUp(self):
    self.lazy_functions = lazy_functions.get_lazy_functions()
    self.evaluate = mock.MagicMock()

  def test_lazy_and_with_false_first(self):
    self.evaluate.return_value = c_ast.CNumber(0)
    actual = self.lazy_functions['&&'](self.evaluate, 42, 33)
    self.evaluate.assert_called_once_with(42)
    expected = c_ast.CNumber(0)
    self.assertEqual(actual, expected)

  def test_lazy_and_with_true_and_false(self):
    self.evaluate.side_effect = (
        c_ast.CNumber(24),
        c_ast.CNumber(0),
    )
    actual = self.lazy_functions['&&'](self.evaluate, 42, 33)
    self.evaluate.assert_has_calls([
        mock.call(42),
        mock.call(33),
    ])
    expected = c_ast.CNumber(0)
    self.assertEqual(actual, expected)

  def test_lazy_and_with_true_and_true(self):
    self.evaluate.side_effect = (
        c_ast.CNumber(24),
        c_ast.CNumber(15),
    )
    actual = self.lazy_functions['&&'](self.evaluate, 42, 33)
    self.evaluate.assert_has_calls([
        mock.call(42),
        mock.call(33),
    ])
    expected = c_ast.CNumber(15)
    self.assertEqual(actual, expected)

  def test_lazy_or_with_true_first(self):
    self.evaluate.return_value = c_ast.CNumber(24)
    actual = self.lazy_functions['||'](self.evaluate, 42, 33)
    self.evaluate.assert_called_once_with(42)
    expected = c_ast.CNumber(24)
    self.assertEqual(actual, expected)

  def test_lazy_or_with_false_and_false(self):
    self.evaluate.side_effect = (
        c_ast.CNumber(0),
        c_ast.CNumber(0),
    )
    actual = self.lazy_functions['||'](self.evaluate, 42, 33)
    self.evaluate.assert_has_calls([
        mock.call(42),
        mock.call(33),
    ])
    expected = c_ast.CNumber(0)
    self.assertEqual(actual, expected)

  def test_lazy_or_with_false_and_true(self):
    self.evaluate.side_effect = (
        c_ast.CNumber(0),
        c_ast.CNumber(15),
    )
    actual = self.lazy_functions['||'](self.evaluate, 42, 33)
    self.evaluate.assert_has_calls([
        mock.call(42),
        mock.call(33),
    ])
    expected = c_ast.CNumber(15)
    self.assertEqual(actual, expected)

  def test_lazy_conditional_with_true(self):
    self.evaluate.side_effect = (
        c_ast.CNumber(5),
        c_ast.CNumber(7),
    )
    actual = self.lazy_functions['?:'](self.evaluate, 42, 33, 24)
    expected_evaluate_calls = [
        mock.call(42),
        mock.call(33),
    ]
    self.assertEqual(self.evaluate.call_args_list, expected_evaluate_calls)
    expected = c_ast.CNumber(7)
    self.assertEqual(actual, expected)

  def test_lazy_conditional_with_false(self):
    self.evaluate.side_effect = (
        c_ast.CNumber(0),
        c_ast.CNumber(4),
    )
    actual = self.lazy_functions['?:'](self.evaluate, 42, 33, 24)
    expected_evaluate_calls = [
        mock.call(42),
        mock.call(24),
    ]
    self.assertEqual(self.evaluate.call_args_list, expected_evaluate_calls)
    expected = c_ast.CNumber(4)
    self.assertEqual(actual, expected)


class TestGetStateDependentFunctions(unittest.TestCase):

  def setUp(self):
    self.object_likes = {}
    self.function_likes = {}
    self.state_dependent_functions = (
        lazy_functions.get_state_dependent_functions(
            object_likes=self.object_likes,
            function_likes=self.function_likes,
        )
    )

  def test_defined_with_name_in_object_likes(self):
    self.object_likes.update({
        'some_name': None,
    })
    defined = self.state_dependent_functions['defined']
    actual = defined(
        evaluate=None,
        variable=c_ast.CVariable('some_name'),
    )
    self.assertTrue(actual)

  def test_defined_with_name_in_function_likes(self):
    self.function_likes.update({
        'some_name': None,
    })
    defined = self.state_dependent_functions['defined']
    actual = defined(
        evaluate=None,
        variable=c_ast.CVariable('some_name'),
    )
    self.assertTrue(actual)

  def test_defined_with_undefined_name(self):
    self.object_likes.update({
        'some_name_1': None,
    })
    self.function_likes.update({
        'some_name_2': None,
    })
    defined = self.state_dependent_functions['defined']
    actual = defined(
        evaluate=None,
        variable=c_ast.CVariable('some_name_3'),
    )
    self.assertFalse(actual)

  def test_is_enabled_with_flag_set(self):
    self.object_likes.update({
        'SOME_FLAG': None,
    })
    is_enabled = self.state_dependent_functions['IS_ENABLED']
    actual = is_enabled(
        evaluate=None,
        variable=c_ast.CVariable('SOME_FLAG'),
    )
    self.assertTrue(actual)

  def test_is_enabled_with_module_flag_set(self):
    self.object_likes.update({
        'SOME_FLAG_MODULE': None,
    })
    is_enabled = self.state_dependent_functions['IS_ENABLED']
    actual = is_enabled(
        evaluate=None,
        variable=c_ast.CVariable('SOME_FLAG'),
    )
    self.assertTrue(actual)

  def test_is_enabled_with_flag_not_set(self):
    self.function_likes.update({
        'SOME_FLAG': None,
        'SOME_FLAG_MODULE': None,
    })
    is_enabled = self.state_dependent_functions['IS_ENABLED']
    actual = is_enabled(
        evaluate=None,
        variable=c_ast.CVariable('SOME_FLAG'),
    )
    self.assertFalse(actual)

