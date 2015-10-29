from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.c_ast import pre_ast
from rekall.layout_expert.preprocessing_visitors import macro_expression_evaluator_visitor


class MacroExpressionEvaluatorVisitorTest(unittest.TestCase):

  def setUp(self):
    self.object_likes = {}
    self.function_likes = {}
    self.functions = {
        '+': lambda x, y: c_ast.CNumber(x.value + y.value),
        '*': lambda x, y: c_ast.CNumber(x.value * y.value),
    }
    self.lazy_functions = {
        'defined': self._defined,
    }
    self.evaluator = (
        macro_expression_evaluator_visitor.MacroExpressionEvaluatorVisitor(
            self.object_likes,
            self.function_likes,
            self.functions,
            self.lazy_functions,
        )
    )

  def _defined(self, evaluate, variable):
    _ = evaluate
    return (
        variable.name in self.object_likes
        or variable.name in self.function_likes
    )

  def test_evaluate_undefined_identifier(self):
    expression = c_ast.CVariable('foo')
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CVariable('foo')
    self.assertEqual(actual, expected)

  def test_evaluate_identifier_defined_to_empty_string(self):
    self.object_likes.update({
        'foo': pre_ast.DefineObjectLike(
            name='foo',
            replacement=None,
            string_replacement='',
        ),
    })
    expression = c_ast.CVariable('foo')
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CLiteral('')
    self.assertEqual(actual, expected)

  def test_evaluate_identifier_defined_to_undefined_identifier(self):
    self.object_likes.update({
        'foo': pre_ast.DefineObjectLike(
            name='foo',
            replacement=c_ast.CVariable('bar'),
            string_replacement='bar',
        ),
    })
    expression = c_ast.CVariable('foo')
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CVariable('bar')
    self.assertEqual(actual, expected)

  def test_evaluate_identifier_defined_to_identifier_defined_to_empty_string(
      self,
  ):
    self.object_likes.update({
        'foo': pre_ast.DefineObjectLike(
            name='foo',
            replacement=c_ast.CVariable('bar'),
            string_replacement='bar',
        ),
        'bar': pre_ast.DefineObjectLike(
            name='bar',
            replacement=None,
            string_replacement='',
        )
    })
    expression = c_ast.CVariable('foo')
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CLiteral('')
    self.assertEqual(actual, expected)

  def test_evaluate_identifier_defined_to_identifier_defined_to_undefined_id(
      self,
  ):
    self.object_likes.update({
        'foo': pre_ast.DefineObjectLike(
            name='foo',
            replacement=c_ast.CVariable('bar'),
            string_replacement='bar',
        ),
        'bar': pre_ast.DefineObjectLike(
            name='bar',
            replacement=c_ast.CLiteral('baz'),
            string_replacement='baz',
        ),
    })
    expression = c_ast.CVariable('foo')
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CVariable('baz')
    self.assertEqual(actual, expected)

  def test_evaluate_nested_expression(self):
    self.object_likes.update({
        'foo': pre_ast.DefineObjectLike(
            name='foo',
            replacement=c_ast.CNumber(42),
            string_replacement='42',
        ),
        'bar': pre_ast.DefineObjectLike(
            name='bar',
            replacement=c_ast.CNumber(33),
            string_replacement='33',
        ),
    })
    expression = c_ast.CNestedExpression(
        opener='(',
        content=c_ast.CVariable('foo'),
        closer=')',
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(42)
    self.assertEqual(actual, expected)

  def test_keep_parentheses_in_nested_expression(self):
    evaluator = (
        macro_expression_evaluator_visitor.MacroExpressionEvaluatorVisitor(
            object_likes=self.object_likes,
            function_likes=self.function_likes,
            functions=self.functions,
            lazy_functions=self.lazy_functions,
            keep_parentheses=True,
        )
    )
    self.object_likes.update({
        'foo': pre_ast.DefineObjectLike(
            name='foo',
            replacement=c_ast.CNumber(42),
            string_replacement='42',
        ),
        'bar': pre_ast.DefineObjectLike(
            name='bar',
            replacement=c_ast.CNumber(33),
            string_replacement='33',
        ),
    })
    expression = c_ast.CNestedExpression(
        opener='(',
        content=c_ast.CVariable('foo'),
        closer=')',
    )
    actual = evaluator.evaluate(expression)
    expected = c_ast.CNestedExpression(
        opener='(',
        content=c_ast.CNumber(42),
        closer=')',
    )
    self.assertEqual(actual, expected)

  def test_evaluate_cycle_in_object_like_definitions(
      self,
  ):
    self.object_likes.update({
        'foo': pre_ast.DefineObjectLike(
            name='foo',
            replacement=c_ast.CVariable('bar'),
            string_replacement='bar',
        ),
        'bar': pre_ast.DefineObjectLike(
            name='bar',
            replacement=c_ast.CVariable('baz'),
            string_replacement='baz',
        ),
        'baz': pre_ast.DefineObjectLike(
            name='baz',
            replacement=c_ast.CVariable('foo'),
            string_replacement='foo',
        ),
    })
    expression = c_ast.CVariable('foo')
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CVariable('foo')
    self.assertEqual(actual, expected)

  def test_evaluate_function_call_with_identifier_defined_to_other_identifier(
      self,
  ):
    self.object_likes.update({
        'foo': pre_ast.DefineObjectLike(
            name='foo',
            replacement=c_ast.CVariable('bar'),
            string_replacement='bar',
        ),
    })
    self.function_likes.update({
        'bar': pre_ast.DefineFunctionLike(
            name='bar',
            arguments=['x'],
            replacement=c_ast.CNumber(42),
            string_replacement='42',
        ),
    })
    expression = c_ast.CFunctionCall(
        function_name='foo',
        arguments=[c_ast.CVariable('x')],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(42)
    self.assertEqual(actual, expected)

  def test_evaluate_function_call_with_arguments(
      self,
  ):
    self.function_likes.update({
        'foo': pre_ast.DefineFunctionLike(
            name='foo',
            arguments=['x', 'y'],
            replacement=c_ast.CVariable('y'),
            string_replacement='y',
        ),
    })
    expression = c_ast.CFunctionCall(
        function_name='foo',
        arguments=[
            c_ast.CNumber(42),
            c_ast.CNumber(33),
        ],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(33)
    self.assertEqual(actual, expected)

  def test_evaluate_argument(
      self,
  ):
    self.object_likes.update({
        'foo': pre_ast.DefineObjectLike(
            name='foo',
            replacement=c_ast.CNumber(42),
            string_replacement='42',
        )
    })
    expression = c_ast.CFunctionCall(
        function_name='f',
        arguments=[c_ast.CVariable('foo')],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CFunctionCall(
        function_name='f',
        arguments=[c_ast.CNumber(42)],
    )
    self.assertEqual(actual, expected)

  def test_evaluate_cycle_in_function_like_definitions(
      self,
  ):
    self.function_likes.update({
        'foo': pre_ast.DefineFunctionLike(
            name='foo',
            arguments=[],
            replacement=c_ast.CFunctionCall(
                function_name='bar',
                arguments=[],
            ),
            string_replacement='bar()',
        ),
        'bar': pre_ast.DefineFunctionLike(
            name='bar',
            arguments=[],
            replacement=c_ast.CFunctionCall(
                function_name='baz',
                arguments=[],
            ),
            string_replacement='baz()',
        ),
        'baz': pre_ast.DefineFunctionLike(
            name='baz',
            arguments=[],
            replacement=c_ast.CFunctionCall(
                function_name='foo',
                arguments=[],
            ),
            string_replacement='foo()',
        ),
    })
    expression = c_ast.CFunctionCall(
        function_name='foo',
        arguments=[],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CFunctionCall(
        function_name='foo',
        arguments=[],
    )
    self.assertEqual(actual, expected)

  def test_evaluate_function_like_argument_overshadows_object_like_variable(
      self,
  ):
    self.object_likes.update({
        'x': pre_ast.DefineObjectLike(
            name='x',
            replacement=c_ast.CFunctionCall(
                function_name='f',
                arguments=[
                    c_ast.CNumber(42),
                ]
            ),
            string_replacement='f(42)',
        ),
    })
    self.function_likes.update({
        'f': pre_ast.DefineFunctionLike(
            name='f',
            arguments=['x'],
            replacement=c_ast.CVariable('x'),
            string_replacement='x',
        ),
    })
    expression = c_ast.CVariable('x')
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(42)
    self.assertEqual(actual, expected)

  def test_evaluate_no_implicit_function_like_argument_pass(
      self,
  ):
    self.function_likes.update({
        'f': pre_ast.DefineFunctionLike(
            name='f',
            arguments=['x'],
            replacement=c_ast.CFunctionCall(
                function_name='g',
                arguments=[],
            ),
            string_replacement='g()',
        ),
        'g': pre_ast.DefineFunctionLike(
            name='g',
            arguments=[],
            replacement=c_ast.CVariable('x'),
            string_replacement='x',
        ),
    })
    expression = c_ast.CVariable('x')
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CVariable('x')
    self.assertEqual(actual, expected)

  def test_evaluate_nested_call_access_top_level_variable(
      self,
  ):
    self.object_likes.update({
        'x': pre_ast.DefineObjectLike(
            name='x',
            replacement=c_ast.CNumber(33),
            string_replacement='33',
        ),
    })
    self.function_likes.update({
        'f': pre_ast.DefineFunctionLike(
            name='f',
            arguments=['x'],
            replacement=c_ast.CFunctionCall(
                function_name='g',
                arguments=[],
            ),
            string_replacement='g()',
        ),
        'g': pre_ast.DefineFunctionLike(
            name='g',
            arguments=[],
            replacement=c_ast.CVariable('x'),
            string_replacement='x',
        ),
    })
    expression = c_ast.CVariable('x')
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(33)
    self.assertEqual(actual, expected)

  def test_evaluate_argument_overshadows_top_level_variable(
      self,
  ):
    self.object_likes.update({
        'x': pre_ast.DefineObjectLike(
            name='x',
            replacement=c_ast.CNumber(33),
            string_replacement='33',
        ),
    })
    self.function_likes.update({
        'f': pre_ast.DefineFunctionLike(
            name='f',
            arguments=['x'],
            replacement=c_ast.CVariable('x'),
            string_replacement='x',
        ),
    })
    expression = c_ast.CFunctionCall(
        function_name='f',
        arguments=[c_ast.CNumber(42)],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(42)
    self.assertEqual(actual, expected)

  def test_evaluate_against_mistnesting(
      self,
  ):
    self.function_likes.update({
        'twice': pre_ast.DefineFunctionLike(
            name='twice',
            arguments=['x'],
            replacement=c_ast.CFunctionCall(
                function_name='*',
                arguments=[
                    c_ast.CNumber(2),
                    c_ast.CVariable('x'),
                ],
            ),
            string_replacement='(2*(x))',
        ),
        'call_with_1': pre_ast.DefineFunctionLike(
            name='call_with_1',
            arguments=['x'],
            replacement=c_ast.CFunctionCall(
                function_name='x',
                arguments=[c_ast.CNumber(1)],
            ),
            string_replacement='(2*(x))',
        ),
    })
    expression = c_ast.CFunctionCall(
        function_name='call_with_1',
        arguments=[c_ast.CVariable('twice')],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(2)
    self.assertEqual(actual, expected)

  def test_evaluate_same_function_call_as_argument(self):
    self.function_likes.update({
        'f': pre_ast.DefineFunctionLike(
            name='f',
            arguments=['x'],
            replacement=c_ast.CVariable('x'),
            string_replacement='x',
        ),
    })
    expression = c_ast.CFunctionCall(
        function_name='f',
        arguments=[
            c_ast.CFunctionCall(
                function_name='f',
                arguments=[
                    c_ast.CNumber(42),
                ],
            ),
        ],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(42)
    self.assertEqual(actual, expected)

  def test_evaluate_variable_and_function_argument_cycle(
      self,
  ):
    self.object_likes.update({
        'x': pre_ast.DefineObjectLike(
            name='x',
            replacement=c_ast.CFunctionCall(
                function_name='f',
                arguments=[c_ast.CVariable('x')],
            ),
            string_replacement='f(x)',
        ),
    })
    self.function_likes.update({
        'f': pre_ast.DefineFunctionLike(
            name='f',
            arguments=['x'],
            replacement=c_ast.CVariable('x'),
            string_replacement='x',
        ),
    })
    expression = c_ast.CVariable('x')
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CVariable('x')
    self.assertEqual(actual, expected)

  def test_evaluate_object_like_with_simple_recursion(
      self,
  ):
    self.object_likes.update({
        'x': pre_ast.DefineObjectLike(
            name='x',
            replacement=c_ast.CVariable('x'),
            string_replacement='x',
        ),
    })
    expression = c_ast.CVariable('x')
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CVariable('x')
    self.assertEqual(actual, expected)

  def test_evaluate_function_like_with_simple_recursion(
      self,
  ):
    self.function_likes.update({
        'f': pre_ast.DefineFunctionLike(
            name='f',
            arguments=['x'],
            replacement=c_ast.CFunctionCall(
                function_name='f',
                arguments=[c_ast.CVariable('x')],
            ),
            string_replacement='f(x)',
        ),
    })
    expression = c_ast.CFunctionCall(
        function_name='f',
        arguments=[c_ast.CNumber(42)],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CFunctionCall(
        function_name='f',
        arguments=[c_ast.CNumber(42)],
    )
    self.assertEqual(actual, expected)

  def test_evaluate_function_argument_cycle_with_composition(
      self,
  ):
    self.function_likes.update({
        'f': pre_ast.DefineFunctionLike(
            name='f',
            arguments=['x'],
            replacement=c_ast.CFunctionCall(
                function_name='f',
                arguments=[
                    c_ast.CFunctionCall(
                        function_name='f',
                        arguments=[c_ast.CVariable('x')],
                    ),
                ],
            ),
            string_replacement='f(f(x))',
        ),
    })
    expression = c_ast.CFunctionCall(
        function_name='f',
        arguments=[c_ast.CNumber(42)],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CFunctionCall(
        function_name='f',
        arguments=[
            c_ast.CFunctionCall(
                function_name='f',
                arguments=[c_ast.CNumber(42)],
            )
        ]
    )
    self.assertEqual(actual, expected)

  def test_evaluate_function_variable_cycle(
      self,
  ):
    self.object_likes.update({
        'y': pre_ast.DefineObjectLike(
            name='y',
            replacement=c_ast.CFunctionCall(
                function_name='f',
                arguments=[c_ast.CVariable('x')],
            ),
            string_replacement='f(x)',
        ),
    })
    self.function_likes.update({
        'f': pre_ast.DefineFunctionLike(
            name='f',
            arguments=['x'],
            replacement=c_ast.CVariable('y'),
            string_replacement='y',
        ),
    })
    expression = c_ast.CFunctionCall(
        function_name='f',
        arguments=[c_ast.CNumber(42)],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CFunctionCall(
        function_name='f',
        arguments=[c_ast.CVariable('x')],
    )
    self.assertEqual(actual, expected)

  def test_evaluate_variable_cycle_with_self_call(
      self,
  ):
    self.object_likes.update({
        'x': pre_ast.DefineObjectLike(
            name='x',
            replacement=c_ast.CFunctionCall(
                function_name='x',
                arguments=[c_ast.CVariable('x')],
            ),
            string_replacement='x(x)',
        ),
    })
    expression = c_ast.CVariable('x')
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CFunctionCall(
        function_name='x',
        arguments=[c_ast.CVariable('x')],
    )
    self.assertEqual(actual, expected)

  def test_evaluate_function_argument_self_call(
      self,
  ):
    self.function_likes.update({
        'f': pre_ast.DefineFunctionLike(
            name='f',
            arguments=['f'],
            replacement=c_ast.CFunctionCall(
                function_name='f',
                arguments=[c_ast.CVariable('f')],
            ),
            string_replacement='f(f)',
        ),
    })
    expression = c_ast.CFunctionCall(
        function_name='f',
        arguments=[c_ast.CVariable('x')],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CFunctionCall(
        function_name='x',
        arguments=[c_ast.CVariable('x')],
    )
    self.assertEqual(actual, expected)

  def test_evaluate_with_argument_to_resolve_named_as_unresolvable_object(
      self,
  ):
    self.object_likes.update({
        'x': pre_ast.DefineObjectLike(
            name='x',
            replacement=c_ast.CFunctionCall(
                function_name='f',
                arguments=[c_ast.CNumber(42)],
            ),
            string_replacement='f(42)',
        ),
    })
    self.function_likes.update({
        'f': pre_ast.DefineFunctionLike(
            name='f',
            arguments=['x'],
            replacement=c_ast.CVariable('x'),
            string_replacement='x',
        ),
    })
    expression = c_ast.CVariable('x')
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(42)
    self.assertEqual(actual, expected)

  def test_evaluate_with_argument_to_resolve_named_as_unresolvable_function(
      self,
  ):
    self.function_likes.update({
        'f': pre_ast.DefineFunctionLike(
            name='f',
            arguments=['x'],
            replacement=c_ast.CFunctionCall(
                function_name='g',
                arguments=[c_ast.CVariable('h')],
            ),
            string_replacement='g(h)',
        ),
        'g': pre_ast.DefineFunctionLike(
            name='g',
            arguments=['f'],
            replacement=c_ast.CFunctionCall(
                function_name='f',
                arguments=[c_ast.CNumber(42)],
            ),
            string_replacement='f(42)',
        ),
    })
    expression = c_ast.CFunctionCall(
        function_name='f',
        arguments=[c_ast.CNumber(33)],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CFunctionCall(
        function_name='h',
        arguments=[c_ast.CNumber(42)],
    )
    self.assertEqual(actual, expected)

  def test_evaluate_with_simple_arithmetic(
      self,
  ):
    expression = c_ast.CFunctionCall(
        function_name='+',
        arguments=[
            c_ast.CNumber(3),
            c_ast.CNumber(4),
        ],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(7)
    self.assertEqual(actual, expected)

  def test_evaluate_with_arithmetic_with_two_operators(
      self,
  ):
    expression = c_ast.CFunctionCall(
        function_name='*',
        arguments=[
            c_ast.CFunctionCall(
                function_name='+',
                arguments=[
                    c_ast.CNumber(2),
                    c_ast.CNumber(3),
                ],
            ),
            c_ast.CFunctionCall(
                function_name='+',
                arguments=[
                    c_ast.CNumber(5),
                    c_ast.CNumber(7),
                ],
            ),
        ],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(60)
    self.assertEqual(actual, expected)

  def test_evaluate_with_arithmetic_with_the_same_operator_twice(
      self,
  ):
    expression = c_ast.CFunctionCall(
        function_name='+',
        arguments=[
            c_ast.CFunctionCall(
                function_name='+',
                arguments=[
                    c_ast.CNumber(2),
                    c_ast.CNumber(3),
                ],
            ),
            c_ast.CNumber(4),
        ],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(9)
    self.assertEqual(actual, expected)

  def test_evaluate_defined_with_undefined_identifier(
      self,
  ):
    expression = c_ast.CFunctionCall(
        function_name='defined',
        arguments=[c_ast.CVariable('x')],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(0)
    self.assertEqual(actual, expected)

  def test_evaluate_defined_with_defined_object_like(
      self,
  ):
    self.object_likes.update({
        'x': pre_ast.DefineObjectLike(
            name='x',
            replacement=c_ast.CLiteral(''),
            string_replacement='',
        ),
    })
    expression = c_ast.CFunctionCall(
        function_name='defined',
        arguments=[c_ast.CVariable('x')],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(1)
    self.assertEqual(actual, expected)

  def test_evaluate_defined_with_defined_function_like(
      self,
  ):
    self.function_likes.update({
        'f': pre_ast.DefineFunctionLike(
            name='f',
            arguments=['x'],
            replacement=c_ast.CVariable('x'),
            string_replacement='x',
        ),
    })
    expression = c_ast.CFunctionCall(
        function_name='defined',
        arguments=[c_ast.CVariable('f')],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(1)
    self.assertEqual(actual, expected)

  def test_transform_result_to_integer(
      self,
  ):
    expression = c_ast.CVariable('42ULL')
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(42)
    self.assertEqual(actual, expected)

  def test_transform_result_to_integer_as_hex(
      self,
  ):
    expression = c_ast.CVariable('0x33')
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(51)
    self.assertEqual(actual, expected)

  def test_evaluate_with_argument_passing_to_function_call(
      self,
  ):
    self.function_likes.update({
        'f': pre_ast.DefineFunctionLike(
            name='f',
            arguments=['x'],
            replacement=c_ast.CFunctionCall(
                function_name='g',
                arguments=[c_ast.CVariable('x')],
            ),
            string_replacement='g(x)',
        ),
        'g': pre_ast.DefineFunctionLike(
            name='g',
            arguments=['y'],
            replacement=c_ast.CVariable('y'),
            string_replacement='y',
        ),
    })
    expression = c_ast.CFunctionCall(
        function_name='f',
        arguments=[c_ast.CNumber(42)],
    )
    actual = self.evaluator.evaluate(expression)
    expected = c_ast.CNumber(42)
    self.assertEqual(actual, expected)


if __name__ == '__main__':
  unittest.main()
