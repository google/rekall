from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

import mock

from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.visitors import expression_evaluator_visitor


class TestExpressionEvaluatorVisitor(unittest.TestCase):

  def f1(self, x, y):
    self.x.append(x)
    self.y.append(y)
    return 33

  def f2(self, z):
    self.z.append(z)
    return 42

  def setUp(self):
    self.variables = {
        'a': 'b',
        'c': 'd',
    }
    self.x = []
    self.y = []
    self.z = []
    self.functions = {
        'f1': self.f1,
        'f2': self.f2,
    }
    self.expression_evaluator = (
        expression_evaluator_visitor.ExpressionEvaluatorVisitor(
            self.variables,
            self.functions,
        )
    )

  def test_evaluate(self):
    expression = mock.MagicMock()
    expression.accept.return_value = 24
    actual = self.expression_evaluator.evaluate(expression)
    self.assertEqual(actual, 24)

  def test_visit_function_call(self):
    function_call = c_ast.CFunctionCall(
        function_name='f1',
        arguments=[
            c_ast.CNumber(24),
            c_ast.CLiteral('literal'),
        ],
    )
    actual = self.expression_evaluator.evaluate(function_call)
    self.assertEqual(actual, 33)
    self.assertEqual(self.x, [24])
    self.assertEqual(self.y, ['literal'])

  def test_visit_nested_expression(self):
    expression = c_ast.CNestedExpression(
        opener='(',
        content=c_ast.CVariable('a'),
        closer=')',
    )
    actual = self.expression_evaluator.evaluate(expression)
    self.assertEqual(actual, 'b')

  def test_visit_variable(self):
    variable = c_ast.CVariable('c')
    actual = self.expression_evaluator.evaluate(variable)
    self.assertEqual(actual, 'd')

  def test_visit_number(self):
    number = c_ast.CNumber(42)
    actual = self.expression_evaluator.evaluate(number)
    self.assertEqual(actual, 42)

  def test_visit_literal(self):
    literal = c_ast.CLiteral('value')
    actual = self.expression_evaluator.evaluate(literal)
    self.assertEqual(actual, 'value')


if __name__ == '__main__':
  unittest.main()

