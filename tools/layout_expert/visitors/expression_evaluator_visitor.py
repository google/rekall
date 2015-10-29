"""A module containing a class for evaluating expressions given as AST tree.

Used for evaluation the normal AST.

Evaluates simple expressions in pre-processed AST e.g. calculates size of
array based on size or number of other elements. For example:
int t[10 * sizeof(struct s) + 1]
"""


from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


class ExpressionEvaluatorVisitor(object):
  """A class for evaluating expressions given as AST tree.

  Attributes:
    variables: a dict from string identifiers to the values of the variables.
    functions: a dict from string identifiers to the implementation of the
      functions.
  """

  def __init__(self, variables, functions):
    self._variables = variables
    self._functions = functions

  def evaluate(self, expression):
    return expression.accept(self)

  def visit_c_function_call(self, function_call):
    function = self._functions[function_call.function_name]
    arguments = []
    for argument in function_call.arguments:
      arguments.append(argument.accept(self))
    return function(*arguments)

  def visit_c_nested_expression(self, nested_expression):
    return self.evaluate(nested_expression.content)

  def visit_c_variable(self, variable):
    return self._variables[variable.name]

  def visit_c_number(self, number):
    return number.value

  def visit_c_literal(self, literal):
    return literal.value
