"""A module containing a class for evaluating macros given as AST tree."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import functools
import re

from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.c_ast import pre_ast


class MacroExpressionEvaluatorVisitor(object):
  """A class for evaluating macros given as AST tree."""

  _C_IDENTIFIER_OR_LITERAL_PATTERN = re.compile('^[a-zA-Z0-9_]+$')
  _C_INT_PATTERN = re.compile(
      '^(?P<number>(0x)?[0-9]+)(u|U)?(l|ll|L|LL)?$',
  )

  def __init__(
      self,
      object_likes,
      function_likes,
      functions,
      lazy_functions,
      keep_parentheses=False,
  ):
    self._object_likes = object_likes
    self._function_likes = function_likes
    self._functions = functions
    self._lazy_functions = lazy_functions
    self._keep_parentheses = keep_parentheses

  def evaluate(self, expression, arguments=None, currently_evaluating=None):
    """Evaluates a macro expression. (from AST form to AST form)."""
    if not arguments:
      arguments = {}
    if not currently_evaluating:
      currently_evaluating = []
    unwrapped_result = expression.accept(self, arguments, currently_evaluating)
    return self._wrap_result(unwrapped_result)

  def _wrap_result(self, result):
    """This method converts the result to the type of the proper AST Node."""
    if isinstance(result, bool):
      result = c_ast.CNumber(1 if result else 0)
    if isinstance(result, int):
      result = c_ast.CNumber(result)
    if isinstance(result, basestring):
      result = c_ast.CLiteral(result)
    if isinstance(result, c_ast.CLiteral):
      if self._C_IDENTIFIER_OR_LITERAL_PATTERN.match(result.value):
        result = c_ast.CVariable(result.value)
    if isinstance(result, c_ast.CVariable):
      match = self._C_INT_PATTERN.match(result.name)
      if match:
        result = c_ast.CNumber(int(match.group('number'), base=0))
    return result

  def visit_c_function_call(
      self,
      function_call,
      arguments,
      currently_evaluating,
  ):
    """Evaluates a function call."""
    evaluate = functools.partial(
        self.evaluate,
        arguments=arguments,
        currently_evaluating=currently_evaluating,
    )
    function_name = self._evaluate_name(evaluate, function_call.function_name)

    if function_name in self._lazy_functions:
      function = self._lazy_functions[function_name]
      return function(evaluate, *function_call.arguments)

    return self._evaluate_eager_function(
        evaluate,
        function_name,
        function_call.arguments,
        currently_evaluating,
    )

  def _evaluate_name(self, evaluate, name):
    evaluated_name = evaluate(c_ast.CVariable(name))
    if hasattr(evaluated_name, 'name'):
      name = evaluated_name.name
    return name

  def _evaluate_eager_function(
      self,
      evaluate,
      function_name,
      function_arguments,
      currently_evaluating,
  ):
    """Evaluates a function with eager evaluation of the arguments."""
    evaluated_arguments = map(evaluate, function_arguments)

    if function_name not in currently_evaluating:
      if function_name in self._function_likes:
        return self._evaluate_function_like(
            function_name,
            evaluated_arguments,
            currently_evaluating,
        )

    if function_name in self._functions:
      return self._functions[function_name](*evaluated_arguments)
    return c_ast.CFunctionCall(
        function_name=function_name,
        arguments=evaluated_arguments,
    )

  def _evaluate_function_like(
      self,
      function_name,
      evaluated_arguments,
      currently_evaluating,
  ):
    function_like = self._function_likes[function_name]
    replacement = function_like.replacement
    if replacement:
      argument_names = function_like.arguments
      function_arguments = dict(zip(argument_names, evaluated_arguments))
      return self.evaluate(
          replacement,
          function_arguments,
          currently_evaluating + [function_name],
      )
    else:
      return function_like.string_replacement

  def visit_c_nested_expression(
      self,
      nested_expression,
      arguments,
      currently_evaluating,
  ):
    evaluated_content = self.evaluate(
        nested_expression.content,
        arguments,
        currently_evaluating,
    )
    if self._keep_parentheses:
      return c_ast.CNestedExpression(
          opener=nested_expression.opener,
          content=evaluated_content,
          closer=nested_expression.closer,
      )
    else:
      return evaluated_content

  def visit_composite_block(
      self,
      composite_block,
      arguments,
      currently_evaluating,
  ):
    evaluated_content = []
    for element in composite_block.content:
      evaluated_element = self.evaluate(
          expression=element,
          arguments=arguments,
          currently_evaluating=currently_evaluating,
      )
      evaluated_content.append(evaluated_element)
    return pre_ast.CompositeBlock(evaluated_content)

  def visit_c_variable(self, variable, arguments, currently_evaluating):
    """Evaluates variable as a macro."""
    name = variable.name
    if name in arguments:
      return self.evaluate(arguments[name], [], currently_evaluating[:-1])
    if name not in currently_evaluating and name in self._object_likes:
      object_like = self._object_likes[name]
      replacement = object_like.replacement
      if replacement:
        return self.evaluate(
            expression=replacement,
            arguments=[],
            currently_evaluating=currently_evaluating + [name],
        )
      return object_like.string_replacement
    return variable

  def visit_c_number(self, number, arguments, currently_evaluating):
    _ = arguments
    _ = currently_evaluating
    return number

  def visit_c_literal(self, literal, arguments, currently_evaluating):
    _ = arguments
    _ = currently_evaluating
    return literal
