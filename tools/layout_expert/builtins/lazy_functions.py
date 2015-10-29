"""A module containing funcions that operate on unevaluated AST expressions."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import functools


def get_lazy_and_state_dependent_functions(object_likes, function_likes):
  functions = get_lazy_functions()
  functions.update(get_state_dependent_functions(object_likes, function_likes))
  return functions


def get_lazy_functions():
  return {
      '&&': _lazy_and,
      '||': _lazy_or,
      '?:': _lazy_conditional,
  }


def get_state_dependent_functions(object_likes, function_likes):
  return {
      'defined': functools.partial(_defined, object_likes, function_likes),
      'IS_ENABLED': functools.partial(_is_enabled, object_likes),
      'IS_BUILTIN': functools.partial(_is_builtin, object_likes),
      'IS_MODULE': functools.partial(_is_module, object_likes),
  }


def _lazy_and(evaluate, x, y):
  evaluated_x = evaluate(x)
  return evaluate(y) if evaluated_x.value else evaluated_x


def _lazy_or(evaluate, x, y):
  evaluated_x = evaluate(x)
  return evaluated_x if evaluated_x.value else evaluate(y)


def _lazy_conditional(evaluate, condition, if_true, if_false):
  evaluated_condition = evaluate(condition)
  return evaluate(if_true) if evaluated_condition.value else evaluate(if_false)


def _defined(object_likes, function_likes, evaluate, variable):
  _ = evaluate
  result = variable.name in object_likes or variable.name in function_likes
  return result


def _is_enabled(object_likes, evaluate, variable):
  _ = evaluate
  flag = variable.name
  module_flag = flag + '_MODULE'
  return flag in object_likes or module_flag in object_likes


def _is_builtin(object_likes, evaluate, variable):
  _ = evaluate
  flag = variable.name
  return flag in object_likes


def _is_module(object_likes, evaluate, variable):
  _ = evaluate
  flag = variable.name
  module_flag = flag + '_MODULE'
  return module_flag in object_likes
