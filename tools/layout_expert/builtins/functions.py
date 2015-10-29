"""A module containing definitions of compiler builtin functions.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import operator
from rekall.layout_expert.c_ast import c_ast


def get_64bit_functions():
  """A functions returns a dict with builtin function for 64bit GCC.

  Returns:
    A dict from type names to functions for 64bit GCC.
  """
  return {
      '+': lambda *args: args[0] + args[1] if len(args) > 1 else args[0],
      '-': lambda *args: args[0] - args[1] if len(args) > 1 else -args[0],
      '!': operator.not_,
      '~': operator.inv,
      'defined': lambda x: x is not None,
      '*': operator.mul,
      '/': operator.floordiv,
      '%': operator.mod,
      '<<': operator.lshift,
      '>>': operator.rshift,
      '<': operator.lt,
      '>': operator.gt,
      '<=': operator.le,
      '>=': operator.ge,
      '==': operator.eq,
      '!=': operator.ne,
      '&': operator.and_,
      '^': operator.xor,
      '|': operator.or_,
      '&&': lambda x, y: x and y,
      '||': lambda x, y: x or y,
      '?:': lambda c, x, y: x if c else y,
      '()': lambda _, value: value,
  }


def get_preprocessor_functions():
  return {
      '##': lambda x, y: '%s%s' % (x, y),
  }


def get_preprocessor_and_64bit_functions():
  functions = get_preprocessor_functions()
  functions.update(_get_64bit_functions_wrapped_for_ast_nodes())
  return functions


def _get_64bit_functions_wrapped_for_ast_nodes():
  functions = {}
  for name, function in get_64bit_functions().iteritems():
    if name in ('defined',):
      pass  # defined on c_ast works on unevaluated node
    elif name in ('?:', '()'):
      functions[name] = function
    else:
      functions[name] = _wrap_function_for_ast_nodes(function)
  return functions


def _wrap_function_for_ast_nodes(function_to_wrap):

  def wrapped_function(*args, **kwargs):
    args_values = [arg.value for arg in args]
    kwargs_values = {k: v.value for k, v in kwargs.iteritems()}
    result = function_to_wrap(*args_values, **kwargs_values)
    return c_ast.CNumber(result)

  return wrapped_function
