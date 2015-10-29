"""A module containing an expression parser intended for C header files."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pyparsing

from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.c_ast import pre_ast
from rekall.layout_expert.parser import util

pyparsing.ParserElement.enablePackrat()  # speed hack

_UNARY = 1
_BINARY = 2
_TERNARY = 3

_LEFT = pyparsing.opAssoc.LEFT
_RIGHT = pyparsing.opAssoc.RIGHT

_OPEN_PARENTHESIS = pyparsing.Literal('(').suppress()
_CLOSE_PARENTHESIS = pyparsing.Literal(')').suppress()
_OPEN_BRACKETS = pyparsing.Literal('[').suppress()
_CLOSE_BRACKETS = pyparsing.Literal(']').suppress()

_PRECEDENCE = (
    (('##',), _BINARY, _LEFT),
    (('+', '-', '!', '~'), _UNARY, _RIGHT),
    (('*', '/', '%'), _BINARY, _LEFT),
    (('+', '-'), _BINARY, _LEFT),
    (('<<', '>>'), _BINARY, _LEFT),
    (('<', '<=', '>', '>='), _BINARY, _LEFT),
    (('==', '!='), _BINARY, _LEFT),
    (('&',), _BINARY, _LEFT),
    (('^',), _BINARY, _LEFT),
    (('|',), _BINARY, _LEFT),
    (('&&',), _BINARY, _LEFT),
    (('||',), _BINARY, _LEFT),
    (('?', ':'), _TERNARY, _LEFT)
)

_DEFINED = pyparsing.Keyword('defined')

_SIZEOF = pyparsing.Keyword('sizeof') | pyparsing.Keyword('__sizeof__')
_ALIGNOF = pyparsing.Keyword('__alignof__')

_TYPE_PROPERTY_KEYWORD = _SIZEOF | _ALIGNOF

_PLUS = pyparsing.Literal('+').suppress()
_MINUS = pyparsing.Literal('-').suppress()


def expression_parser():
  """A function returning a (pyparsing) parser for parsing C expressions.

  Returns:
    a (pyparsing) parser for parsing C expressions.
  """
  precedence = []
  for operators, arity, associativity in _PRECEDENCE:
    if arity <= 2:
      operators = pyparsing.Or(map(pyparsing.Literal, operators))
    else:
      operators = tuple(map(pyparsing.Literal, operators))
    precedence.append((
        operators,
        arity,
        associativity,
        _construct_operator(arity),
    ))
  expression = pyparsing.Forward()
  # pylint: disable=expression-not-assigned
  expression << pyparsing.infixNotation(
      baseExpr=_base_or_array_expression(expression),
      opList=precedence,
      lpar=pyparsing.NoMatch(),
      rpar=pyparsing.NoMatch(),
  )
  expression.ignore(pyparsing.cppStyleComment)
  return expression


def _construct_operator(arity):
  if arity == _UNARY:
    return _construct_unary
  elif arity == _BINARY:
    return _construct_binary
  elif arity >= _TERNARY:
    return _construct_ternary_or_more


@util.action
def _construct_unary(expression_tokens):
  operator_name, argument = expression_tokens
  return c_ast.CFunctionCall(
      function_name=operator_name,
      arguments=[argument],
  )


@util.action
def _construct_binary(expression_tokens):
  result = expression_tokens[0]
  operators = expression_tokens[1::2]
  values = expression_tokens[2::2]
  for operator_name, value in zip(operators, values):
    result = c_ast.CFunctionCall(
        function_name=operator_name,
        arguments=[result, value],
    )
  return result


@util.action
def _construct_ternary_or_more(expression_tokens):
  arguments = expression_tokens[::2]
  operators = expression_tokens[1::2]
  function_name = ''.join(operators)
  return c_ast.CFunctionCall(
      function_name=function_name,
      arguments=arguments,
  )


def _base_or_array_expression(expression):
  array_indices = pyparsing.ZeroOrMore(
      _OPEN_BRACKETS
      + expression
      + _CLOSE_BRACKETS
  )
  return (
      _base_expression(expression)
      + pyparsing.Group(array_indices)
  ).setParseAction(_create_base_or_array_expression)


@util.action
def _create_base_or_array_expression(array_expression, indices):
  """Creates FunctionCalls representing array call of a form t[x][y]...[z]."""
  result = array_expression
  for index in indices:
    result = c_ast.CFunctionCall(
        function_name='[]',
        arguments=[
            result,
            index,
        ],
    )
  return result


def _base_expression(expression):
  return (
      _number()
      | _string_literal()
      | _defined()
      | _type_property()
      | _function_call(expression)
      | _variable()
      | _offsetof()
      | _cast_expression(expression)
      | _nested_expression(expression)
  )


def _defined():
  maybe_nested_variable = pyparsing.Forward()
  nested_variable = (
      _OPEN_PARENTHESIS
      + maybe_nested_variable
      + _CLOSE_PARENTHESIS
  )
  # pylint: disable=expression-not-assigned
  maybe_nested_variable << (_variable() | nested_variable)
  return (
      _DEFINED
      + pyparsing.Group(maybe_nested_variable)
  ).setParseAction(util.action(c_ast.CFunctionCall))


def _function_call(expression):
  return (
      ~_TYPE_PROPERTY_KEYWORD
      + _identifier()
      + _OPEN_PARENTHESIS
      + _arguments(expression)
      + _CLOSE_PARENTHESIS
  ).setParseAction(util.action(c_ast.CFunctionCall))


def _arguments(expression):
  return pyparsing.Group(
      pyparsing.Optional(pyparsing.delimitedList(_argument(expression)))
  )


def _argument(expression):
  return (
      _multiword_argument()
      | expression
      | _argument_with_dots()
  )


def _multiword_argument():
  return pyparsing.Group(
      _variable()
      + pyparsing.OneOrMore(_variable())
  ).setParseAction(util.action(pre_ast.CompositeBlock))


def _argument_with_dots():
  return (
      _identifier_with_dots()
  ).setParseAction(util.action(c_ast.CLiteral))


def _type_property():
  return (
      _TYPE_PROPERTY_KEYWORD
      + _OPEN_PARENTHESIS
      + pyparsing.Word(pyparsing.alphanums + ' _*[]')
      + _CLOSE_PARENTHESIS
  ).setParseAction(_create_sizeof_type)


@util.action
def _create_sizeof_type(sizeof, type_name):
  return c_ast.CFunctionCall(
      function_name=sizeof,
      arguments=[c_ast.CLiteral(type_name)],
  )


def _offsetof():
  return (
      _OPEN_PARENTHESIS
      + _OPEN_PARENTHESIS
      + pyparsing.Keyword('size_t').suppress()
      + _CLOSE_PARENTHESIS
      + pyparsing.Literal('&').suppress()
      + _OPEN_PARENTHESIS
      + _OPEN_PARENTHESIS
      + pyparsing.Group(pyparsing.OneOrMore(_identifier()))
      + pyparsing.Literal('*').suppress()
      + _CLOSE_PARENTHESIS
      + pyparsing.Literal('0').suppress()
      + _CLOSE_PARENTHESIS
      + pyparsing.Literal('->').suppress()
      + _identifier()
      + _CLOSE_PARENTHESIS
  ).setParseAction(_create_ofsetof)


@util.action
def _create_ofsetof(type_name_words, field_name):
  type_name = ' '.join(type_name_words)
  return c_ast.CFunctionCall(
      function_name='offsetof',
      arguments=[
          c_ast.CLiteral(type_name),
          c_ast.CLiteral(field_name),
      ],
  )


def _cast_expression(expression):
  """A function returning a (pyparsing) parser for parsing cast expressions.

  Args:
    expression: a pyparsing parser for parsing an expression to be cast.

  Returns:
    A (pyparsing) parser for parsing cast expressions.
  """
  word = pyparsing.Word(pyparsing.alphanums + '_*[]')
  nested = pyparsing.Forward()
  # pylint: disable=expression-not-assigned
  nested << (
      pyparsing.Literal('(')
      + pyparsing.ZeroOrMore(word | nested)
      + pyparsing.Literal(')')
  )
  typeof_expression = pyparsing.Keyword('typeof') + nested
  simple_type_expression = (
      pyparsing.Word(pyparsing.alphanums + ' _[]')
      + pyparsing.Optional(pyparsing.Word(' *'))
  )
  type_expression = (
      typeof_expression
      | simple_type_expression
  )
  return (
      _OPEN_PARENTHESIS
      + pyparsing.Combine(type_expression)
      + _CLOSE_PARENTHESIS
      + ~(_PLUS | _MINUS)
      + expression
  ).setParseAction(_create_cast_expression)


@util.action
def _create_cast_expression(target, expression):
  return c_ast.CFunctionCall(
      function_name='()',
      arguments=[
          c_ast.CLiteral(target),
          expression,
      ],
  )


def _nested_expression(expression):
  return (
      pyparsing.Literal('(')
      + expression
      + pyparsing.Literal(')')
  ).setParseAction(util.action(c_ast.CNestedExpression))


def _variable():
  return (
      _identifier()
  ).addParseAction(util.action(c_ast.CVariable))


def _identifier():
  return pyparsing.Word(pyparsing.alphas + '_', pyparsing.alphanums + '_')


def _identifier_with_dots():
  return pyparsing.Word(pyparsing.alphas + '_.', pyparsing.alphanums + '_.')


def _string_literal():
  return (
      pyparsing.dblQuotedString.copy()
  ).setParseAction(util.action(c_ast.CLiteral))


def _number():
  return _integer().addParseAction(util.action(c_ast.CNumber))


def _integer():
  integer = _hexadecimal_as_string() | _decimal_as_string()
  unsigned_suffix = pyparsing.Literal('u') | 'U'
  size_suffix = pyparsing.Literal('ll') | 'LL' | 'l' | 'L'
  maybe_suffix = (
      pyparsing.Optional(unsigned_suffix)
      + pyparsing.Optional(size_suffix)
  ).suppress()
  return (
      integer
      + maybe_suffix
  ).setParseAction(util.action(int, base=0))


def _decimal_as_string():
  return pyparsing.Word(pyparsing.nums)


def _hexadecimal_as_string():
  return pyparsing.Combine('0x' + pyparsing.Word(pyparsing.hexnums))
