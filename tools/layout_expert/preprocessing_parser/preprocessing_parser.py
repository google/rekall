"""A module containing a parser for unpreprocessed C headers."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pyparsing

from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.c_ast import pre_ast
from rekall.layout_expert.parser import expression_parser
from rekall.layout_expert.parser import parser
from rekall.layout_expert.parser import util

pyparsing.ParserElement.enablePackrat()  # speed hack


class PreprocessingParser(object):

  def __init__(self):
    self.parser = _program()

  def parse(self, source):
    line_continuation = pyparsing.Literal('\\\n')
    ignorable = (
        line_continuation
        | pyparsing.cppStyleComment
        | parser.extern_field()
        | parser.function_definition()
    ).suppress()
    source = ignorable.transformString(source)
    return self.parser.parseString(source, parseAll=True)[0]


def _literal(name):
  return pyparsing.Literal(name).suppress()


_SHARP = _literal('#')
_DOUBLE_QUOTE = _literal('"')
_OPEN_PARENTHESES = _literal('(')
_CLOSE_PARENTHESES = _literal(')')
_OPEN_ANGLE_BRACKETS = _literal('<')
_CLOSE_ANGLE_BRACKETS = _literal('>')
_EQUALS = _literal('=')
_COMA = _literal(',')

_LINE_END = pyparsing.LineEnd().suppress()


def _preprocessor_keyword(name):
  return _SHARP + pyparsing.Keyword(name).suppress()


_INCLUDE = _preprocessor_keyword('include')
_PRAGMA = _preprocessor_keyword('pragma')
_ERROR = _preprocessor_keyword('error')
_DEFINE = _preprocessor_keyword('define')
_UNDEF = _preprocessor_keyword('undef')
_IF = _preprocessor_keyword('if')
_IFDEF = _preprocessor_keyword('ifdef')
_IFNDEF = _preprocessor_keyword('ifndef')
_ELIF = _preprocessor_keyword('elif')
_ELSE = _preprocessor_keyword('else')
_ENDIF = _preprocessor_keyword('endif')

_PREPROCESSOR_KEYWORD = (
    _INCLUDE
    | _PRAGMA
    | _ERROR
    | _DEFINE
    | _UNDEF
    | _IF
    | _IFDEF
    | _IFNDEF
    | _ELIF
    | _ELSE
    | _ENDIF
)


def _program():
  return _composite_block().copy().setParseAction(util.action(pre_ast.File))


def _include():
  return _include_with_angle_brackets() | _include_with_double_quotes()


def _include_with_angle_brackets():
  quotes_type = pre_ast.Include.QuotesType.ANGLE_BRACKETS
  return (
      _INCLUDE
      + _OPEN_ANGLE_BRACKETS
      + _path()
      + _CLOSE_ANGLE_BRACKETS
  ).setParseAction(util.action(pre_ast.Include, quotes_type=quotes_type))


def _include_with_double_quotes():
  quotes_type = pre_ast.Include.QuotesType.DOUBLE_QUOTES
  return (
      _INCLUDE
      + _DOUBLE_QUOTE
      + _path()
      + _DOUBLE_QUOTE
  ).setParseAction(util.action(pre_ast.Include, quotes_type=quotes_type))


def _path():
  return pyparsing.Word(pyparsing.alphanums + '_.-/')


def _pragma():
  arguments = pyparsing.Group(pyparsing.ZeroOrMore(_pragma_argument()))
  return (
      _PRAGMA
      + _parse_to_line_end(arguments)
  ).setParseAction(util.action(pre_ast.Pragma))


def _pragma_argument():
  expression = expression_parser.expression_parser()
  expression.ignore(pyparsing.cppStyleComment)
  arguments = pyparsing.Group(
      _OPEN_PARENTHESES
      + _maybe_empty_delimited_list(expression)
      + _CLOSE_PARENTHESES
  )
  value_assignment = _EQUALS + expression
  return (
      (_identifier() | pyparsing.dblQuotedString)
      + pyparsing.Optional(arguments, None)
      + pyparsing.Optional(value_assignment, None)
  ).setParseAction(util.action(pre_ast.PragmaArgument))


def _error():
  return (
      _ERROR
      + pyparsing.SkipTo(pyparsing.lineEnd)
  ).setParseAction(util.action(pre_ast.Error))


def _define():
  return _define_function_like() | _define_object_like()


def _define_object_like():
  return (
      _DEFINE
      + _identifier()
      + pyparsing.restOfLine
  ).setParseAction(_create_define_object_like())


def _create_define_object_like():
  """Creates a (pyparsing) action that creates DefineObjectLike object."""
  replacement_list = _replacement_list()

  @util.action
  def create_define_object_like(identifier, string_replacement):
    replacement = _try_to_parse(replacement_list, string_replacement)
    return pre_ast.DefineObjectLike(
        name=identifier,
        replacement=replacement,
        string_replacement=string_replacement,
    )

  return create_define_object_like


def _define_function_like():
  return (
      _DEFINE
      + pyparsing.Combine(_function_identifier() + _OPEN_PARENTHESES)
      + pyparsing.Group(_maybe_empty_delimited_list(_identifier()))
      + _CLOSE_PARENTHESES
      + pyparsing.restOfLine
  ).setParseAction(_create_define_function_like())


def _create_define_function_like():
  """Creates a (pyparsing) action that creates DefineFunctionLike object."""
  replacement_list = _replacement_list()

  @util.action
  def create_define_function_like(identifier, arguments, string_replacement):
    replacement = _try_to_parse(replacement_list, string_replacement)
    return pre_ast.DefineFunctionLike(
        name=identifier,
        arguments=arguments,
        replacement=replacement,
        string_replacement=string_replacement,
    )

  return create_define_function_like


def _replacement_list():
  element = (
      expression_parser.expression_parser()
      | _semicolon()
  )
  expressions = pyparsing.Group(
      pyparsing.OneOrMore(element)
  ).setParseAction(_create_single_or_composite_block)
  expressions.ignore(pyparsing.cppStyleComment)
  return expressions


@util.action
def _create_single_or_composite_block(elements):
  if len(elements) == 1:
    return elements[0]
  else:
    return pre_ast.CompositeBlock(elements)


def _function_identifier():
  return (
      ~pyparsing.Keyword('__attribute__')
      + _identifier()
  )


def _undef():
  return (
      _UNDEF
      + _identifier()
  ).setParseAction(util.action(pre_ast.Undef))


def _conditional_construct(content):
  return (
      _conditional_blocks(content)
      + pyparsing.Optional(_else_block(content))
      + _ENDIF
      + _LINE_END
  ).setParseAction(util.action(pre_ast.If))


def _conditional_blocks(content):
  conditional_blocks = (
      _initial_conditional_block(content)
      + pyparsing.ZeroOrMore(_elif_block(content))
  )
  return pyparsing.Group(conditional_blocks)


def _initial_conditional_block(content):
  return (
      (_if_expression() | _ifdef_expression() | _ifndef_expression())
      + content
  ).setParseAction(util.action(pre_ast.ConditionalBlock))


def _elif_block(content):
  expression = expression_parser.expression_parser()
  expression.ignore(pyparsing.cppStyleComment)
  return (
      _ELIF
      + _parse_to_line_end(expression)
      + content
  ).setParseAction(util.action(pre_ast.ConditionalBlock))


def _else_block(content):
  return (
      _ELSE
      + _LINE_END
      + content
  )


def _if_expression():
  expression = expression_parser.expression_parser()
  expression.ignore(pyparsing.cppStyleComment)
  return (
      _IF
      + _parse_to_line_end(expression)
  )


def _ifdef_expression():
  return (
      _IFDEF
      + _parse_to_line_end(_identifier())
  ).setParseAction(_construct_ifdef_expression)


@util.action
def _construct_ifdef_expression(identifier):
  return c_ast.CFunctionCall(
      function_name='defined',
      arguments=[c_ast.CVariable(identifier)],
  )


def _ifndef_expression():
  return (
      _IFNDEF
      + _parse_to_line_end(_identifier())
  ).setParseAction(_construct_ifndef_expression)


@util.action
def _construct_ifndef_expression(identifier):
  return c_ast.CFunctionCall(
      function_name='!',
      arguments=[
          c_ast.CFunctionCall('defined', [c_ast.CVariable(identifier)]),
      ],
  )


def _composite_block():
  """Creates a (pyparsing) parser that parses a CompositeBlock object."""
  composite_block = pyparsing.Forward()
  element = (
      _include()
      | _pragma()
      | _error()
      | _define()
      | _undef()
      | _conditional_construct(composite_block)
      | _text_block()
  )
  # pylint: disable=expression-not-assigned
  composite_block << pyparsing.Group(
      pyparsing.ZeroOrMore(element)
  ).setParseAction(util.action(pre_ast.CompositeBlock))
  return composite_block


def _text_block():
  block_end = _PREPROCESSOR_KEYWORD | pyparsing.stringEnd
  return (
      ~block_end
      + pyparsing.SkipTo(block_end)
  ).setParseAction(util.action(pre_ast.TextBlock))


def _identifier():
  return pyparsing.Word(pyparsing.alphanums + '_')


def _semicolon():
  return pyparsing.Literal(';').setParseAction(util.action(c_ast.CLiteral))


def _maybe_empty_delimited_list(expression, delimiter=_COMA):
  one_or_more = expression + pyparsing.ZeroOrMore(delimiter + expression)
  return one_or_more | pyparsing.empty


def _parse_to_line_end(
    expression,
    include=True,
    ignore=pyparsing.cppStyleComment,
    fallback_function=None,
):
  return _parse_to_delimiter(
      expression,
      pyparsing.lineEnd,
      include,
      ignore,
      fallback_function,
  )


def _parse_to_delimiter(
    expression,
    delimiter,
    include,
    ignore=pyparsing.cppStyleComment,
    fallback_function=None,
):
  if ignore:
    expression = expression.copy().ignore(ignore)
  to_delimiter_parser = pyparsing.SkipTo(delimiter).setParseAction(
      _parse_result(expression, fallback_function),
  )
  if include:
    to_delimiter_parser += pyparsing.Suppress(delimiter)
  return to_delimiter_parser


def _parse_result(expression, fallback_function=None):
  """Creates a (pyparsing) action that parses the result."""

  @util.action
  def parse_result(result):
    try:
      return expression.parseString(result, parseAll=True)
    except pyparsing.ParseException:
      if fallback_function:
        return fallback_function(result)
      else:
        raise

  return parse_result


def _try_to_parse(parser_object, string, default=None, parse_all=True):
  try:
    return parser_object.parseString(string, parseAll=parse_all)[0]
  except pyparsing.ParseException:
    return default
