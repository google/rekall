"""A module containing a parser intended for C header files."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import string
import pyparsing

from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.c_ast import pre_ast
from rekall.layout_expert.parser import expression_parser
from rekall.layout_expert.parser import util

pyparsing.ParserElement.enablePackrat()  # speed hack


class Parser(object):

  def __init__(self):
    self.parser = _program().ignore(pyparsing.cStyleComment)

  def parse(self, source):
    return self.parser.parseString(source, parseAll=True)[0]


def function_definition():
  return (
      pyparsing.ZeroOrMore(_STATIC | _INLINE)
      + _maybe_unimportant_attributes()
      + _type_identifier()
      + pyparsing.ZeroOrMore(_STAR + _MAYBE_CONST)
      + _identifier()
      + _anything_in_parentheses()
      + _anything_in_curly()
  ).suppress()


def extern_field():
  return (
      _EXTERN
      + pyparsing.ZeroOrMore(
          _CONST
          | _unimportant_attribute_clause()
          | _STAR
          | _anything_in_brackets()
          | _anything_in_parentheses()
          | _COMA
          | _type_identifier()
          | _identifier()
      )
      + _SEMICOLON
  ).suppress()

# We do not use the preprocessor keywords and corresponding syntax constructs
# since we have a Pre-AST parser.
# They are left here in case we would need them again.
_IFDEF = pyparsing.Keyword('//ifdef').suppress()
_IFNDEF = pyparsing.Keyword('//ifndef').suppress()
_IF = pyparsing.Keyword('//if').suppress()
_ELIF = pyparsing.Keyword('//elif').suppress()
_ELSE = pyparsing.Keyword('//else').suppress()
_ENDIF = pyparsing.Keyword('//endif').suppress()
_PREPROCESSOR_KEYWORD = _IFDEF | _IFNDEF | _IF | _ELIF | _ELSE | _ENDIF

_LINE_END = pyparsing.LineEnd().suppress()

_ENUM = pyparsing.Keyword('enum')
_STRUCT = pyparsing.Keyword('struct')
_UNION = pyparsing.Keyword('union')
_COMPOUND_TYPE_KEYWORD = _ENUM | _STRUCT | _UNION

_TYPEDEF = pyparsing.Keyword('typedef').suppress()
_DECLARATION_KEYWORD = (_COMPOUND_TYPE_KEYWORD | _TYPEDEF).suppress()

_CONST = pyparsing.Keyword('const').suppress()
_VOLATILE = pyparsing.Keyword('volatile').suppress()
_EXTERN = pyparsing.Keyword('extern').suppress()
_STATIC = pyparsing.Keyword('static').suppress()
_INLINE = pyparsing.Keyword('inline').suppress()
_MAYBE_CONST = pyparsing.Optional(_CONST)
_MAYBE_EXTERN = pyparsing.Optional(_EXTERN)
_MAYBE_VOLATILE = pyparsing.Optional(_VOLATILE)

_DO = pyparsing.Keyword('do').suppress()
_WHILE = pyparsing.Keyword('while').suppress()
_C_FLOW_KEYWORD = _DO | _WHILE

_SIGNED = pyparsing.Keyword('signed') | pyparsing.Keyword('__signed__')
_UNSIGNED = pyparsing.Keyword('unsigned')
_CHAR = pyparsing.Keyword('char')
_SHORT = pyparsing.Keyword('short')
_INT = pyparsing.Keyword('int')
_LONG = pyparsing.Keyword('long')
_LONG_LONG = _LONG + _LONG

_NUMBER_TYPE_KEYWORD = (
    _SIGNED
    | _UNSIGNED
    | _CHAR
    | _SHORT
    | _INT
    | _LONG
    | _LONG_LONG
)

_SEMICOLON = pyparsing.Literal(';').suppress()
_STAR = pyparsing.Literal('*').suppress()
_OPEN_BRACKET = pyparsing.Literal('[').suppress()
_CLOSE_BRACKET = pyparsing.Literal(']').suppress()
_BRACKETS = (_OPEN_BRACKET + _CLOSE_BRACKET).suppress()
_OPEN_PARENTHESIS = pyparsing.Literal('(').suppress()
_CLOSE_PARENTHESIS = pyparsing.Literal(')').suppress()
_OPEN_CURLY = pyparsing.Literal('{').suppress()
_CLOSE_CURLY = pyparsing.Literal('}').suppress()
_COLON = pyparsing.Literal(':').suppress()
_COMA = pyparsing.Literal(',').suppress()

_ATTRIBUTE = pyparsing.Keyword('__attribute__').suppress()
_DOUBLE_OPEN_PARENTHESIS = _OPEN_PARENTHESIS + _OPEN_PARENTHESIS
_DOUBLE_CLOSE_PARENTHESIS = _CLOSE_PARENTHESIS + _CLOSE_PARENTHESIS

_KEYWORD = (
    _PREPROCESSOR_KEYWORD
    | _DECLARATION_KEYWORD
    | _C_FLOW_KEYWORD
    | _NUMBER_TYPE_KEYWORD
    | _ATTRIBUTE
)


def _program():
  return _top_level_elements().copy().setParseAction(
      util.action(c_ast.CProgram)
  )


def _top_level_elements():
  top_level_elements = pyparsing.Forward()
  top_level_block = (
      _top_level_element()
      | _conditional_construct(top_level_elements)
      | _skip_one_token()
  )
  # pylint: disable=expression-not-assigned
  top_level_elements << pyparsing.Group(pyparsing.ZeroOrMore(top_level_block))
  return top_level_elements


def _top_level_element():
  return (
      _typedef()
      | _element()
      | _function_declaration()
      | function_definition()
      | _type_declaration_without_definition()
      | _malformed_function_declaration()
      | _do_while_block_artifact()
  )


def _skip_one_token():
  important_token = _PREPROCESSOR_KEYWORD | _DECLARATION_KEYWORD
  word = pyparsing.Word(pyparsing.alphanums + '_')
  character = pyparsing.Word(string.printable, exact=1)
  typeof = pyparsing.Keyword('__typeof__') + _anything_in_parentheses()
  return (
      (~important_token)
      + (typeof | word | character)
  ).suppress()


def _function_declaration():
  identifier_in_parentheses = (
      _OPEN_PARENTHESIS
      + _identifier()
      + _CLOSE_PARENTHESIS
  )
  return (
      pyparsing.Optional(_TYPEDEF)
      + _type_identifier()
      + pyparsing.ZeroOrMore(_STAR + _MAYBE_CONST)
      + _maybe_unimportant_attributes()
      + (_identifier() | identifier_in_parentheses)
      + _anything_in_parentheses()
      + _maybe_unimportant_attributes()
      + _SEMICOLON
  ).suppress()


def _malformed_function_declaration():
  return (
      pyparsing.ZeroOrMore(_STATIC | _INLINE)
      + _maybe_unimportant_attributes()
      + _type_identifier()
      + pyparsing.ZeroOrMore(_STAR + _MAYBE_CONST)
      + pyparsing.Optional(_identifier())
      + pyparsing.OneOrMore(_anything_in_parentheses())
      + (_anything_in_curly() | _SEMICOLON)
  ).suppress()


def _do_while_block_artifact():
  return (
      _DO
      + _anything_in_curly()
      + _WHILE
      + _anything_in_parentheses()
      + pyparsing.Optional(_SEMICOLON)
  ).suppress()


def _type_declaration_without_definition():
  return (
      (_ENUM | _STRUCT | _UNION)
      + _identifier()
      + _SEMICOLON
  ).suppress()


def _typedef():
  return _simple_typedef() | _typedef_with_definition()


def _simple_typedef():
  return (
      _TYPEDEF
      + _maybe_attributes()
      + _type_reference()
      + _maybe_attributes()
      + _type_instance(c_ast.CTypedef)
      + _SEMICOLON
  ).setParseAction(_insert_type_reference_into_typedef_instance)


@util.action
def _insert_type_reference_into_typedef_instance(
    attributes_1,
    type_reference,
    attributes_2,
    type_instance,
):
  return _insert_type_reference_into_type_instances(
      type_reference,
      attributes_1 + attributes_2,
      type_instance,
  )


def _typedef_with_definition():
  return (
      _TYPEDEF
      + _maybe_identifier_and_attributed_type_definition(_elements())
      + _type_instance(c_ast.CTypedef)
      + _SEMICOLON
  ).setParseAction(_insert_type_definition_into_typedef_instance)


@util.action
def _insert_type_definition_into_typedef_instance(
    identifier,
    definition,
    typedef_instance,
):
  if identifier:
    definition = c_ast.CTypeDefinition(
        type_name=identifier,
        type_definition=definition,
    )
  typedef_instance.insert_type_definition(definition)
  return typedef_instance


def _elements():
  return pyparsing.Group(pyparsing.ZeroOrMore(_element()))


def _element():
  """Builds a (pyparsing) parser for one element of complex types like struct.

  Returns:
    A (pyparsing) parser for one element of complex types.
  """
  element = pyparsing.Forward()
  elements = pyparsing.Group(pyparsing.ZeroOrMore(element))
  # pylint: disable=expression-not-assigned
  element << (
      (~_TYPEDEF) + (
          _type_definition_possibly_with_fields(elements)
          | _type_name_with_fields()
          | _conditional_construct(elements)
          | _preprocessing_artifact()
          | _SEMICOLON
      )
  )
  return element


def _preprocessing_artifact():
  return (
      pyparsing.Literal('#')
      + _natural()
      + pyparsing.dblQuotedString
      + pyparsing.SkipTo(pyparsing.LineEnd())
  ).suppress()


def _conditional_construct(elements):
  return (
      _conditional_blocks(elements)
      + pyparsing.Optional(_else_block(elements))
      + _ENDIF
      + _LINE_END
  ).setParseAction(util.action(pre_ast.If))


def _conditional_blocks(elements):
  conditional_blocks = (
      _initial_conditional_block(elements)
      + pyparsing.ZeroOrMore(_elif_block(elements))
  )
  return pyparsing.Group(conditional_blocks)


def _initial_conditional_block(elements):
  return (
      (_if_expression() | _ifdef_expression() | _ifndef_expression())
      + elements
  ).setParseAction(util.action(pre_ast.ConditionalBlock))


def _elif_block(elements):
  expression = expression_parser.expression_parser()
  return (
      _ELIF
      + pyparsing.restOfLine
      + elements
  ).setParseAction(_construct_elif_block(expression))


def _construct_elif_block(expression):
  """Builds a (pyparsing) parser for macro elif block.

  Args:
    expression: A (pyparsing) parser for parsing expressions.

  Returns:
    A (pyparsing) parser for macro elif block.
  """

  @util.action
  def construct_elif_block(expression_string, content):
    expression_parse_result = expression.parseString(
        expression_string,
        parseAll=True,
    )
    conditional_expression = expression_parse_result[0]
    return pre_ast.ConditionalBlock(conditional_expression, content)

  return construct_elif_block


def _else_block(elements):
  return (
      _ELSE
      + _LINE_END
      + elements
  )


def _if_expression():
  expression = expression_parser.expression_parser()
  return (
      _IF
      + pyparsing.restOfLine
  ).setParseAction(_create_if_expression(expression))


def _create_if_expression(expression):

  @util.action
  def create_if_expression(expression_string):
    return expression.parseString(
        expression_string,
        parseAll=True,
    )

  return create_if_expression


def _ifdef_expression():
  return (
      _IFDEF
      + _identifier()
      + _LINE_END
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
      + _identifier()
      + _LINE_END
  ).setParseAction(_construct_ifndef_expression)


@util.action
def _construct_ifndef_expression(identifier):
  return c_ast.CFunctionCall(
      function_name='!',
      arguments=[
          c_ast.CFunctionCall(
              function_name='defined',
              arguments=[c_ast.CVariable(identifier)],
          ),
      ],
  )


def _type_name_with_fields():
  return (
      _type_reference()
      + _maybe_attributes()
      + pyparsing.delimitedList(_field())
      + _SEMICOLON
  ).setParseAction(util.action(_insert_type_reference_into_type_instances))


def _insert_type_reference_into_type_instances(
    type_reference,
    attributes,
    *type_instances
):
  for field in type_instances:
    field.insert_type_definition(type_reference)
    _insert_attributes_into_type_instance(field, attributes)
  return list(type_instances)


def _type_reference():
  return _type_identifier().addParseAction(util.action(c_ast.CTypeReference))


def _type_definition_possibly_with_fields(elements):
  return (
      _maybe_identifier_and_attributed_type_definition(elements)
      + _maybe_fields()
      + _SEMICOLON
  ).setParseAction(_insert_type_definition_into_fields)


@util.action
def _insert_type_definition_into_fields(
    identifier,
    type_definition,
    *fields
):
  for field in fields:
    field.insert_type_definition(type_definition)
  return c_ast.CTypeDefinition(identifier, type_definition, list(fields))


def _maybe_fields():
  return pyparsing.Optional(pyparsing.delimitedList(_field()))


def _field():
  return _bit_field() | _type_instance(c_ast.CField)


def _bit_field():
  expression = expression_parser.expression_parser()
  return (
      pyparsing.Optional(_identifier(), None)
      + _COLON
      + pyparsing.SkipTo(_SEMICOLON | _COMA)
  ).setParseAction(_construct_bitfield(expression))


def _construct_bitfield(expression):

  @util.action
  def construct_bitfield(maybe_identifier, bit_size_string):
    bit_size = expression.parseString(bit_size_string, parseAll=True)[0]
    return c_ast.CField(
        name=maybe_identifier,
        bit_size=bit_size,
    )

  return construct_bitfield


def _type_instance(type_instance_constructor):
  type_instance = (
      (_concrete_type_instance(type_instance_constructor) + (~_OPEN_BRACKET))
      | _pointer_type_instance(type_instance_constructor)
  )
  attributed_type_instance = type_instance + _maybe_attributes()
  attributed_type_instance.setParseAction(
      util.action(_insert_attributes_into_type_instance)
  )
  return attributed_type_instance


def _insert_attributes_into_type_instance(type_instance, attributes):
  if attributes:
    type_instance.attributes.extend(attributes)
  return type_instance


def _pointer_type_instance(type_instance_constructor):
  """Returns a (pyparsing) parser for a pointer type instance denoted with *.

  Args:
    type_instance_constructor: a constructor of the type instance.

  Returns:
    A (pyparsing) parser for a pointer type instance denoted with *.
  """
  pointer_type_instance = pyparsing.Forward()
  after_star = (
      (_concrete_type_instance(type_instance_constructor) + (~_OPEN_BRACKET))
      | pointer_type_instance
  )
  with_star = _STAR + _MAYBE_CONST + after_star
  with_star.setParseAction(_insert_pointer_as_type_definition)
  # pylint: disable=expression-not-assigned
  pointer_type_instance << (
      with_star
      | _pointer_type_instance_with_brackets(type_instance_constructor)
      | _pointer_to_function_type_instance(type_instance_constructor)
  )
  return pointer_type_instance


@util.action
def _insert_pointer_as_type_definition(*type_instances):
  for type_instance in type_instances:
    type_instance.insert_type_definition(c_ast.CPointer())
  return list(type_instances)


def _pointer_type_instance_with_brackets(type_instance_constructor):
  """Builds a (pyparsing) parser for a pointer type instance denoted with [].

  Args:
    type_instance_constructor: a constructor of the type instance.

  Returns:
    A (pyparsing) parser for a pointer type instance.
  """
  before_brackets = (
      _concrete_type_instance(type_instance_constructor)
      | _pointer_to_function_type_instance(type_instance_constructor)
  )
  with_brackets = (
      before_brackets
      + pyparsing.OneOrMore(pyparsing.Group(_BRACKETS))
  )
  with_brackets.setParseAction(_insert_pointer_types_for_brackets)
  return with_brackets


@util.action
def _insert_pointer_types_for_brackets(type_instance, *brackets):
  for _ in brackets:
    type_instance.insert_type_definition(c_ast.CPointer())
  return type_instance


def _pointer_to_function_type_instance(type_instance_constructor):
  return (
      _OPEN_PARENTHESIS
      + _STAR
      + _MAYBE_CONST
      + _identifier()
      + _CLOSE_PARENTHESIS
      + _anything_in_parentheses()
  ).setParseAction(
      _create_pointer_to_function_type_instance(type_instance_constructor)
  )


def _create_pointer_to_function_type_instance(type_instance_constructor):

  @util.action
  def create_pointer_to_function_type_instance(identifier):
    return type_instance_constructor(
        name=identifier,
        type_definition=c_ast.CPointerToFunction(),
    )

  return create_pointer_to_function_type_instance


def _concrete_type_instance(type_instance_constructor):
  # _simple_field() can be a prefix of _array_field()
  return (
      _array_type_instance(type_instance_constructor)
      | _simple_type_instance(type_instance_constructor)
  )


def _array_type_instance(type_instance_constructor):
  brackets_with_expression_inside = (
      _OPEN_BRACKET
      + (~_CLOSE_BRACKET)
      + pyparsing.SkipTo(_CLOSE_BRACKET)
      + _CLOSE_BRACKET
  )
  expression = expression_parser.expression_parser()
  return (
      _simple_type_instance(type_instance_constructor)
      + pyparsing.OneOrMore(brackets_with_expression_inside)
  ).setParseAction(_insert_array_type_definitions(expression))


def _insert_array_type_definitions(expression):

  @util.action
  def insert_array_type_definitions(type_instance, *length_expressions):
    for length_expression in length_expressions:
      length = expression.parseString(length_expression, parseAll=True)[0]
      type_instance.insert_type_definition(c_ast.CArray(length))
    return type_instance

  return insert_array_type_definitions


def _simple_type_instance(type_instance_constructor):
  return _identifier().setParseAction(util.action(type_instance_constructor))


def _maybe_attributes():
  maybe_attributes = pyparsing.Forward()
  attributes_and_conditionals = pyparsing.ZeroOrMore(
      _attribute_clause()
      | _conditional_construct(maybe_attributes)
  )
  # pylint: disable=expression-not-assigned
  maybe_attributes << pyparsing.Group(attributes_and_conditionals)
  return maybe_attributes


def _attribute_clause():
  return (
      _ATTRIBUTE
      + _DOUBLE_OPEN_PARENTHESIS
      + pyparsing.delimitedList(_attribute())
      + _DOUBLE_CLOSE_PARENTHESIS
  )


def _attribute():
  return (
      _attribute_aligned()
      | _attribute_packed()
      | _attribute_noreturn()
      | _attribute_section()
      | _attribute_format()
  )


def _attribute_aligned():
  expression = expression_parser.expression_parser()
  return (
      _attribute_name('aligned')
      + _OPEN_PARENTHESIS
      + _anything_beetween('()')
      + _CLOSE_PARENTHESIS
  ).setParseAction(_create_aligned(expression))


def _create_aligned(expression):

  @util.action
  def create_aligned(aligned, argument_string):
    argument = expression.parseString(argument_string, parseAll=True)[0]
    return c_ast.CAttribute(aligned, argument)

  return create_aligned


def _attribute_packed():
  return _make_attribute('packed')


def _attribute_noreturn():
  return _make_attribute('noreturn')


def _attribute_section():
  return _make_attribute('section', pyparsing.dblQuotedString)


def _attribute_format():
  parameters = (
      _identifier()
      + _COMA
      + _natural()
      + _COMA
      + _natural()
  )
  return _make_attribute('format', parameters)


def _make_attribute(name, parameters_parser=None):
  """Creates an attribute parser (pyparsing).

  Args:
    name: a string representing the name of the attribute.
    parameters_parser: a (pyparsing) parser for parsing the parameters
      of the attribute.

  Returns:
    A (pyparsing) parser for the attribute.
  """
  if parameters_parser:
    maybe_parameters = (
        _OPEN_PARENTHESIS
        + parameters_parser
        + _CLOSE_PARENTHESIS
    )
  else:
    maybe_parameters = pyparsing.empty
  attribute = (
      _attribute_name(name)
      + maybe_parameters
  )
  attribute.setParseAction(util.action(c_ast.CAttribute))
  return attribute


def _attribute_name(name):
  return pyparsing.Keyword(name) | pyparsing.Keyword('__' + name + '__')


def _maybe_unimportant_attributes():
  return pyparsing.ZeroOrMore(_unimportant_attribute_clause())


def _unimportant_attribute_clause():
  return (
      _ATTRIBUTE
      + _DOUBLE_OPEN_PARENTHESIS
      + _anything_beetween('()')
      + _DOUBLE_CLOSE_PARENTHESIS
  ).suppress()


def _maybe_identifier_and_attributed_type_definition(elements):
  identifier_type_definition_and_attributes = (
      _MAYBE_CONST
      + _maybe_identifier_and_type_definition(elements)
      + _maybe_attributes()
  )
  identifier_type_definition_and_attributes.setParseAction(
      _insert_attributes_into_definition
  )
  return identifier_type_definition_and_attributes


@util.action
def _insert_attributes_into_definition(
    identifier,
    type_definition,
    attributes,
):
  if attributes:
    type_definition.attributes.extend(attributes)
  return [identifier, type_definition]


def _maybe_identifier_and_type_definition(elements):
  return (
      _maybe_identifier_and_enum()
      | _maybe_identifier_and_compound_type(_STRUCT, c_ast.CStruct, elements)
      | _maybe_identifier_and_compound_type(_UNION, c_ast.CUnion, elements)
  )


def _maybe_identifier_and_enum():
  return (
      _ENUM
      + pyparsing.Optional(_identifier(), None)
      + _anything_in_curly()
  ).setParseAction(_return_type_name_and_constructed(c_ast.CEnum))


def _maybe_identifier_and_compound_type(keyword, constructor, elements):
  return (
      keyword
      + pyparsing.Optional(_identifier(), None)
      + _OPEN_CURLY
      + elements
      + _CLOSE_CURLY
  ).setParseAction(_return_type_name_and_constructed(constructor))


def _return_type_name_and_constructed(constructor):

  @util.action
  def return_type_name_and_constructed(kind, identifier, *args):
    type_name = kind + ' ' + identifier if identifier else None
    return [type_name, constructor(*args)]

  return return_type_name_and_constructed


def _type_identifier():
  identifier = (
      _typeof_expression()
      | _numeric_type_identifier()
      | _compound_type_identifier()
      | _identifier()
  )
  return (
      pyparsing.ZeroOrMore(_CONST | _VOLATILE)
      + identifier
      + _MAYBE_CONST
  ).setParseAction(_construct_type_identifier)


@util.action
def _construct_type_identifier(*args):
  return ' '.join(args)


def _typeof_expression():
  keyword = (
      pyparsing.Keyword('typeof')
      | pyparsing.Keyword('__typeof__')
  )
  return pyparsing.Combine(
      keyword
      + pyparsing.Literal('(')
      + pyparsing.Combine(_anything_beetween('()'))
      + pyparsing.Literal(')')
  )


@util.action
def _create_typeof_expression(keyword, *arguments):
  return c_ast.CFunctionCall(
      function_name=keyword,
      arguments=arguments,
  )


def _numeric_type_identifier():
  with_sign_identifier = (
      _number_sign_identifier()
      + pyparsing.Optional(_number_size_identifier())
  )
  with_size_identifier = (
      pyparsing.Optional(_number_sign_identifier())
      + _number_size_identifier()
  )
  return with_sign_identifier | with_size_identifier


def _compound_type_identifier():
  return(
      (_ENUM | _STRUCT | _UNION)
      + _identifier()
  )


def _number_sign_identifier():
  return _SIGNED | _UNSIGNED


def _number_size_identifier():
  may_have_int_suffix = _LONG_LONG | _SHORT | _LONG
  return _INT | _CHAR | (may_have_int_suffix + pyparsing.Optional(_INT))


def _identifier():
  proper_identifier = pyparsing.Word(
      pyparsing.alphas + '_',
      pyparsing.alphanums + '_',
  )
  malformed_identifier = (
      pyparsing.Keyword('_u._sa_handler')
  )
  return (
      (~_KEYWORD)
      + (malformed_identifier | proper_identifier)
  )


def _natural():
  return pyparsing.Word(pyparsing.nums).setParseAction(util.action(int))


def _anything_in_curly():
  return _anything_in('{}')


def _anything_in_parentheses():
  return _anything_in('()')


def _anything_in_brackets():
  return _anything_in('[]')


def _anything_in(opener_and_closer):
  opener = opener_and_closer[0]
  closer = opener_and_closer[1]
  anything = _anything_beetween(opener_and_closer)
  return (opener + anything + closer).suppress()


def _anything_beetween(opener_and_closer):
  """Builds a (pyparsing) parser for the content inside delimiters.

  Args:
    opener_and_closer: a string containing two elements: opener and closer

  Returns:
     A (pyparsing) parser for the content inside delimiters.
  """
  char_removal_mapping = dict.fromkeys(map(ord, opener_and_closer))
  other_chars = unicode(string.printable).translate(char_removal_mapping)
  word_without_delimiters = pyparsing.Word(other_chars)
  opener = opener_and_closer[0]
  closer = opener_and_closer[1]
  anything = pyparsing.Forward()
  delimited_block = opener + anything + closer
  # pylint: disable=expression-not-assigned
  anything << pyparsing.ZeroOrMore(word_without_delimiters | delimited_block)
  return pyparsing.Combine(anything)
