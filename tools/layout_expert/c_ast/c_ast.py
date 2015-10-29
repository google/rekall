"""Abstract syntax tree for the struct layout expert.

This file contains classes representing an abstract syntax tree for the
purpose of computing struct layouts.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import itertools
import re

from rekall.layout_expert.c_ast import visitor_mixin

from rekall.layout_expert.common import data_container


class _CASTNode(data_container.DataContainer, visitor_mixin.VisitorMixin):
  """A base class for AST nodes."""


class CProgram(_CASTNode):
  """A class to represent a whole program."""

  def __init__(self, content):
    """Initiates File with content.

    Args:
      content: a list containing objects representing the content of a program.
    """
    super(CProgram, self).__init__()
    self.content = content


class CEnum(_CASTNode):
  """A class representing an CEnum type."""

  def __init__(self, attributes=None):
    super(CEnum, self).__init__()
    self.attributes = attributes or []


class CStruct(_CASTNode):
  """A class representing a CStruct type."""

  def __init__(self, content, attributes=None):
    """Initiates a CStruct object with content.

    Args:
      content: A list of the objects representing the content of the struct.
      attributes: A list of the objects representing the attributes of
        the struct.
    """
    super(CStruct, self).__init__()
    self.content = content
    self.attributes = attributes or []


class CUnion(_CASTNode):
  """A class representing a CUnion type."""

  def __init__(self, content, attributes=None):
    """Initiates a CUnion object with content.

    Args:
      content: A list of the objects representing the content of the union. For
          example fields and conditional blocks.
      attributes: A list of the objects representing the attributes of
        the union.
    """
    super(CUnion, self).__init__()
    self.content = content
    self.attributes = attributes or []


class _CTypeContainer(_CASTNode):
  """An abstract base class representing AST node containing type definition.

  Provides a method for recursive insertion of type definition.
  """

  def insert_type_definition(self, type_definition):
    """A method for recursive insertion of type definition.

    Args:
     type_definition: a type definition to be inserted recursively.
    """
    self_type_definition = getattr(self, 'type_definition', None)
    if self_type_definition:
      self_type_definition.insert_type_definition(type_definition)
    else:
      setattr(self, 'type_definition', type_definition)


class CArray(_CTypeContainer):
  """A class representing an array of the given type."""

  def __init__(self, length, type_definition=None, evaluated_length=None):
    """Initiates an CArray object with length and type definition.

    Args:
      length: An expression representing the number of the elements in
          the array.
      type_definition: An object representing a type of the elements
          of the array. May be None.
      evaluated_length: An int representing the evaluated lenght of the array.
          May be None.
    """
    super(CArray, self).__init__()
    self.type_definition = type_definition
    self.length = length
    self.evaluated_length = evaluated_length


class CPointer(_CTypeContainer):
  """A class representing a pointer type."""

  def __init__(self, type_definition=None):
    """Initiates a CPointer object with type_definition.

    Args:
      type_definition: an object representing a type definition under the
        pointer. May be None.
    """
    super(CPointer, self).__init__()
    self.type_definition = type_definition


class CPointerToFunction(_CTypeContainer):
  """A class representing a CPointerToFunction type."""

  def insert_type_definition(self, type_definition):
    """Purposefully does nothing.

    The parser does not track the type of the underlying function.

    Args:
      type_definition: an object representing a type_definition.
    """
    pass


class CSimpleType(_CASTNode):

  def __init__(self, bit_size, bit_alignment):
    super(CSimpleType, self).__init__()
    self.bit_size = bit_size
    self.bit_alignment = bit_alignment


class CTypeReference(_CASTNode):
  """A class representing a reference to a type by name."""

  def __init__(self, type_name):
    """Initializes a CTypeReference object with type name.

    Args:
      type_name: a string representing the name of the referenced type.
    """
    super(CTypeReference, self).__init__()
    self.type_name = type_name


class CTypeDefinition(_CASTNode):
  """A class representing a definition of a type.

  E.g. a struct, union or enum definition. But not simple typedefs.
  """

  def __init__(self, type_name, type_definition, following_fields=None):
    """Initializes a CTypeDefinition object.

    Args:
      type_name: a string representing the name of the defined type.
        May be None.
      type_definition: an object representing a definition of the type
        e.g. an CEnum, CStruct or CUnion object.
      following_fields: a list of objects representing fields immediately
        following the definition (before the semicolon).
    """
    super(CTypeDefinition, self).__init__()
    self.type_name = type_name  # May be none
    self.type_definition = type_definition
    self.following_fields = following_fields or []


class CField(_CTypeContainer):
  """A class representing a field inside of a more complex type."""

  def __init__(
      self,
      name=None,
      type_definition=None,
      bit_size=None,
      attributes=None,
  ):
    """Initializes a field object.

    Args:
      name: a string representing a name of the field. May be None.
      type_definition: an object representing a type of the field. May be None.
      bit_size: an int representing a bit_size of the field, if a bit size
        is explicitly specified. May be none.
      attributes: A list of the objects representing the attributes of
        the field.
    """
    super(CField, self).__init__()
    self.name = name
    self.type_definition = type_definition
    self.bit_size = bit_size
    self.attributes = attributes or []


class CTypedef(_CTypeContainer):
  """A class to represent a typedef."""

  def __init__(self, name, type_definition=None, attributes=None):
    """Initializes a CTypedef object.

    Args:
      name: a string representing a new name of the type.
      type_definition: an object representing a type definition. May be None.
      attributes: A list of the objects representing the attributes of
        the typedef.
    """
    super(CTypedef, self).__init__()
    self.name = name
    self.type_definition = type_definition
    self.attributes = attributes or []


class CAttribute(_CASTNode):
  """A class to represent an attribute of a type or a field."""

  def __init__(self, name, *parameters):
    """Initializes an CAttribute object with name and parameters.

    Args:
      name: a string representing the name of the attribute.
      *parameters: a list of objects representing parameters of the attribute.
    """
    super(CAttribute, self).__init__()
    self.name = name
    self.parameters = parameters


class CFunctionCall(_CASTNode):
  """A class to represent a function call expression."""

  # TODO(arkadiuszs) Split into operator and function call nodes.

  _IDENTIFIER_PATTERN = re.compile(r'^\w+$')

  def __init__(self, function_name, arguments):
    """Initializes a CFunctionCall object with function name and arguments.

    Args:
      function_name: a string representing a name of the called function.
      arguments: a list of objects representing the argumets of this function
        call.
    """
    super(CFunctionCall, self).__init__()
    self.function_name = function_name
    self.arguments = arguments

  def __str__(self):
    arguments = map(str, self.arguments)
    if self._IDENTIFIER_PATTERN.match(self.function_name):
      return self.function_name + '(' + ', '.join(arguments) + ')'
    elif len(arguments) == 1:
      return self.function_name + arguments[0]
    elif len(arguments) == 2:
      if self.function_name in '()':
        return '(' + arguments[0] + ') ' + arguments[1]
      elif self.function_name in '[]':
        return arguments[0] + '[' + arguments[1] + ']'
      else:
        return arguments[0] + ' ' + self.function_name + ' ' + arguments[1]
    else:
      operator_characters = self.function_name
      tokens = []
      if len(arguments) > len(operator_characters):
        tokens.append(arguments[0])
        following_arguments = arguments[1:]
      else:
        following_arguments = arguments
      operators_and_arguments = zip(operator_characters, following_arguments)
      tokens.extend(itertools.chain(*operators_and_arguments))
      separator = ' ' if len(arguments) > 1 else ''
      return separator.join(tokens)


class CNestedExpression(_CASTNode):

  def __init__(self, opener, content, closer):
    super(CNestedExpression, self).__init__()
    self.opener = opener
    self.content = content
    self.closer = closer

  def __str__(self):
    return self.opener + str(self.content) + self.closer


class CVariable(_CASTNode):
  """A class to represent a variable reference expression."""

  def __init__(self, name):
    """Initializes a CVariable object with a name of the referenced variable.

    Args:
      name: a string representing a name of the referenced variable.
    """
    super(CVariable, self).__init__()
    self.name = name

  def __str__(self):
    return self.name


class CNumber(_CASTNode):
  """A class to represent a number literal expression."""

  def __init__(self, value):
    """Initializes a CNumber object with a value of the number.

    Args:
      value: a number representing the value of the literal.
    """
    super(CNumber, self).__init__()
    self.value = value

  def __str__(self):
    return str(self.value)


class CLiteral(_CASTNode):
  """A class to represent a string literal expression."""

  def __init__(self, value):
    """Initializes a CLiteral object with a string.

    Args:
      value: a string representing the value of the literal.
    """
    super(CLiteral, self).__init__()
    self.value = value

  def __str__(self):
    return self.value
