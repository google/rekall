#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2016 Google Inc. All Rights Reserved.
#
# Authors:
# Arkadiusz Socała <as277575@mimuw.edu.pl>
# Michael Cohen <scudette@google.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

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

from layout_expert.c_ast import visitor_mixin
from layout_expert.serialization import json_serialization
from layout_expert.common import data_container


class IrreducibleFunction(Exception):
    """Exception raised when a CFunctionCall node can not be reduced."""


def AssertOfType(obj, type):
    if not isinstance(obj, type):
        raise IrreducibleFunction(obj)


class CASTNode(data_container.DataContainer, visitor_mixin.VisitorMixin):
    """A base class for AST nodes."""

    def __init__(self, name=None, attributes=None):
        super(CASTNode, self).__init__()
        self.attributes = attributes or []
        self.name = name

    def __nonzero__(self):
        return self.__bool__()

    def __bool__(self):
        raise IrreducibleFunction("Cant evaluate non literal nodes.")

    def add_attributes(self, attributes):
        if isinstance(attributes, (list, tuple)):
            self.attributes.extend(attributes)
        elif attributes:
            self.attributes.extend(attributes.asList())

    def __repr__(self):
        return str(self)


class CProgram(CASTNode):
    """A class to represent a whole program."""

    def __init__(self, content, **kw):
        """Initiates File with content.

        Args:
            content: a list containing objects representing the content of a
        program.
        """
        super(CProgram, self).__init__(**kw)
        self.content = content


class CEnum(CASTNode):
    """A class representing an CEnum type."""

    def __init__(self, attributes=None, fields=None, **kw):
        super(CEnum, self).__init__(**kw)
        self.add_attributes(attributes)
        self.fields = fields or []
        # Number the enum constants.
        counter = CNumber(0)
        for x in self.fields:
            if x.value is None:
                x.value = counter
                counter = CFunctionCall("+", (counter, CNumber(1)))
            else:
                # Start counting the next free field from the current assigned
                # one.
                counter = CFunctionCall("+", [x.value, CNumber(1)])


class CEnumField(CASTNode):
    """A single enum field."""

    def __init__(self, name=None, value=None, **kw):
        super(CEnumField, self).__init__(**kw)
        self.name = name
        self.value = value


class CStruct(CASTNode):
    """A class representing a CStruct type."""

    def __init__(self, content, attributes=None, **kw):
        """Initiates a CStruct object with content.

        Args:
            content: A list of the objects representing the content of the
               struct.
            attributes: A list of the objects representing the attributes of
                the struct.

        """
        super(CStruct, self).__init__(**kw)
        self.content = content
        self.add_attributes(attributes)


class CUnion(CASTNode):
    """A class representing a CUnion type."""

    def __init__(self, content, attributes=None, **kw):
        """Initiates a CUnion object with content.

        Args:
            content: A list of the objects representing the content of the
                    union. For example fields and conditional blocks.
            attributes: A list of the objects representing the attributes of the
                union.

        """
        super(CUnion, self).__init__(**kw)
        self.content = content
        self.add_attributes(attributes)


class CTypeContainer(CASTNode):
    """An abstract base class representing AST node containing type definition.

    Provides a method for recursive insertion of type definition.
    """

    def __init__(self, name=None, **kw):
        super(CTypeContainer, self).__init__(**kw)
        self.name = name

    def insert_type_definition(self, type_definition):
        """A method for recursive insertion of type definition.

        Args:
         type_definition: a type definition to be inserted recursively.
        """
        self_type_definition = getattr(self, 'type_definition', None)
        if self_type_definition is not None:
            self_type_definition.insert_type_definition(type_definition)
        else:
            setattr(self, 'type_definition', type_definition)


class CArray(CTypeContainer):
    """A class representing an array of the given type."""

    def __init__(self, length=None, type_definition=None,
                 evaluated_length=None, **kw):
        """Initiates an CArray object with length and type definition.

        Args:
            length: An expression representing the number of the elements in
                    the array.
            type_definition: An object representing a type of the elements
                    of the array. May be None.
            evaluated_length: An int representing the evaluated lenght of the
                    array.  May be None.
        """
        super(CArray, self).__init__(**kw)
        self.type_definition = type_definition
        self.length = length
        self.evaluated_length = evaluated_length


class CPointer(CTypeContainer):
    """A class representing a pointer type."""

    def __init__(self, type_definition=None, **kw):
        """Initiates a CPointer object with type_definition.

        Args:
            type_definition: an object representing a type definition under the
                pointer. May be None.
        """
        super(CPointer, self).__init__(**kw)
        self.type_definition = type_definition


class CFunction(CTypeContainer):
    """A class representing a CFunction type."""

    def insert_type_definition(self, type_definition):
        """Purposefully does nothing.

        The parser does not track the type of the underlying function.

        Args:
            type_definition: an object representing a type_definition.
        """
        pass


class CSimpleType(CASTNode):

    def __init__(self, bit_size, bit_alignment, signed=False, **kw):
        super(CSimpleType, self).__init__(**kw)
        self.bit_size = bit_size
        self.bit_alignment = bit_alignment
        self.signed = signed


class CVoidType(CASTNode):
    """A Special type representing Void."""


class CTypeReference(CASTNode):
    """A class representing a reference to a type by name."""

    def __init__(self, name, **kw):
        """Initializes a CTypeReference object with type name.

        Args:
            name: a string representing the name of the referenced type.
        """
        super(CTypeReference, self).__init__(**kw)
        self.name = name


class CTypeDefinition(CASTNode):
    """A class representing a definition of a type.

    E.g. a struct, union or enum definition. But not simple typedefs.
    """

    def __init__(self, name, type_definition, following_fields=None, **kw):
        """Initializes a CTypeDefinition object.

        Args:
            name: a string representing the name of the defined type.
                May be None.
            type_definition: an object representing a definition of the type
                e.g. an CEnum, CStruct or CUnion object.
            following_fields: a list of objects representing fields immediately
                following the definition (before the semicolon).
        """
        super(CTypeDefinition, self).__init__(**kw)
        self.name = name    # May be none
        self.type_definition = type_definition
        self.following_fields = following_fields or []


class CField(CTypeContainer):
    """A class representing a field inside of a more complex type."""

    def __init__(self, name=None, type_definition=None, bit_size=None,
                 attributes=None, **kw):
        """Initializes a field object.

        Args:
            name: a string representing a name of the field. May be None.
            type_definition: an object representing a type of the field. May be
              None.
            bit_size: an int representing a bit_size of the field, if a bit size
                is explicitly specified. May be none.
            attributes: A list of the objects representing the attributes of
                the field.

        """
        super(CField, self).__init__(**kw)
        self.name = name
        self.type_definition = type_definition
        self.bit_size = bit_size
        self.add_attributes(attributes)


class CTypedef(CTypeContainer):
    """A class to represent a typedef."""

    def __init__(self, type_definition=None, attributes=None, **kw):
        """Initializes a CTypedef object.

        Args:
            name: a string representing a new name of the type.

            type_definition: an object representing a type definition. May be
            None.

            attributes: A list of the objects representing the attributes of
                the typedef.

        """
        super(CTypedef, self).__init__(**kw)
        self.type_definition = type_definition
        self.add_attributes(attributes)


class CAttribute(CASTNode):
    """A class to represent an attribute of a type or a field."""

    def __init__(self, name, *parameters, **kw):
        """Initializes an CAttribute object with name and parameters.

        Args:
          name: a string representing the name of the attribute.

          *parameters: a list of objects representing parameters of the
        attribute.

        """
        parameters = list(parameters) + kw.pop("parameters", [])
        super(CAttribute, self).__init__(**kw)
        self.name = name
        self.parameters = parameters


class CFunctionCall(CASTNode):
    """A class to represent a function call expression."""

    _IDENTIFIER_PATTERN = re.compile(r'^\w+$')

    def __init__(self, function_name, arguments, **kw):
        """Initializes a CFunctionCall object with function name and arguments.

        Args:
            function_name: a string representing a name of the called function.

            arguments: a list of objects representing the argumets of this
                function call.
        """
        super(CFunctionCall, self).__init__(**kw)
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
                return (arguments[0] + ' ' + self.function_name +
                        ' ' + arguments[1])
        else:
            operator_characters = self.function_name
            tokens = []
            if len(arguments) > len(operator_characters):
                tokens.append(arguments[0])
                following_arguments = arguments[1:]
            else:
                following_arguments = arguments
            operators_and_arguments = zip(
                operator_characters, following_arguments)

            tokens.extend(itertools.chain(*operators_and_arguments))
            separator = ' ' if len(arguments) > 1 else ''
            return separator.join(tokens)


class CNestedExpression(CASTNode):

    def __init__(self, opener, content, closer, **kw):
        super(CNestedExpression, self).__init__(**kw)
        self.opener = opener
        self.content = content
        self.closer = closer

    def __str__(self):
        return self.opener + str(self.content) + self.closer


class CVariable(CASTNode):
    """A class to represent a variable reference expression."""

    def __init__(self, name=None, **kw):
        """Initializes with a name of the referenced variable.

        Args:
            name: a string representing a name of the referenced variable.
        """
        super(CVariable, self).__init__(**kw)
        self.name = name

    def __str__(self):
        return self.name


class CLiteral(CASTNode):
    """A class to represent a string literal expression."""

    def __init__(self, value, **kw):
        """Initializes a CLiteral object with a string.

        Args:
        value: a string representing the value of the literal.
        """
        super(CLiteral, self).__init__(**kw)
        self.value = value

    def __str__(self):
        return str(self.value)

    def __bool__(self):
        return bool(self.value)

    def __repr__(self):
        return "%s{%r}" % (self.__class__.__name__, self.value)


class CNumber(CLiteral):
    """A class to represent a number literal expression."""

    def __str__(self):
        return str(self.value)

    def __int__(self):
        return int(self.value)

    def __eq__(self, other):
        if other == self.value:
            return True

        if type(other) == CNumber:
            return other.value == self.value

        return False


json_serialization.DataContainerObjectRenderer.set_safe_constructors(
    CArray,
    CEnum,
    CEnumField,
    CField,
    CFunctionCall,
    CLiteral,
    CNestedExpression,
    CNumber,
    CPointer,
    CFunction,
    CProgram,
    CSimpleType,
    CStruct,
    CTypeDefinition,
    CTypeReference,
    CTypedef,
    CUnion,
    CVariable,
    CAttribute,
    CVoidType
)
