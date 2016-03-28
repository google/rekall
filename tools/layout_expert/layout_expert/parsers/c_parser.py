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

"""A module containing a parser intended for C header files."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

# pylint: disable=expression-not-assigned
# pylint: disable=pointless-statement

import pyparsing

from layout_expert.c_ast import c_ast
from layout_expert.lib import parsers
from layout_expert.parsers import expression_parser
from layout_expert.parsers import util

_LINE_END = pyparsing.LineEnd().suppress()

_ENUM = pyparsing.Keyword('enum')
_STRUCT = pyparsing.Keyword('struct')
_UNION = pyparsing.Keyword('union')
_COMPOUND_TYPE_KEYWORD = _ENUM | _STRUCT | _UNION

_TYPEDEF = pyparsing.Keyword('typedef').suppress().setName("typedef")
_DECLARATION_KEYWORD = (_COMPOUND_TYPE_KEYWORD | _TYPEDEF).suppress()

_VOLATILE = pyparsing.Keyword('volatile').suppress()
_EXTERN = pyparsing.Keyword('extern').suppress()
_STATIC = pyparsing.Keyword('static').suppress()
_INLINE = pyparsing.Keyword('inline').suppress()
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
_EQUALS = pyparsing.Word("=")

_NUMBER_TYPE_KEYWORD = (
    _INT
    | _LONG
    | _CHAR
    | _SHORT
    | _UNSIGNED
    | _SIGNED
    | _LONG_LONG
)

_SEMICOLON = pyparsing.Literal(';').suppress()
_STAR = pyparsing.Literal('*')
_COMMA = pyparsing.Literal(',')
_OPEN_BRACKET = pyparsing.Literal('[').suppress()
_CLOSE_BRACKET = pyparsing.Literal(']').suppress()
_BRACKETS = (_OPEN_BRACKET + _CLOSE_BRACKET).suppress()
_OPEN_PARENTHESIS = pyparsing.Literal('(').suppress()
_CLOSE_PARENTHESIS = pyparsing.Literal(')').suppress()
_OPEN_CURLY = pyparsing.Literal('{').suppress()
_CLOSE_CURLY = pyparsing.Literal('}').suppress()
_COLON = pyparsing.Literal(':').suppress()
_COMA = pyparsing.Literal(',').suppress()

# Apparently GCC understands either form.
_ATTRIBUTE = (pyparsing.Keyword('__attribute__') |
              pyparsing.Keyword('__attribute')).suppress()
_DOUBLE_OPEN_PARENTHESIS = _OPEN_PARENTHESIS + _OPEN_PARENTHESIS
_DOUBLE_CLOSE_PARENTHESIS = _CLOSE_PARENTHESIS + _CLOSE_PARENTHESIS

_KEYWORD = (
    _DECLARATION_KEYWORD
    | _C_FLOW_KEYWORD
    | _NUMBER_TYPE_KEYWORD
    | _ATTRIBUTE
)


class Parser(object):
    """A parser suitable for parsing C header files.

    NOTE: We only support parsing the forms that result after trimming. See
    trimming_parser._stuff_we_care_about() for a list of forms we care
    about. This parse is used to parse snippets.
    """

    def __init__(self, type_manager=None):
        self.type_manager = type_manager
        self.expression_parser = expression_parser.ExpressionParser(
            type_manager=self.type_manager)
        self.parser = self._program()
        self.anonymous_id = 0

    def parse(self, source):
        pyparsing.ParserElement.enablePackrat()
        result = self.parser.parseString(source, parseAll=True)[0]
        pyparsing.ParserElement.disablePackrat()
        return result

    def _make_anonymous_type(self, object_type):
        name = "%s __unknown_%s_%s" % (object_type, object_type,
                                       self.anonymous_id)
        self.anonymous_id += 1
        return name

    def _make_anonymous_field_name(self):
        name = "u%s" % (self.anonymous_id)
        self.anonymous_id += 1
        return name

    @util.pyparsing_debug
    def _program(self):
        return pyparsing.ZeroOrMore(
            self._element()
            | self._typedef()
        ).setParseAction(self._make_prog)

    def _make_prog(self, t):
        return c_ast.CProgram(t.asList())

    @util.pyparsing_debug
    def _typedef(self):
        """Detect a typedef expression.

        e.g:    typedef int t;
             type ref->^^^ ^<---- type_instance

        The type ref is the type that we be aliased. The type_instance is the
        name of the new type. The new name can be decorated just like a field so
        we use the same parser.

        Examples: typedef int t[100];    <---- New type t is an array of int.
                  typedef int *foo;      <---- New type foo is a pointer to int.
        """
        return (
            _TYPEDEF
            + self._maybe_attributes()("pre_attributes")
            + self._type_reference()("type_definition")
            + self._maybe_attributes()("post_attributes")
            + self._type_instance()("instance")
            + _SEMICOLON
        ).setParseAction(self._create_typedef)

    def _create_typedef(self, tok):
        type_definition = self._create_type_definition(
            tok.type_definition, tok.instance)

        typedef_name = tok.instance.type_instance_name.first

        result = c_ast.CTypedef(name=typedef_name,
                                type_definition=type_definition)

        result.add_attributes(tok.instance.attributes)
        result.add_attributes(tok.pre_attributes)
        result.add_attributes(tok.post_attributes)

        # Tell the type manager about the types.
        if result.name:
            self.type_manager.add_type(result.name, result)

        return result

    def _create_type_definition(self, type_definition, field):
        """Creates the token definition from inspecting results in tok."""
        # The initial type definition we detected.
        definition = type_definition

        # Is it a pointer to function?
        if field.function_args:
            if field.function_pointer:
                definition = c_ast.CPointer(c_ast.CFunction())
            else:
                definition = c_ast.CFunction()

        # We detected pointers - Add pointer references.
        for _ in field.type_pointer:
            definition = c_ast.CPointer(definition)

        # We detected an array - add an array reference.
        for expr in reversed(field.brackets_with_expression_inside):
            # 0 length for an anonymous array (e.g. int a[]).
            length = 0
            if expr:
                length = self.expression_parser.evaluate_string(expr)

            definition = c_ast.CArray(
                length=c_ast.CNumber(length),
                type_definition=definition
            )

        return definition

    @util.pyparsing_debug
    def _element(self):
        """The parser for all elements."""
        self.element = pyparsing.Forward()
        self.element << (
            (~_TYPEDEF) + (
                # e.g. int x;
                self._type_name_with_fields()

                # e.g. struct s {};
                | self._struct_definition_possibly_with_fields()

                # e.g. enum foo { OPTION = 1 + 2; };
                | self._enum_definition()

                | pyparsing.OneOrMore(_SEMICOLON)
            )
        )
        return self.element.setName("element")

    @util.pyparsing_debug
    def _enum_definition(self):
        """Detect an enum definition.

        e.g.
             enum foo {
                OPTION_1: 1 + 2,
                OPTION_2
             }
        """
        return (
            _ENUM
            + pyparsing.Optional(self._identifier())("enum_name")
            + _OPEN_CURLY
            + pyparsing.ZeroOrMore(
                pyparsing.Group(
                    self._identifier()("name")
                    + pyparsing.Optional(
                        _EQUALS
                        # This allows us to get even invalid expressions.
                        + pyparsing.SkipTo(pyparsing.Word(",}"))("expression")
                    )
                    + pyparsing.Optional(_COMMA)
                )
            )("fields")
            + _CLOSE_CURLY
            + self._maybe_attributes()("attributes")
        ).setParseAction(self._process_enum_definition)

    def _process_enum_definition(self, tok):
        fields = []
        for field in tok.fields:
            if field.expression:
                expression = self.expression_parser.parse(field.expression)
            else:
                expression = None

            fields.append(c_ast.CEnumField(
                name=field.name.first, value=expression))

        name = tok.enum_name
        if name:
            name = "enum %s" % tok.enum_name.first
        else:
            name = self._make_anonymous_type("enum")

        return c_ast.CTypeDefinition(
            name=name, type_definition=c_ast.CEnum(
                attributes=tok.attributes,
                fields=fields, name=name))

    @util.pyparsing_debug
    def _struct_definition_possibly_with_fields(self):
        """Detect a struct/enum/union definition.

        e.g.
              struct foobar {
                   int v[100];
              } __attribute__((packed))
        """
        return (
            (_STRUCT | _UNION)("type")
            + pyparsing.Optional(self._identifier())("type_name")
            + _OPEN_CURLY
            + pyparsing.ZeroOrMore(
                self.element
            )("fields")
            + _CLOSE_CURLY

            + self._maybe_attributes()("attributes")
        ).setParseAction(self._process_struct_definition)

    def _process_struct_definition(self, tok):
        if tok.type == "struct":
            cls_type = c_ast.CStruct
        elif tok.type == "enum":
            cls_type = c_ast.CEnum
        elif tok.type == "union":
            cls_type = c_ast.CUnion

        # Anonymous types have no real name, we generate one.
        name = tok.type_name
        if name:
            name = "%s %s" % (tok.type, tok.type_name.first)
        else:
            name = self._make_anonymous_type(tok.type)

        type_definition = cls_type(tok.fields, name=name)
        type_definition.add_attributes(tok.attributes)

        return c_ast.CTypeDefinition(
            name=name, type_definition=type_definition)

    @util.pyparsing_debug
    def _type_name_with_fields(self):
        """Detect type name definitions.

        e.g. int v1;
                 type_t v2, v3;
        type refs ^^^^  ^^^ type_instances

        Returns:
         a list of CField() instances
        """
        return (
            self._type_reference()("type_definition")
            + self._maybe_attributes()("attributes")
            + pyparsing.delimitedList(
                self._type_instance()
            )("field")
        ).setParseAction(self._create_type_name_with_fields)

    def _create_type_name_with_fields(self, tok):
        """Creates CField() list from parsed token."""
        result = []
        for field in tok["field"]:

            field.type_definition = tok.type_definition

            bit_size = None
            if field.bitfield:
                bit_size = self.expression_parser.parse(field.bitfield)

            type_definition = self._create_type_definition(
                tok.type_definition, field)

            field_ast = c_ast.CField(
                name=field.type_instance_name.first,
                bit_size=bit_size,
                attributes=tok.attributes,
                type_definition=type_definition)

            field_ast.add_attributes(field.attributes)
            result.append(field_ast)

        return result

    @util.pyparsing_debug
    def _type_reference(self):
        """A reference to a type.

        The type may be already defined in place or just refered by name.
        """
        identifier = (
            self._typeof_expression()

            # Inline struct definition.
            # e.g. struct { int x; } foo;
            | self._struct_definition_possibly_with_fields()
            | self._enum_definition()
            | self._numeric_type_identifier()
            | self._compound_type_identifier()
            | self._identifier()
        )
        return (
            pyparsing.ZeroOrMore(_VOLATILE)
            + identifier
        ).setParseAction(self._create_type_reference)

    def _create_type_reference(self, tok):
        if len(tok.type_definition) > 1:
            return c_ast.CTypeReference(" ".join(tok.type_definition.asList()))

        type_name = tok.type_definition.first
        if isinstance(type_name, c_ast.CTypeDefinition):
            return type_name

        return c_ast.CTypeReference(type_name)

    @util.pyparsing_debug
    def _type_instance(self):
        """A type declaration.

        The modifiers of a typedef:
                struct s *P[];
                         ^^^^<-    The type instance.
        """
        type_instance = (
            # Function pointer     (*f)(int foobar)
            pyparsing.ZeroOrMore(_STAR)
            + _OPEN_PARENTHESIS
            + pyparsing.Optional(_STAR("function_pointer"))
            + self._identifier()("type_instance_name")
            + _CLOSE_PARENTHESIS
            + parsers.anything_in_parentheses()("function_args")
        ) | (
            # Function object  f(foo bar *)
            pyparsing.ZeroOrMore(_STAR)
            + self._identifier()("type_instance_name")
            + parsers.anything_in_parentheses()("function_args")
        ) | (
            # Simple form: *foo[10];
            pyparsing.ZeroOrMore(_STAR)("type_pointer")
            + self._identifier()("type_instance_name")

            # Possibly array: [] , [][]
            + pyparsing.ZeroOrMore(
                _OPEN_BRACKET
                + pyparsing.SkipTo(_CLOSE_BRACKET)(
                    "brackets_with_expression_inside*")
                + _CLOSE_BRACKET)

            # Bitfields:    int x: 7;
            + pyparsing.Optional(
                _COLON
                + pyparsing.SkipTo(
                    _SEMICOLON | _COMMA)("bitfield")
            )
        )

        return pyparsing.Group(
            type_instance
            + self._maybe_attributes()
        )

    @util.pyparsing_debug
    def _maybe_attributes(self):
        """Possibly match some attributes.

        The syntax of attributes is described here:
        https://gcc.gnu.org/onlinedocs/gcc/Attribute-Syntax.html
        """
        return pyparsing.Group(
            pyparsing.ZeroOrMore(
                _ATTRIBUTE
                + _DOUBLE_OPEN_PARENTHESIS
                + pyparsing.delimitedList(
                    pyparsing.Group(
                        self._identifier()("name")
                        + pyparsing.Optional(
                            _OPEN_PARENTHESIS
                            + parsers.anything_beetween("()")("args")
                            + _CLOSE_PARENTHESIS
                        )
                    )
                )
                + _DOUBLE_CLOSE_PARENTHESIS
            ).setParseAction(self._make_attribute)
        )("attributes")

    def _make_attribute(self, tok):
        """Compose a c_ast.CAttribute() object for each attribute."""
        result = []
        for attr_specifier in tok:
            expression = []
            if attr_specifier.args:
                # Try to parse the expression if possible.
                try:
                    expression = [self.expression_parser.parse(
                        attr_specifier.args)]
                except pyparsing.ParseException:
                    pass

            result.append(c_ast.CAttribute(
                attr_specifier.name.first,
                *expression))

        return result

    @util.pyparsing_debug
    def _typeof_expression(self):
        keyword = (
            pyparsing.Keyword('typeof')
            | pyparsing.Keyword('__typeof__')
        )
        return pyparsing.Combine(
            keyword
            + pyparsing.Literal('(')
            + parsers.anything_beetween('()')
            + pyparsing.Literal(')')
        )

    @util.action
    def _create_typeof_expression(self, keyword, *arguments):
        return c_ast.CFunctionCall(
            function_name=keyword,
            arguments=arguments,
        )

    @util.pyparsing_debug
    def _numeric_type_identifier(self):
        with_sign_identifier = (
            self._number_sign_identifier()
            + pyparsing.Optional(self._number_size_identifier())
        )
        with_size_identifier = (
            pyparsing.Optional(self._number_sign_identifier())
            + self._number_size_identifier()
        )
        return with_sign_identifier | with_size_identifier

    @util.pyparsing_debug
    def _compound_type_identifier(self):
        return(
            (_ENUM | _STRUCT | _UNION)
            + self._identifier()
        )

    @util.pyparsing_debug
    def _number_sign_identifier(self):
        return _SIGNED | _UNSIGNED

    @util.pyparsing_debug
    def _number_size_identifier(self):
        may_have_int_suffix = _LONG_LONG | _SHORT | _LONG
        return _INT | _CHAR | (may_have_int_suffix + pyparsing.Optional(_INT))

    @util.pyparsing_debug
    def _identifier(self):
        proper_identifier = pyparsing.Word(
            pyparsing.alphas + '_',
            pyparsing.alphanums + '_',
        )
        return (
            (~_KEYWORD)
            + proper_identifier
        )

    @util.pyparsing_debug
    def _natural(self):
        return pyparsing.Word(pyparsing.nums).setParseAction(util.action(int))
