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

"""A module containing an expression parser intended for C header files."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pyparsing

from layout_expert.lib import parsers
from layout_expert.c_ast import c_ast
from layout_expert.c_ast import pre_ast
from layout_expert.parsers import util

# pylint: disable=expression-not-assigned

_UNARY = 1
_BINARY = 2
_TERNARY = 3

_LEFT = pyparsing.opAssoc.LEFT
_RIGHT = pyparsing.opAssoc.RIGHT

_OPEN_PARENTHESIS = pyparsing.Literal('(').suppress()
_CLOSE_PARENTHESIS = pyparsing.Literal(')').suppress()
_OPEN_BRACKETS = pyparsing.Literal('[').suppress()
_CLOSE_BRACKETS = pyparsing.Literal(']').suppress()

_UNARY_C = (
    # C's & dereference operator.
    (('+', '-', '!', '~', '&'), _UNARY, _RIGHT),
)

_UNARY_MACROS = (
    # Macro expressions cant use dereference.
    (('+', '-', '!', '~'), _UNARY, _RIGHT),
)

_PRECEDENCE = (
    (('*', '/', '%'), _BINARY, _LEFT),
    (('+', '-', '->', '.', "|"), _BINARY, _LEFT),
    (('<<', '>>'), _BINARY, _LEFT),
    (('<=', '<', '>', '>='), _BINARY, _LEFT),

    (('==', '!=', '='), _BINARY, _LEFT),

    (('&&',), _BINARY, _LEFT),
    (('||',), _BINARY, _LEFT),
    (('&',), _BINARY, _LEFT),
    (('^',), _BINARY, _LEFT),
    (('|',), _BINARY, _LEFT),

    (('?', ':'), _TERNARY, _LEFT),
)

_SIZEOF = pyparsing.Keyword('sizeof') | pyparsing.Keyword('__sizeof__')
_ALIGNOF = pyparsing.Keyword('__alignof__')

_TYPE_PROPERTY_KEYWORD = _SIZEOF | _ALIGNOF

_PLUS = pyparsing.Literal('+').suppress()
_MINUS = pyparsing.Literal('-').suppress()
_STAR = pyparsing.Literal("*")



class ExpressionParser(object):
    """A parser for C expressions.

    This parser is shared between the macro manager and the C parser. In order
    to parse C expressions a type manager is required. If type_manager is None,
    then this parser will not process C cast and unary reference expressions.

    """

    def __init__(self, type_manager=None):
        self.type_manager = type_manager
        self.parser = self.expression_parser()
        self.cast_transformer = self._cast_transformer()
        self.parentheses_reducer = self._parentheses_reducer()
        self.typeof_transform = self._typeof_transform()

    def _transform_until_no_change(self, transformer, source):
        """Keep applying the transform until the string has not changed."""
        while 1:
            new_source = transformer.transformString(source)
            if new_source == source:
                return new_source

            source = new_source

    @util.pyparsing_debug
    def _cast_transformer(self):
        """Removes obvious casts."""
        return pyparsing.Combine(
            pyparsing.Regex(r"\([^()]*\)").suppress()
            + (pyparsing.Word(pyparsing.alphanums + "_")
               | pyparsing.Literal("(")),
            adjacent=False)

    @util.pyparsing_debug
    def _parentheses_reducer(self):
        """Removes useless parentheses."""
        return (
            _OPEN_PARENTHESIS
            + parsers.anything_in_parentheses()("nested")
            + _CLOSE_PARENTHESIS
        ).setParseAction(lambda tok: tok.nested)

    def _typeof_transform(self):
        """Removes typeof expressions."""
        return (
            _OPEN_PARENTHESIS
            + pyparsing.Keyword('typeof')
            + parsers.anything_in_parentheses()
            + _CLOSE_PARENTHESIS
        ).suppress()

    def transform(self, source):
        """Transform the source to make it easier to parse.

        Since we use pyparsing's precedence parser it seems to be incompatible
        with casts because they look like brackets around expressions. It is
        hard to force the standard precedence parser to realize that casts are
        highest precedence. Therefore we specifically search for casts first
        off, then enclose them in parentheses to force precedence order in
        parsing.
        """
        source = self.typeof_transform().transformString(source)
        source = self._transform_until_no_change(
            self.parentheses_reducer, source)
        source = self.cast_transformer.transformString(source)

        return source

    def parse(self, source):
        """Returns a C_AST representing the source."""
        pyparsing.ParserElement.enablePackrat()    # speed hack

        # Transform the source in order to enforce precedence.
        source = self.transform(source)
        # If we know about types we can remove casts.
        return self.parser.parseString(source, parseAll=True)[0]

    def evaluate_string(self, source):
        expression_ast = self.parse(source)
        return self.type_manager.evaluate(expression_ast)

    def _build_precedence(self, precedence_table):
        # C's & dereference operator.
        precedence = []
        for operators, arity, associativity in precedence_table:
            operators = [pyparsing.Literal(x) for x in operators]

            if arity in [_UNARY, _BINARY]:
                operators = pyparsing.Or(operators)

            precedence.append((
                operators,
                arity,
                associativity,
                self._construct_operator(arity),
            ))
        return precedence

    def expression_parser(self):
        """A function returning a (pyparsing) parser for parsing C expressions.

        Returns:
            a (pyparsing) parser for parsing C expressions.
        """
        precedence = (self._build_precedence(_UNARY_MACROS) +
                      self._build_precedence(_PRECEDENCE))

        self.expression = pyparsing.Forward()

        # pylint: disable=expression-not-assigned
        self.expression << (
            pyparsing.infixNotation(
                baseExpr=self._base_or_array_expression(),
                opList=precedence,
            )
        )

        return self.expression

    def _construct_operator(self, arity):
        if arity == _UNARY:
            return self._construct_unary
        elif arity == _BINARY:
            return self._construct_binary
        elif arity >= _TERNARY:
            return self._construct_ternary_or_more

    def _construct_unary(self, tok):
        expression_tokens = tok.first
        operator_name, argument = expression_tokens
        return c_ast.CFunctionCall(
            function_name=operator_name,
            arguments=[argument],
        )

    def _construct_binary(self, tok):
        expression_tokens = tok.first
        result = expression_tokens[0]
        operators = expression_tokens[1::2]
        values = expression_tokens[2::2]
        for operator_name, value in zip(operators, values):
            result = c_ast.CFunctionCall(
                function_name=operator_name,
                arguments=[result, value],
            )
        return result

    def _construct_ternary_or_more(self, tok):
        expression_tokens = tok.first
        arguments = expression_tokens[::2]
        operators = expression_tokens[1::2]
        function_name = ''.join(operators)
        return c_ast.CFunctionCall(
            function_name=function_name,
            arguments=arguments,
        )

    def _base_or_array_expression(self):
        array_indices = pyparsing.ZeroOrMore(
            _OPEN_BRACKETS
            + self.expression
            + _CLOSE_BRACKETS
        )
        return (
            self._base_expression()
            + pyparsing.Group(array_indices)
        ).setParseAction(self._create_base_or_array_expression)

    @util.action
    def _create_base_or_array_expression(self, array_expression, indices):
        """Creates FunctionCalls for array calls of a form t[x][y]...[z]."""
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

    def _base_expression(self):
        result = (
            self._number()
            | self._string_literal()
            | self._type_property()
            | self._function_call()
            | self._variable()
        )

        # We need a type manager to parse cast expressions.
        if self.type_manager:
            return (result
                    | self._nested_expression())

        return (result
                | self._nested_expression())

    def _function_call(self):
        return (
            ~_TYPE_PROPERTY_KEYWORD
            + self._identifier()
            + _OPEN_PARENTHESIS
            + self._arguments()
            + _CLOSE_PARENTHESIS
        ).setParseAction(util.action(c_ast.CFunctionCall))

    def _arguments(self):
        return pyparsing.Group(
            pyparsing.Optional(pyparsing.delimitedList(self._argument()))
        )

    def _argument(self):
        return (
            self._multiword_argument()
            | self.expression
            | self._argument_with_dots()
        )

    def _multiword_argument(self):
        return pyparsing.Group(
            self._variable()
            + pyparsing.OneOrMore(self._variable())
        ).setParseAction(util.action(pre_ast.CompositeBlock))

    def _argument_with_dots(self):
        return (
            self._identifier_with_dots()
        ).setParseAction(util.action(c_ast.CLiteral))

    def _type_property(self):
        return (
            _TYPE_PROPERTY_KEYWORD
            + _OPEN_PARENTHESIS
            + pyparsing.Word(pyparsing.alphanums + ' _*[]')
            + _CLOSE_PARENTHESIS
        ).setParseAction(self._create_sizeof_type)

    @util.action
    def _create_sizeof_type(self, sizeof, type_name):
        return c_ast.CFunctionCall(
            function_name=sizeof,
            arguments=[c_ast.CLiteral(type_name)],
        )

    @util.pyparsing_debug
    def XXXX_cast_expression(self):
        """A function returning a parser for parsing cast expressions.

        Args:
            expression: a pyparsing parser for parsing an expression to be cast.

        Returns:
            A (pyparsing) parser for parsing cast expressions.
        """
        word = pyparsing.Word(pyparsing.alphanums + '_*[]')
        nested = pyparsing.Forward().setName("nested")
        nested << pyparsing.Combine(
            pyparsing.Literal('(').suppress()
            + pyparsing.Combine(
                pyparsing.ZeroOrMore(self._integer() | word | nested))
            + pyparsing.Literal(')').suppress()
        )
        typeof_expression = (
            _OPEN_PARENTHESIS
            + pyparsing.Keyword('typeof')
            + nested("typeof_arg")
            + _CLOSE_PARENTHESIS
        )

        type_expression = (
            typeof_expression
            | nested("simple_type")
        )
        return (
            type_expression
            + ~(_PLUS | _MINUS)
            + self.expression("expression")
        ).setParseAction(self._create_cast_expression)

    def XXXX_create_cast_expression(self, tok):
        if tok.typeof_arg:
            type_expression = self.type_manager.get_type_of(
                tok.typeof_arg.first)
        else:
            type_expression = tok.simple_type

        # Check that casting makes sense.
        target = self.type_manager.get_type_of(type_expression)
        if not target:
            raise pyparsing.ParseException(
                "%s is not a type" % target)

        return c_ast.CFunctionCall(
            function_name='()',
            arguments=[
                c_ast.CLiteral(target),
                tok.expression,
            ],
        )

    @util.pyparsing_debug
    def _nested_expression(self):
        return (
            pyparsing.Literal('(')
            + self.expression
            + pyparsing.Literal(')')
        ).setParseAction(util.action(c_ast.CNestedExpression))

    @util.pyparsing_debug
    def _variable(self):
        return (
            self._identifier()
        ).addParseAction(util.action(c_ast.CVariable))

    @util.pyparsing_debug
    def _identifier(self):
        return parsers.identifier()

    @util.pyparsing_debug
    def _identifier_with_dots(self):
        return pyparsing.Word(
            pyparsing.alphas + '_.', pyparsing.alphanums + '_.')

    @util.pyparsing_debug
    def _string_literal(self):
        return (
            pyparsing.dblQuotedString.copy()
        ).setParseAction(util.action(c_ast.CLiteral))

    @util.pyparsing_debug
    def _number(self):
        return self._integer().addParseAction(util.action(c_ast.CNumber))

    @util.pyparsing_debug
    def _integer(self):
        integer = self._hexadecimal_as_string() | self._decimal_as_string()
        # Python does not care about suffixes so we just drop them.
        possible_suffix = pyparsing.Literal('u') | 'U' | 'll' | 'LL' | 'l' | 'L'
        maybe_suffix = (
            pyparsing.ZeroOrMore(possible_suffix)
        ).suppress()
        return (
            integer
            + maybe_suffix
        ).setParseAction(util.action(lambda x: int(x, base=0)))

    @util.pyparsing_debug
    def _decimal_as_string(self):
        return pyparsing.Word(pyparsing.nums)

    @util.pyparsing_debug
    def _hexadecimal_as_string(self):
        return pyparsing.Combine('0x' + pyparsing.Word(pyparsing.hexnums))
