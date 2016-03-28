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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys
import unittest

import pyparsing

from layout_expert.c_ast import c_ast
from layout_expert.c_ast import c_ast_test
from layout_expert.c_ast import pre_ast
from layout_expert.lib import type_manager as type_manager_module
from layout_expert.parsers import expression_parser


sys.setrecursionlimit(10000)


class TestMacroExpressionParser(c_ast_test.CASTTestCase):
    """Test for macro style expressions."""

    def setUp(self):
        self.parser = expression_parser.ExpressionParser()

    def test_parse_defined_with_parentheses(self):
        source = 'defined (CONFIG_SOMETHING)'
        expected = c_ast.CFunctionCall(
            function_name='defined',
            arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_not_defined_with_parentheses(self):
        source = '!defined (CONFIG_SOMETHING)'
        expected = c_ast.CFunctionCall(
            function_name='!',
            arguments=[
                c_ast.CFunctionCall(
                    function_name='defined',
                    arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
                ),
            ],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_defined_function_like(self):
        source = 'defined(CONFIG_SOMETHING)'
        expected = c_ast.CFunctionCall(
            function_name='defined',
            arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_not_defined_function_like(self):
        source = '!defined(CONFIG_SOMETHING)'
        expected = c_ast.CFunctionCall(
            function_name='!',
            arguments=[
                c_ast.CFunctionCall(
                    function_name='defined',
                    arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
                ),
            ],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)


class TestExpressionParser(c_ast_test.CASTTestCase):
    """Test class for the expression_parser() method.

    Note that the operator precedence is tested only partially since it is
    provided by the external pyparsing.infixNotation(...) function.
    """

    def setUp(self):
        self.type_manager = type_manager_module.TypeManager()
        self.parser = expression_parser.ExpressionParser(
            type_manager=self.type_manager)

        self.unary_operators = '+', '-', '!', '~'
        self.binary_operators = (
            '*', '/', '%',
            '+', '-',
            '<<', '>>',
            '<', '<=', '>', '>=',
            '==', '!=',
            '&',
            '^',
            '|',
            '&&',
            '||',
        )

    def test_casting_killer(self):
        # Remove the casts.
        source = '((unsigned int)(4))'
        actual = self.parser.parse(source)
        expected = c_ast.CNestedExpression(
            opener='(',
            closer=")",
            content=c_ast.CNestedExpression(
                opener='(',
                content=c_ast.CNumber(4),
                closer=')',
            ),
        )
        self.assertASTEqual(actual, expected)

        source = '1024 / (8 * sizeof(long) - 1)'
        actual = self.parser.evaluate_string(source)
        self.assertEqual(actual, 1024 // (8 * 8 - 1))

        source = """
((__be32) ((__u32) ((((__u32) ((0x00800000)) & (__u32) 0x000000ffUL) << 24) | (((__u32) ((0x00800000)) & (__u32) 0x0000ff00UL) << 8) | (((__u32) ((0x00800000)) & (__u32) 0x00ff0000UL) >> 8) | (((__u32) ((0x00800000)) & (__u32) 0xff000000UL) >> 24))))
"""
        actual = self.parser.evaluate_string(source)
        self.assertEqual(actual, 0x008000)

    def test_sizeof_evaluation(self):
        source = 'sizeof(unsigned int)'
        actual = self.parser.evaluate_string(source)
        expected = c_ast.CNumber(4)
        self.assertASTEqual(actual, expected)

        self.type_manager.add_type(
            "__kernel_uid32_t", c_ast.CTypedef(
                name="__kernel_uid32_t",
                type_definition=c_ast.CTypeReference(name="unsigned long")))

        source = 'sizeof(__kernel_uid32_t)'
        actual = self.parser.evaluate_string(source)
        expected = c_ast.CNumber(8)
        self.assertASTEqual(actual, expected)

        source = 'sizeof(_unknown_t)'
        self.assertRaises(c_ast.IrreducibleFunction,
                          self.parser.evaluate_string, source)

    def test_parse_zero(self):
        source = '0'
        expected = c_ast.CNumber(0)
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_positive_integer(self):
        source = '42'
        expected = c_ast.CNumber(42)
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_negative_integer(self):
        source = '-33'
        expected = c_ast.CFunctionCall(
            function_name='-',
            arguments=[c_ast.CNumber(33)],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_hex_integer(self):
        source = '0xaf72'
        expected = c_ast.CNumber(44914)
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_hex_integer_without_letters_as_digits(self):
        source = '0x4233'
        expected = c_ast.CNumber(16947)
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_negative_hex_integer(self):
        source = '-0xabcd'
        expected = c_ast.CFunctionCall(
            function_name='-',
            arguments=[c_ast.CNumber(43981)],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_zero_with_suffix(self):
        source = '0u'
        expected = c_ast.CNumber(0)
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_positive_integer_with_suffix(self):
        source = '314U'
        expected = c_ast.CNumber(314)
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_negative_integer_with_suffix(self):
        source = '-272l'
        expected = c_ast.CFunctionCall(
            function_name='-',
            arguments=[c_ast.CNumber(272)],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_hex_integer_with_suffix(self):
        source = '0xaf72L'
        expected = c_ast.CNumber(44914)
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_hex_integer_without_letters_as_digits_with_suffix(self):
        source = '0x4233ll'
        expected = c_ast.CNumber(16947)
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_negative_hex_integer_with_suffix(self):
        source = '-0xdcbaLL'
        expected = c_ast.CFunctionCall(
            function_name='-',
            arguments=[c_ast.CNumber(56506)],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_hex_integer_with_two_suffixes(self):
        source = '0xaf72UL'
        expected = c_ast.CNumber(44914)
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_hex_integer_with_two_suffixes_opposite_order(self):
        source = '0xaf72LU'
        expected = c_ast.CNumber(44914)
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_usigned_long_long_literal(self):
        source = '2357ull'
        expected = c_ast.CNumber(2357)
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_variable(self):
        source = 'CONFIG_SOMETHING'
        expected = c_ast.CVariable('CONFIG_SOMETHING')
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_number_in_parentheses(self):
        source = '(42)'
        expected = c_ast.CNestedExpression(
            opener='(',
            content=c_ast.CNumber(42),
            closer=')',
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_variable_in_parentheses(self):
        source = '(x)'
        expected = c_ast.CNestedExpression(
            opener='(',
            content=c_ast.CVariable('x'),
            closer=')',
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_variable_in_parentheses2(self):
        # Unfortunately our parser is not that great since it misidentifies the
        # below with & is substituted for +. It accidentally considers it the
        # dereference operator.  I dont think there is a way to properly parse
        # without context (i.e. cant make a context free grammer) because you
        # need to resolve the RHS to the & operator to know if it makes sense.
        source = '(((x) + 1) | 2)'
        actual = self.parser.parse(source)
        expected = c_ast.CNestedExpression(
            opener='(',
            closer=')',
            content=c_ast.CFunctionCall(
                function_name="|",
                arguments=[
                    c_ast.CNestedExpression(
                        opener='(',
                        closer=')',
                        content=c_ast.CFunctionCall(
                            function_name="+",
                            arguments=[
                                c_ast.CNestedExpression(
                                    opener='(',
                                    content=c_ast.CVariable('x'),
                                    closer=')',
                                ),
                                c_ast.CNumber(1),
                            ])
                    ),
                    c_ast.CNumber(2)
                ]
            )
        )

        self.assertASTEqual(actual, expected)

    def test_unary_operator_and_parentheses(self):
        source = '-(33)'
        expected = c_ast.CFunctionCall(
            function_name='-',
            arguments=[
                c_ast.CNestedExpression(
                    opener='(',
                    content=c_ast.CNumber(33),
                    closer=')',
                ),
            ],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_function_call_with_no_arguments(self):
        source = 'f()'
        expected = c_ast.CFunctionCall(
            function_name='f',
            arguments=[],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_function_call_with_one_argument(self):
        source = 'f(a)'
        expected = c_ast.CFunctionCall(
            function_name='f',
            arguments=[c_ast.CVariable('a')],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_function_call_with_multiword_argument(self):
        source = 'f(union u)'
        expected = c_ast.CFunctionCall(
            function_name='f',
            arguments=[
                pre_ast.CompositeBlock([
                    c_ast.CVariable('union'),
                    c_ast.CVariable('u'),
                ]),
            ],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_function_call_with_two_arguments(self):
        source = 'f(a, 42)'
        expected = c_ast.CFunctionCall(
            function_name='f',
            arguments=[
                c_ast.CVariable('a'),
                c_ast.CNumber(42),
            ],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_function_call_with_five_arguments(self):
        source = 'f(2, 3, 5, 7, 11)'
        expected = c_ast.CFunctionCall(
            function_name='f',
            arguments=[
                c_ast.CNumber(2),
                c_ast.CNumber(3),
                c_ast.CNumber(5),
                c_ast.CNumber(7),
                c_ast.CNumber(11),
            ],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_attribute(self):
        source = '__attribute__((x))'
        expected = c_ast.CFunctionCall(
            function_name='__attribute__',
            arguments=[
                c_ast.CVariable('x'),
            ],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_cast_expression_without_parentheses(self):
        source = 'int x'
        with self.assertRaises(pyparsing.ParseException):
            self.parser.parse(source)

    def test_multiplication_in_parentheses_and_binary_minus(self):
        # This is tricky because it's not a cast and an unary minus.  To fully
        # distinguish those cases we would need to know what identifiers are
        # types and what identifiers are variables, e.g.
        #         (x) - y
        # depends on the meaning of x. If x is a type then it can be a cast and
        # an unary minus, if x is a variable then it is a binary minus.
        source = '(a * b) - c'
        actual = self.parser.parse(source)
        expected = c_ast.CFunctionCall(
            function_name='-',
            arguments=[
                c_ast.CNestedExpression(
                    opener='(',
                    content=c_ast.CFunctionCall(
                        function_name='*',
                        arguments=[
                            c_ast.CVariable('a'),
                            c_ast.CVariable('b'),
                        ],
                    ),
                    closer=')'
                ),
                c_ast.CVariable('c'),
            ],
        )
        self.assertASTEqual(actual, expected)

    def test_parse_parentheses_and_binary_plus(self):
        source = '(a) + b'
        actual = self.parser.parse(source)
        expected = c_ast.CFunctionCall(
            function_name='+',
            arguments=[
                c_ast.CNestedExpression(
                    opener='(',
                    content=c_ast.CVariable('a'),
                    closer=')',
                ),
                c_ast.CVariable('b'),
            ],
        )
        self.assertASTEqual(actual, expected)

    def test_parse_complex_parentheses_expression(self):
        source = '(((x) + (y)) & ~(y))'
        actual = self.parser.parse(source)
        expected = c_ast.CNestedExpression(
            opener='(',
            content=c_ast.CFunctionCall(
                function_name='&',
                arguments=[
                    c_ast.CNestedExpression(
                        opener='(',
                        content=c_ast.CFunctionCall(
                            function_name='+',
                            arguments=[
                                c_ast.CNestedExpression(
                                    opener='(',
                                    content=c_ast.CVariable('x'),
                                    closer=')',
                                ),
                                c_ast.CNestedExpression(
                                    opener='(',
                                    content=c_ast.CVariable('y'),
                                    closer=')',
                                ),
                            ],
                        ),
                        closer=')',
                    ),
                    c_ast.CFunctionCall(
                        function_name='~',
                        arguments=[
                            c_ast.CNestedExpression(
                                opener='(',
                                content=c_ast.CVariable('y'),
                                closer=')',
                            ),
                        ],
                    ),
                ],
            ),
            closer=')',
        )
        self.assertASTEqual(actual, expected)

    def test_parse_array_expression(self):
        source = 't[x]'
        actual = self.parser.parse(source)
        expected = c_ast.CFunctionCall(
            function_name='[]',
            arguments=[
                c_ast.CVariable('t'),
                c_ast.CVariable('x'),
            ],
        )
        self.assertASTEqual(actual, expected)

    def test_parse_multidimensional_array_expression(self):
        source = 't[x][y]'
        actual = self.parser.parse(source)
        expected = c_ast.CFunctionCall(
            function_name='[]',
            arguments=[
                c_ast.CFunctionCall(
                    function_name='[]',
                    arguments=[
                        c_ast.CVariable('t'),
                        c_ast.CVariable('x'),
                    ],
                ),
                c_ast.CVariable('y'),
            ],
        )
        self.assertASTEqual(actual, expected)

    def test_parse_unary_operator_with_number(self):
        for unary_operator in self.unary_operators:
            source = unary_operator + '33'
            actual = self.parser.parse(source)
            expected = c_ast.CFunctionCall(
                function_name=unary_operator,
                arguments=[c_ast.CNumber(33)],
            )
            self.assertASTEqual(actual, expected)

    def test_parse_unary_operator_with_variable(self):
        for unary_operator in self.unary_operators:
            source = unary_operator + 'CONFIG_SOMETHING'
            actual = self.parser.parse(source)
            expected = c_ast.CFunctionCall(
                function_name=unary_operator,
                arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
            )
            self.assertASTEqual(actual, expected)

    def test_parse_binary_operator_with_number_and_variable(self):
        for binary_operator in self.binary_operators:
            source = 'CONFIG_SOMETHING' + binary_operator + '42'
            actual = self.parser.parse(source)
            expected = c_ast.CFunctionCall(
                function_name=binary_operator,
                arguments=[
                    c_ast.CVariable('CONFIG_SOMETHING'),
                    c_ast.CNumber(42),
                ]
            )
            self.assertASTEqual(actual, expected)

    def test_parse_binary_operator_with_variable_and_number(self):
        for binary_operator in self.binary_operators:
            source = '51' + binary_operator + 'CONFIG_SOMETHING'
            actual = self.parser.parse(source)
            expected = c_ast.CFunctionCall(
                function_name=binary_operator,
                arguments=[
                    c_ast.CNumber(51),
                    c_ast.CVariable('CONFIG_SOMETHING'),
                ]
            )
            self.assertASTEqual(actual, expected)

    def test_parse_binary_operator_with_function_calls(self):
        source = 'defined(CONFIG_SOMETHING) && defined(CONFIG_SOMETHING_ELSE)'
        expected = c_ast.CFunctionCall(
            function_name='&&',
            arguments=[
                c_ast.CFunctionCall(
                    function_name='defined',
                    arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
                ),
                c_ast.CFunctionCall(
                    function_name='defined',
                    arguments=[c_ast.CVariable('CONFIG_SOMETHING_ELSE')],
                ),
            ],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_ternary_conditional(self):
        source = 'a ? b : c'
        actual = self.parser.parse(source)
        expected = c_ast.CFunctionCall(
            function_name='?:',
            arguments=[
                c_ast.CVariable('a'),
                c_ast.CVariable('b'),
                c_ast.CVariable('c'),
            ],
        )
        self.assertASTEqual(actual, expected)

    def test_parse_same_precedence_operators_plus_and_minus(self):
        source = 'a + b - c'
        expected = c_ast.CFunctionCall(
            function_name='-',
            arguments=[
                c_ast.CFunctionCall(
                    function_name='+',
                    arguments=[
                        c_ast.CVariable('a'),
                        c_ast.CVariable('b'),
                    ],
                ),
                c_ast.CVariable('c'),
            ],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_same_precedence_operators_minus_and_plus(self):
        source = 'a - b + c'
        expected = c_ast.CFunctionCall(
            function_name='+',
            arguments=[
                c_ast.CFunctionCall(
                    function_name='-',
                    arguments=[
                        c_ast.CVariable('a'),
                        c_ast.CVariable('b'),
                    ],
                ),
                c_ast.CVariable('c'),
            ],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_same_precedence_operators_plus_and_plus(self):
        source = 'a + b + c'
        expected = c_ast.CFunctionCall(
            function_name='+',
            arguments=[
                c_ast.CFunctionCall(
                    function_name='+',
                    arguments=[
                        c_ast.CVariable('a'),
                        c_ast.CVariable('b'),
                    ],
                ),
                c_ast.CVariable('c'),
            ],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_addition_and_multiplication_precedence(self):
        source = 'a + b * c'
        expected = c_ast.CFunctionCall(
            function_name='+',
            arguments=[
                c_ast.CVariable('a'),
                c_ast.CFunctionCall(
                    function_name='*',
                    arguments=[
                        c_ast.CVariable('b'),
                        c_ast.CVariable('c'),
                    ]
                )
            ]
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_parentheses_with_addition_and_multiplication(self):
        source = '(a + b) * c'
        expected = c_ast.CFunctionCall(
            function_name='*',
            arguments=[
                c_ast.CNestedExpression(
                    opener='(',
                    content=c_ast.CFunctionCall(
                        function_name='+',
                        arguments=[
                            c_ast.CVariable('a'),
                            c_ast.CVariable('b'),
                        ],
                    ),
                    closer=')',
                ),
                c_ast.CVariable('c'),
            ]
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_binary_operators_with_parentheses_on_left(self):
        source = '(x == 4 && y >= 3) || y > 4'
        expected = c_ast.CFunctionCall(
            function_name='||',
            arguments=[
                c_ast.CNestedExpression(
                    opener='(',
                    content=c_ast.CFunctionCall(
                        function_name='&&',
                        arguments=[
                            c_ast.CFunctionCall(
                                function_name='==',
                                arguments=[
                                    c_ast.CVariable('x'),
                                    c_ast.CNumber(4),
                                ],
                            ),
                            c_ast.CFunctionCall(
                                function_name='>=',
                                arguments=[
                                    c_ast.CVariable('y'),
                                    c_ast.CNumber(3),
                                ]
                            ),
                        ],
                    ),
                    closer=')',
                ),
                c_ast.CFunctionCall(
                    function_name='>',
                    arguments=[
                        c_ast.CVariable('y'),
                        c_ast.CNumber(4),
                    ],
                ),
            ],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_comparison_and_shift_with_parentheses_on_right(self):
        source = 'x < (1 << 14)'
        expected = c_ast.CFunctionCall(
            function_name='<',
            arguments=[
                c_ast.CVariable('x'),
                c_ast.CNestedExpression(
                    opener='(',
                    content=c_ast.CFunctionCall(
                        function_name='<<',
                        arguments=[
                            c_ast.CNumber(1),
                            c_ast.CNumber(14),
                        ]
                    ),
                    closer=')',
                ),
            ],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_binary_operators_with_parentheses_on_right(self):
        source = 'x < 4 || (y == 4 && z < 1)'
        expected = c_ast.CFunctionCall(
            function_name='||',
            arguments=[
                c_ast.CFunctionCall(
                    function_name='<',
                    arguments=[
                        c_ast.CVariable('x'),
                        c_ast.CNumber(4),
                    ],
                ),
                c_ast.CNestedExpression(
                    opener='(',
                    content=c_ast.CFunctionCall(
                        function_name='&&',
                        arguments=[
                            c_ast.CFunctionCall(
                                function_name='==',
                                arguments=[
                                    c_ast.CVariable('y'),
                                    c_ast.CNumber(4),
                                ],
                            ),
                            c_ast.CFunctionCall(
                                function_name='<',
                                arguments=[
                                    c_ast.CVariable('z'),
                                    c_ast.CNumber(1),
                                ],
                            ),
                        ],
                    ),
                    closer=')',
                ),
            ],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_logical_or_and_negation(self):
        source = 'someFunction(a) || !defined(b) || c < 2'
        expected = c_ast.CFunctionCall(
            function_name='||',
            arguments=[
                c_ast.CFunctionCall(
                    function_name='||',
                    arguments=[
                        c_ast.CFunctionCall(
                            function_name='someFunction',
                            arguments=[c_ast.CVariable('a')],
                        ),
                        c_ast.CFunctionCall(
                            function_name='!',
                            arguments=[
                                c_ast.CFunctionCall(
                                    function_name='defined',
                                    arguments=[c_ast.CVariable('b')],
                                )
                            ],
                        ),
                    ],
                ),
                c_ast.CFunctionCall(
                    function_name='<',
                    arguments=[
                        c_ast.CVariable('c'),
                        c_ast.CNumber(2),
                    ],
                ),
            ],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_unary_operator_on_expression_in_parentheses(self):
        source = '!(x > 0 || y == 0)'
        expected = c_ast.CFunctionCall(
            function_name='!',
            arguments=[
                c_ast.CNestedExpression(
                    opener='(',
                    content=c_ast.CFunctionCall(
                        function_name='||',
                        arguments=[
                            c_ast.CFunctionCall(
                                function_name='>',
                                arguments=[
                                    c_ast.CVariable('x'),
                                    c_ast.CNumber(0),
                                ],
                            ),
                            c_ast.CFunctionCall(
                                function_name='==',
                                arguments=[
                                    c_ast.CVariable('y'),
                                    c_ast.CNumber(0),
                                ],
                            ),
                        ],
                    ),
                    closer=')',
                ),
            ],
        )
        actual = self.parser.parse(source)
        self.assertASTEqual(actual, expected)

    def test_parse_sizeof(self):
        source = 'sizeof(struct s*)'
        actual = self.parser.parse(source)
        expected = c_ast.CFunctionCall(
            function_name='sizeof',
            arguments=[c_ast.CLiteral('struct s*')],
        )
        self.assertASTEqual(actual, expected)

    def test_parse_sizeof_with_double_underscores_of_array(self):
        source = '__sizeof__(unsigned int[42])'
        actual = self.parser.parse(source)
        expected = c_ast.CFunctionCall(
            function_name='__sizeof__',
            arguments=[c_ast.CLiteral('unsigned int[42]')],
        )
        self.assertASTEqual(actual, expected)

    def test_parse_alignof_with_double_underscores(self):
        source = '__alignof__(struct s*)'
        actual = self.parser.parse(source)
        expected = c_ast.CFunctionCall(
            function_name='__alignof__',
            arguments=[c_ast.CLiteral('struct s*')],
        )
        self.assertASTEqual(actual, expected)

    def test_parse_alignof_with_double_underscores_of_array(self):
        source = '__alignof__(unsigned int[42])'
        actual = self.parser.parse(source)
        expected = c_ast.CFunctionCall(
            function_name='__alignof__',
            arguments=[c_ast.CLiteral('unsigned int[42]')],
        )
        self.assertASTEqual(actual, expected)

    def test_parse_sizeof_and_binary_plus_operators_and_additional_parentheses(
            self):
        source = """
                ( sizeof(struct ymmh_struct)
                 + sizeof(struct lwp_struct)
                 + sizeof(struct mpx_struct)
                )
                """
        actual = self.parser.parse(source)
        expected = c_ast.CNestedExpression(
            opener='(',
            content=c_ast.CFunctionCall(
                function_name='+',
                arguments=[
                    c_ast.CFunctionCall(
                        function_name='+',
                        arguments=[
                            c_ast.CFunctionCall(
                                function_name='sizeof',
                                arguments=[
                                    c_ast.CLiteral('struct ymmh_struct')],
                            ),
                            c_ast.CFunctionCall(
                                function_name='sizeof',
                                arguments=[
                                    c_ast.CLiteral('struct lwp_struct')],
                            ),
                        ],
                    ),
                    c_ast.CFunctionCall(
                        function_name='sizeof',
                        arguments=[
                            c_ast.CLiteral('struct mpx_struct')],
                    ),
                ],
            ),
            closer=')',
        )
        self.assertASTEqual(actual, expected)

    def test_parse_sizeof_and_binary_operators(self):
        source = """
                ((((1 << 0)) + (8 * sizeof(long)) - 1) / (8 * sizeof(long)))
                """
        actual = self.parser.evaluate_string(source)
        expected = ((((1 << 0)) + (8 * 8) - 1) / (8 * 8))
        self.assertEqual(actual, expected)

    def test_evaluator(self):
        source = 'x + (1 << 14)'
        # Cant evaluate the expression without a value for x.
        self.assertRaises(
            c_ast.IrreducibleFunction,
            self.parser.evaluate_string, source)

        # Now we provide a value for x - it should evaluate the expression.
        self.type_manager.add_constant("x", c_ast.CNumber(10))
        result = self.parser.evaluate_string(source)
        self.assertEqual(result, 10 + (1 << 14))

    def test_typeof_evaluation(self):
        source = """
((((32)) + ((typeof((32))) ((sizeof(unsigned long))) - 1)) & ~ ((typeof((32))) ((sizeof(unsigned long))) - 1))
        """
        result = self.parser.evaluate_string(source)
        self.assertEqual(result, ((((32)) + (((8)) - 1)) & ~ (((8)) - 1)))

    def test_expression2(self):
        source = """
        (1 << (6))
        """
        result = self.parser.evaluate_string(source)
        self.assertEqual(result, 1 << 6)


if __name__ == '__main__':
    unittest.main()
