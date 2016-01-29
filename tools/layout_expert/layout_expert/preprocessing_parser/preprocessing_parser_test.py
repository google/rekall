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

import unittest

from layout_expert.c_ast import c_ast_test
from layout_expert.c_ast import pre_ast
from layout_expert.preprocessing_parser import preprocessing_parser


class TestPreprocessingParser(c_ast_test.CASTTestCase):

    def setUp(self):
        self.parser = preprocessing_parser.PreprocessingParser()

    def test_creation(self):
        self.assertIsNotNone(self.parser)

    def test_parse_empty_program(self):
        source = ''
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([])
        self.assertASTEqual(actual, expected)

    def test_parse_include_with_angle_brackets(self):
        source = '# include <some/path/to/file_1.h>'
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock(content=[
            pre_ast.Include(
                path='some/path/to/file_1.h',
                quotes_type="<",
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_include_with_double_quotes(self):
        source = '#include "some/path/to/file_2.h"'
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.Include(
                path='some/path/to/file_2.h',
                quotes_type='"',
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_pragma(self):
        source = '#pragma foo'
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.Pragma('foo'),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_pragma_with_string_argument(self):
        source = '#pragma "-foo"'
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.Pragma('"-foo"'),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_text_block(self):
        source = 'int x;'
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.TextBlock('int x;'),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_pragma_and_text_block(self):
        source = '\n'.join((
            '#pragma foo bar',
            'int x;',
        ))
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.Pragma("foo bar"),
            pre_ast.TextBlock('int x;'),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_error(self):
        source = '#error foo bar 42 baz'
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.Error('foo bar 42 baz'),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_define_empty_object_like(self):
        source = '#define foo'
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement="",
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_define_object_like(self):
        source = '#define foo bar'
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement='bar',
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_define_object_like_as_numeric_constant(self):
        source = '#define foo 42'
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement='42',
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_define_with_function_like_expression_and_concatenation(
            self):
        source = '#define __DECL_REG(name) uint64_t r ## name;'
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.DefineFunctionLike(
                name='__DECL_REG',
                arguments=["name"],
                replacement='uint64_t r ## name;',
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_define_funcion_like_without_arguments(self):
        source = '#define foo() bar'
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.DefineFunctionLike(
                name='foo',
                arguments=[],
                replacement='bar',
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_define_empty_funcion_like(self):
        source = '#define foo()'
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.DefineFunctionLike(
                name='foo',
                arguments=[],
                replacement="",
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_define_empty_object_like_looks_like_func(self):
        # https://gcc.gnu.org/onlinedocs/cpp/Function-like-Macros.html
        # This is not a function like macro.
        source = '#define foo (bar)'
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement="(bar)",
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_multiline_define(self):
        source = '\n'.join([
            '#define foo bar\\',
            '    baz',
            '    42',
        ])
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement='bar    baz',
            ),
            pre_ast.TextBlock('42'),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_undef(self):
        source = '#undef foo'
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.Undef('foo'),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_empty_ifdef_block(self):
        source = """
        #ifdef CONFIG_SOMETHING
        #endif
        """
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.If([
                pre_ast.ConditionalBlock(
                    conditional_expression='defined(CONFIG_SOMETHING)',
                    content=[]
                )
            ]),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_empty_ifndef_block(self):
        source = """
        #ifndef CONFIG_SOMETHING
        #endif
        """
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.If([
                pre_ast.ConditionalBlock(
                    conditional_expression="!defined(CONFIG_SOMETHING)",
                    content=[]
                ),
            ])
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_empty_ifndef_header_guard(self):
        source = """
        #ifndef _SOMETHING_H
        #define _SOMETHING_H
        #endif
        """
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.If([
                pre_ast.ConditionalBlock(
                    conditional_expression="!defined(_SOMETHING_H)",
                    content=[
                        pre_ast.DefineObjectLike(
                            name='_SOMETHING_H',
                            replacement="",
                        ),
                    ],
                ),
            ]),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_empty_ifdef_and_else_blocks(self):
        source = """
        #ifdef CONFIG_SOMETHING
        #else
        #endif
        """
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.If(
                conditional_blocks=[
                    pre_ast.ConditionalBlock(
                        conditional_expression='defined(CONFIG_SOMETHING)',
                        content=[],
                    ),
                    pre_ast.ConditionalBlock(
                        conditional_expression="1",
                        content=[],
                    )]
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_empty_if_elif_and_else_blocks(self):
        source = """
        #if CONFIG_SOMETHING
        #elif defined(CONFIG_SOMETHING_ELSE)
        #else
        #endif
        """
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.If(
                conditional_blocks=[
                    pre_ast.ConditionalBlock(
                        conditional_expression='CONFIG_SOMETHING',
                        content=[],
                    ),
                    pre_ast.ConditionalBlock(
                        conditional_expression='defined(CONFIG_SOMETHING_ELSE)',
                        content=[],
                    ),
                    pre_ast.ConditionalBlock(
                        conditional_expression='1',
                        content=[],
                    ),
                ]
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_nested_if_blocks(self):
        source = """
        #if CONFIG_SOMETHING
          #if CONFIG_SOMETHING_ELSE
            #define FOO
          #endif
        #else
            #define BAR
        #endif
        """
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.If(
                conditional_blocks=[
                    pre_ast.ConditionalBlock(
                        conditional_expression='CONFIG_SOMETHING',
                        content=[pre_ast.If(
                            conditional_blocks=[
                                pre_ast.ConditionalBlock(
                                    conditional_expression="CONFIG_SOMETHING_ELSE",
                                    content=[
                                        pre_ast.DefineObjectLike(
                                            name="FOO",
                                            replacement="")
                                    ],
                                )
                            ]
                        )]),
                    pre_ast.ConditionalBlock(
                        conditional_expression='1',
                        content=[
                            pre_ast.DefineObjectLike(
                                name="BAR",
                                replacement="")
                        ],
                    ),
                ]
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_top_level_ifdef_block(self):
        source = """
int a;
#ifdef CONFIG_SOMETHING
struct s {
  int x;
} y;
int z;
struct s t, u;
#endif
int b;
    """
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.TextBlock('int a;'),
            pre_ast.If([
                pre_ast.ConditionalBlock(
                    conditional_expression='defined(CONFIG_SOMETHING)',
                    content=[
                        pre_ast.TextBlock(
                            '\n'.join((
                                'struct s {',
                                '  int x;',
                                '} y;',
                                'int z;',
                                'struct s t, u;',
                            )),
                        ),
                    ]),
            ]),
            pre_ast.TextBlock('int b;')
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_top_level_ifdef_and_else_blocks(self):
        source = """
int a;
#ifdef CONFIG_SOMETHING
struct s {
  int x;
} y;
struct s t, u;
#else
int z;
#endif
int b;
"""
        actual = self.parser.parse(source)
        expected = pre_ast.CompositeBlock([
            pre_ast.TextBlock('int a;'),
            pre_ast.If(
                conditional_blocks=[
                    pre_ast.ConditionalBlock(
                        conditional_expression='defined(CONFIG_SOMETHING)',
                        content=[
                            pre_ast.TextBlock(
                                '\n'.join((
                                    'struct s {',
                                    '  int x;',
                                    '} y;',
                                    'struct s t, u;',
                                )),
                            ),
                        ]),
                    pre_ast.ConditionalBlock(
                        conditional_expression="1",
                        content=[
                            pre_ast.TextBlock('int z;')
                        ])
                ]
            ),
            pre_ast.TextBlock('int b;')
        ])
        self.assertASTEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
