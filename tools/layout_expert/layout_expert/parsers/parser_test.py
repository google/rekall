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

from layout_expert.c_ast import c_ast
from layout_expert.c_ast import c_ast_test
from layout_expert.lib import type_manager


class TestParser(c_ast_test.CASTTestCase):

    def setUp(self):
        self.type_manager = type_manager.TypeManager()
        self.enum_foo = c_ast.CTypeDefinition(
            name="enum Foo",
            type_definition=c_ast.CEnum(
                name="enum Foo",
                fields=[
                    c_ast.CEnumField("VAL1", c_ast.CNumber(33)),
                    c_ast.CEnumField("VAL2", c_ast.CNumber(42)),
                ]
            )
        )

    def test_parse_with_empty_program(self):
        source = ''
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([])
        self.assertASTEqual(actual, expected)

    def test_parse_with_one_field(self):
        source = """
                int v1;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField('v1', type_definition=c_ast.CTypeReference('int')),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_simple_fields(self):
        source = """
                int v1;
                type_t v2, v3;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField('v1', c_ast.CTypeReference('int')),
            c_ast.CField('v2', c_ast.CTypeReference('type_t')),
            c_ast.CField('v3', c_ast.CTypeReference('type_t')),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_pointer(self):
        source = """
                int *p;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField('p', c_ast.CPointer(c_ast.CTypeReference('int'))),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_pointer_to_pointer(self):
        source = """
                int **p;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='p',
                type_definition=c_ast.CPointer(
                    c_ast.CPointer(c_ast.CTypeReference('int')),
                ),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_volatile_variable(self):
        source = """
                volatile int x;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('int'),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_pointer_as_array(self):
        source = """
                int p[];
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(name='p',
                         type_definition=c_ast.CArray(
                             length=c_ast.CNumber(0),
                             type_definition=c_ast.CTypeReference('int')))
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_pointer_to_pointer_as_arrays(self):
        source = """
                int p[][];
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='p',
                type_definition=c_ast.CArray(
                    length=c_ast.CNumber(0),
                    type_definition=c_ast.CArray(
                        length=c_ast.CNumber(0),
                        type_definition=c_ast.CTypeReference('int')))
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_pointer_as_array_to_pointer(self):
        source = """
                int *p[];
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='p',
                type_definition=c_ast.CArray(
                    length=c_ast.CNumber(0),
                    type_definition=c_ast.CPointer(
                        c_ast.CTypeReference('int')
                    )
                )
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_pointer_to_function_field(self):
        source = """
                int (*f)();
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='f',
                type_definition=c_ast.CPointer(c_ast.CFunction()),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_pointer_to_function_with_arguments_field(self):
        source = """int (*f)(int a, int b);"""
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='f',
                type_definition=c_ast.CPointer(c_ast.CFunction()),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_pointers_and_simple_fields(self):
        source = """
                int v1;
                type_t v2, *v3, v4[], v5;
                int v6, *v7[], v8;
                """
        actual = self.type_manager.parse_c_code(source)
        type_t = c_ast.CTypeReference('type_t')
        int_ = c_ast.CTypeReference('int')
        array_t = c_ast.CArray(c_ast.CNumber(0), type_t)
        pointer_to_type_t = c_ast.CPointer(type_t)
        pointer_int = c_ast.CPointer(int_)
        array_of_pointers_int = c_ast.CArray(c_ast.CNumber(0), pointer_int)
        expected = c_ast.CProgram([
            c_ast.CField('v1', int_),
            c_ast.CField('v2', type_t),
            c_ast.CField('v3', pointer_to_type_t),
            c_ast.CField('v4', array_t),
            c_ast.CField('v5', type_t),
            c_ast.CField('v6', int_),
            c_ast.CField('v7', array_of_pointers_int),
            c_ast.CField('v8', int_),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_array_field(self):
        source = """
                int t[42];
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='t',
                type_definition=c_ast.CArray(
                    length=c_ast.CNumber(42),
                    type_definition=c_ast.CTypeReference('int'),
                ),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_array_of_arrays(self):
        source = """
                int t[42][33];
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='t',
                type_definition=c_ast.CArray(
                    length=c_ast.CNumber(42),
                    type_definition=c_ast.CArray(
                        length=c_ast.CNumber(33),
                        type_definition=c_ast.CTypeReference('int'),
                    )
                )
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_array_of_pointers(self):
        source = """
                int *t[42];
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='t',
                type_definition=c_ast.CArray(
                    length=c_ast.CNumber(42),
                    type_definition=c_ast.CPointer(c_ast.CTypeReference('int'))
                )
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_array_of_pointers_as_arrays(self):
        source = """
                int t[42][];
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='t',
                type_definition=c_ast.CArray(
                    length=c_ast.CNumber(42),
                    type_definition=c_ast.CArray(
                        c_ast.CNumber(0),
                        c_ast.CTypeReference('int')),
                ),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_array_of_pointers_of_pointers(self):
        source = """
                int **t[42];
                """
        actual = self.type_manager.parse_c_code(source)
        pointer_to_int = c_ast.CPointer(c_ast.CTypeReference('int'))
        pointer_to_pointer_to_int = c_ast.CPointer(pointer_to_int)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='t',
                type_definition=c_ast.CArray(
                    length=c_ast.CNumber(42),
                    type_definition=pointer_to_pointer_to_int,
                ),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_array_of_pointers_as_arrays_of_pointers(self):
        source = """
                int *t[42][];
                """
        array_to_ptr = c_ast.CPointer(c_ast.CTypeReference("int"))
        array_to_array_to_ptr = c_ast.CArray(
            c_ast.CNumber(0), array_to_ptr)
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='t',
                type_definition=c_ast.CArray(
                    length=c_ast.CNumber(42),
                    type_definition=array_to_array_to_ptr,
                ),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_array_of_pointers_of_pointers_as_arrays(self):
        source = """
                int t[42][][];
                """
        actual = self.type_manager.parse_c_code(source)
        array_to_int = c_ast.CArray(c_ast.CNumber(0),
                                    c_ast.CTypeReference('int'))

        array_to_array_to_int = c_ast.CArray(c_ast.CNumber(0),
                                             array_to_int)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='t',
                type_definition=c_ast.CArray(
                    length=c_ast.CNumber(42),
                    type_definition=array_to_array_to_int,
                ),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_array_length_as_expression(self):
        source = """
                typedef struct {
                    unsigned long fds_bits[1024 / (8 * sizeof(long))];
                } __kernel_fd_set;
                """
        actual = self.type_manager.parse_c_code(source)
        struct = c_ast.CTypeDefinition(
            name="struct __unknown_struct_0",
            type_definition=c_ast.CStruct([
                c_ast.CField(
                    name='fds_bits',
                    type_definition=c_ast.CArray(
                        length=c_ast.CNumber(16),
                        type_definition=c_ast.CTypeReference('unsigned long')
                    ),
                ),
            ], name="struct __unknown_struct_0")
        )
        expected = c_ast.CProgram([
            c_ast.CTypedef(
                name='__kernel_fd_set',
                type_definition=struct,
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_int_bit_field(self):
        source = """
                int v1 : 3;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='v1',
                type_definition=c_ast.CTypeReference('int'),
                bit_size=c_ast.CNumber(3),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_unsigned_bit_field(self):
        source = """
                unsigned v1 : 7;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='v1',
                type_definition=c_ast.CTypeReference('unsigned'),
                bit_size=c_ast.CNumber(7),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_unsigned_int_bit_field(self):
        source = """
                unsigned int v1 : 7;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='v1',
                type_definition=c_ast.CTypeReference('unsigned int'),
                bit_size=c_ast.CNumber(7),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_int_bit_field_with_expression(self):
        source = """
                int x:32 - 2;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('int'),
                bit_size=c_ast.CFunctionCall(
                    function_name='-',
                    arguments=[
                        c_ast.CNumber(32),
                        c_ast.CNumber(2),
                    ],
                ),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_field_with_packed_attribute_for_type(self):
        source = """
                u64 __attribute__((packed)) x;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('u64'),
                attributes=[
                    c_ast.CAttribute('packed'),
                ],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_field_with_aligned_attribute_for_type(self):
        source = """
                u64 __attribute__((aligned(8))) x;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('u64'),
                attributes=[
                    c_ast.CAttribute('aligned', c_ast.CNumber(8)),
                ],
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_field_with_packed_and_aligned_attributes_for_type(self):
        source = """
                u64 __attribute__((packed)) __attribute__((aligned(16))) x;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('u64'),
                attributes=[
                    c_ast.CAttribute('packed'),
                    c_ast.CAttribute('aligned', c_ast.CNumber(16)),
                ],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_two_fields_with_packed_and_aligned_attributes_for_type(self):
        source = """
                u64 __attribute__((packed)) __attribute__((aligned(16))) x, *y;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('u64'),
                attributes=[
                    c_ast.CAttribute('packed'),
                    c_ast.CAttribute('aligned', c_ast.CNumber(16)),
                ],
            ),
            c_ast.CField(
                name='y',
                type_definition=c_ast.CPointer(c_ast.CTypeReference('u64')),
                attributes=[
                    c_ast.CAttribute('packed'),
                    c_ast.CAttribute('aligned', c_ast.CNumber(16)),
                ],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_one_field_with_packed_attribute(self):
        source = """
                unsigned x __attribute__((packed));
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('unsigned'),
                attributes=[
                    c_ast.CAttribute('packed'),
                ],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_one_field_with_aligned_attribute(self):
        source = """
                unsigned x __attribute__((aligned(32)));
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('unsigned'),
                attributes=[
                    c_ast.CAttribute('aligned', c_ast.CNumber(32)),
                ],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_one_field_with_double_underscored_aligned_attribute(self):
        source = """
                unsigned x __attribute__((__aligned__(32)));
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('unsigned'),
                attributes=[
                    c_ast.CAttribute('__aligned__', c_ast.CNumber(32)),
                ],
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_one_field_aligned_attribute_with_expression_inside(self):
        source = """
                unsigned x __attribute__((aligned(1 << SHIFT)));
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('unsigned'),
                attributes=[
                    c_ast.CAttribute(
                        'aligned',
                        c_ast.CFunctionCall(
                            function_name='<<',
                            arguments=[
                                c_ast.CNumber(1),
                                c_ast.CVariable('SHIFT'),
                            ],
                        ),
                    ),
                ],
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_one_field_with_aligned_and_packed_attributes(self):
        source = """
                u16 x __attribute__((aligned(32))) __attribute__((packed));
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('u16'),
                attributes=[
                    c_ast.CAttribute('aligned', c_ast.CNumber(32)),
                    c_ast.CAttribute('packed'),
                ],
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_one_field_with_two_attributes_in_one_clause(self):
        source = """
                u16 x __attribute__ ((packed, aligned (64)));
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('u16'),
                attributes=[
                    c_ast.CAttribute('packed'),
                    c_ast.CAttribute('aligned', c_ast.CNumber(64)),
                ],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_array_of_pointers_as_arrays_of_pointers_attributes(self):
        source = """
                u16 *x[8][] __attribute__((aligned(32))) __attribute__((packed));
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CArray(
                    length=c_ast.CNumber(8),
                    type_definition=c_ast.CArray(
                        length=c_ast.CNumber(0),
                        type_definition=c_ast.CPointer(
                            c_ast.CTypeReference('u16'),
                        ),
                    )
                ),
                attributes=[
                    c_ast.CAttribute('aligned', c_ast.CNumber(32)),
                    c_ast.CAttribute('packed'),
                ],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_two_fields_with_attributes_for_first(self):
        source = """
                u64 *x __attribute__((packed)) __attribute__((aligned(8))), y;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CPointer(c_ast.CTypeReference('u64')),
                attributes=[
                    c_ast.CAttribute('packed'),
                    c_ast.CAttribute('aligned', c_ast.CNumber(8)),
                ],
            ),
            c_ast.CField(
                name='y',
                type_definition=c_ast.CTypeReference('u64')
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_two_fields_with_attributes_for_second(self):
        source = """
                u64 *x, y __attribute__((aligned(8))) __attribute__((packed));
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CPointer(c_ast.CTypeReference('u64')),
            ),
            c_ast.CField(
                name='y',
                type_definition=c_ast.CTypeReference('u64'),
                attributes=[
                    c_ast.CAttribute('aligned', c_ast.CNumber(8)),
                    c_ast.CAttribute('packed'),
                ],
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_two_fields_with_different_attributes(self):
        source = """
                u64 x __attribute__((packed)), *y __attribute__((aligned(16)));
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('u64'),
                attributes=[
                    c_ast.CAttribute('packed'),
                ],
            ),
            c_ast.CField(
                name='y',
                type_definition=c_ast.CPointer(c_ast.CTypeReference('u64')),
                attributes=[
                    c_ast.CAttribute('aligned', c_ast.CNumber(16)),
                ],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_attribute_for_type_and_for_the_first_field_of_two(self):
        source = """
                u64    __attribute__((aligned(16))) *x __attribute__((packed)), y;
                """
        actual = self.type_manager.parse_c_code(source)
        u64 = c_ast.CTypeReference('u64')
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CPointer(u64),
                attributes=[
                    c_ast.CAttribute('aligned', c_ast.CNumber(16)),
                    c_ast.CAttribute('packed'),
                ],
            ),
            c_ast.CField(
                name='y',
                type_definition=u64,
                attributes=[
                    c_ast.CAttribute('aligned', c_ast.CNumber(16)),
                ],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_attribute_for_type_and_for_the_second_field_of_two(self):
        source = """
                u64    __attribute__((packed)) *x, y __attribute__((aligned(8)));
                """
        actual = self.type_manager.parse_c_code(source)
        u64 = c_ast.CTypeReference('u64')
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CPointer(u64),
                attributes=[
                    c_ast.CAttribute('packed'),
                ],
            ),
            c_ast.CField(
                name='y',
                type_definition=u64,
                attributes=[
                    c_ast.CAttribute('packed'),
                    c_ast.CAttribute('aligned', c_ast.CNumber(8)),
                ],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_field_with_section_attribute(self):
        source = """
                struct s __attribute__ ((__section__(".init.data"))) s1;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='s1',
                type_definition=c_ast.CTypeReference('struct s'),
                attributes=[
                    c_ast.CAttribute(
                        '__section__', c_ast.CLiteral('".init.data"')),
                ],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_signed_char_field(self):
        source = """
                __signed__ char x;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('__signed__ char'),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_unsigned_short_field(self):
        source = """
                unsigned short x;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('unsigned short'),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_unsigned_int_field(self):
        source = """
                unsigned int x;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('unsigned int'),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_long_long_field(self):
        source = """
                long long x;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('long long'),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_signed_long_long_field(self):
        source = """
                __signed__ long long x;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('__signed__ long long'),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_unsigned_long_long_field(self):
        source = """
                unsigned long long x;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('unsigned long long'),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_unsigned_short_int(self):
        source = """
                unsigned short int x;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('unsigned short int'),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_signed_long_long_int(self):
        source = """
                signed long long int x;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('signed long long int'),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_top_level_enum(self):
        source = """
                enum Foo {
                    VAL1 = 33,
                    VAL2 = 42,
                };
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            self.enum_foo
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_top_level_enum_with_one_attribute(self):
        source = """
                enum Foo {
                    VAL1 = 33,
                    VAL2 = 42,
                } __attribute__((packed));
                """
        actual = self.type_manager.parse_c_code(source)
        self.enum_foo.type_definition.attributes.append(
            c_ast.CAttribute('packed'))

        expected = c_ast.CProgram([
            self.enum_foo,
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_top_level_enum_with_two_attributes(self):
        source = """
                enum Foo {
                    VAL1 = 33,
                    VAL2 = 42,
                } __attribute__((packed)) __attribute__((aligned(2)));
                """
        actual = self.type_manager.parse_c_code(source)
        self.enum_foo.type_definition.attributes.extend([
            c_ast.CAttribute('packed'),
            c_ast.CAttribute('aligned', c_ast.CNumber(2)),
        ])

        expected = c_ast.CProgram([
            self.enum_foo,
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_anonymous_top_level_enum(self):
        source = """
                enum {
                    VAL1 = 33,
                    VAL2 = 42,
                };
                """
        actual = self.type_manager.parse_c_code(source)
        self.enum_foo.name = "enum __unknown_enum_1"
        self.enum_foo.type_definition.name = self.enum_foo.name

        expected = c_ast.CProgram([
            self.enum_foo,
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_anonymous_top_level_enum_with_two_attributes(self):
        source = """
                enum {
                    VAL1 = 33,
                    VAL2 = 42,
                } __attribute__((aligned(4))) __attribute__((packed));
                """
        actual = self.type_manager.parse_c_code(source)
        self.enum_foo.name = "enum __unknown_enum_1"
        self.enum_foo.type_definition.name = self.enum_foo.name

        self.enum_foo.type_definition.attributes.extend([
            c_ast.CAttribute('aligned', c_ast.CNumber(4)),
            c_ast.CAttribute('packed'),
        ])
        expected = c_ast.CProgram([
            self.enum_foo,
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_top_level_enum_and_variables(self):
        source = """
                enum Foo {
                    VAL1 = 33,
                    VAL2 = 42,
                } v1, v2, v3;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField('v1', type_definition=self.enum_foo),
            c_ast.CField('v2', type_definition=self.enum_foo),
            c_ast.CField('v3', type_definition=self.enum_foo),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_top_level_enum_variables_with_attributes(self):
        source = """
                enum Foo {
                    VAL1 = 33,
                    VAL2 = 42,
                } __attribute__((aligned(4))) v1, v2, v3 __attribute__((packed));
                """
        actual = self.type_manager.parse_c_code(source)
        self.enum_foo.type_definition.attributes.append(
            c_ast.CAttribute('aligned', c_ast.CNumber(4)),
        )
        expected = c_ast.CProgram([
            c_ast.CField('v1', self.enum_foo),
            c_ast.CField('v2', self.enum_foo),
            c_ast.CField(
                name='v3',
                type_definition=self.enum_foo,
                attributes=[
                    c_ast.CAttribute('packed'),
                ],
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_anonymous_top_level_enum_and_variables(self):
        source = """
                enum {
                    VAL1 = 33,
                    VAL2 = 42,
                } v42, v33;
                """
        actual = self.type_manager.parse_c_code(source)
        self.enum_foo.name = "enum __unknown_enum_0"
        self.enum_foo.type_definition.name = self.enum_foo.name

        expected = c_ast.CProgram([
            c_ast.CField('v42', self.enum_foo),
            c_ast.CField('v33', self.enum_foo),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_anonymous_top_level_enum_variables_with_attributes(self):
        source = """
                enum {
                    VAL1 = 33,
                    VAL2 = 42,
                } __attribute__((aligned(4))) v1, v2, v3 __attribute__((packed));
                """
        actual = self.type_manager.parse_c_code(source)

        self.enum_foo.name = "enum __unknown_enum_0"
        self.enum_foo.type_definition.name = self.enum_foo.name

        self.enum_foo.type_definition.attributes.append(
            c_ast.CAttribute('aligned', c_ast.CNumber(4)),
        )
        expected = c_ast.CProgram([
            c_ast.CField('v1', self.enum_foo),
            c_ast.CField('v2', self.enum_foo),
            c_ast.CField(
                name='v3',
                type_definition=self.enum_foo,
                attributes=[
                    c_ast.CAttribute('packed'),
                ],
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_top_level_enum_and_array(self):
        source = """
                enum Foo {
                    VAL1 = 33,
                    VAL2 = 42,
                } v1, v2[7], v3;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField('v1', type_definition=self.enum_foo),
            c_ast.CField('v2',
                         type_definition=c_ast.CArray(
                             length=c_ast.CNumber(7),
                             type_definition=self.enum_foo
                         )),
            c_ast.CField('v3', type_definition=self.enum_foo),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_top_level_enum_variables_array_and_attributes(self):
        source = """
                enum Foo {
                    VAL1 = 33,
                    VAL2 = 42,
                } __attribute__((aligned(4))) v1, v2[3] __attribute__((packed)), v3;
                """
        actual = self.type_manager.parse_c_code(source)
        self.enum_foo.type_definition.attributes.append(
            c_ast.CAttribute('aligned', c_ast.CNumber(4)),
        )

        expected = c_ast.CProgram([
            c_ast.CField('v1', self.enum_foo),
            c_ast.CField(
                name='v2',
                type_definition=c_ast.CArray(
                    length=c_ast.CNumber(3),
                    type_definition=self.enum_foo,
                ),
                attributes=[
                    c_ast.CAttribute('packed'),
                ],
            ),
            c_ast.CField('v3', self.enum_foo),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_top_level_enum_and_array_of_pointers(self):
        source = """
                enum Foo {
                    VAL1 = 33,
                    VAL2 = 42,
                } v1, *v2[8], v3;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField('v1', type_definition=self.enum_foo),
            c_ast.CField('v2', type_definition=c_ast.CArray(
                length=c_ast.CNumber(8),
                type_definition=c_ast.CPointer(
                    type_definition=self.enum_foo
                )
            )),
            c_ast.CField('v3', type_definition=self.enum_foo),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_top_level_enum_array_of_pointers_and_attributes(self):
        source = """
                enum Foo {
                    VAL1 = 33,
                    VAL2 = 42,
                } __attribute__((aligned(4))) v1, *v2[3] __attribute__((packed)), v3;
                """
        actual = self.type_manager.parse_c_code(source)
        self.enum_foo.type_definition.attributes.append(
            c_ast.CAttribute('aligned', c_ast.CNumber(4)),
        )
        expected = c_ast.CProgram([
            c_ast.CField('v1', self.enum_foo),
            c_ast.CField(
                name='v2',
                type_definition=c_ast.CArray(
                    length=c_ast.CNumber(3),
                    type_definition=c_ast.CPointer(self.enum_foo),
                ),
                attributes=[
                    c_ast.CAttribute('packed'),
                ],
            ),
            c_ast.CField('v3', self.enum_foo),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_top_level_enum_and_array_of_pointers_as_array(self):
        source = """
                enum Foo {
                    VAL1 = 33,
                    VAL2 = 42,
                } v1, v2[9][], v3;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField('v1', type_definition=self.enum_foo),
            c_ast.CField('v2', type_definition=c_ast.CArray(
                length=c_ast.CNumber(9),
                type_definition=c_ast.CArray(
                    length=c_ast.CNumber(0),
                    type_definition=self.enum_foo
                )
            )),
            c_ast.CField('v3', type_definition=self.enum_foo),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_top_level_enum_array_of_array_pointers_and_attributes(self):
        source = """
                enum Foo {
                    VAL1 = 33,
                    VAL2 = 42,
                } __attribute__((aligned(4))) v1, v2[8][] __attribute__((packed)), v3;
                """
        actual = self.type_manager.parse_c_code(source)
        self.enum_foo.type_definition.attributes.append(
            c_ast.CAttribute('aligned', c_ast.CNumber(4)),
        )
        expected = c_ast.CProgram([
            c_ast.CField('v1', self.enum_foo),
            c_ast.CField(name='v2',
                         type_definition=c_ast.CArray(
                             length=c_ast.CNumber(8),
                             type_definition=c_ast.CArray(
                                 c_ast.CNumber(0),
                                 self.enum_foo),
                         ),
                         attributes=[
                             c_ast.CAttribute('packed'),
                         ]),
            c_ast.CField('v3', self.enum_foo),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_empty_top_level_struct(self):
        source = """
            struct s {
            };
            """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='struct s',
                type_definition=c_ast.CStruct(
                    [], name="struct s"),
                following_fields=[],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_attributed_empty_top_level_struct(self):
        source = """
            struct s {
            } __attribute__((aligned(4)));
            """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='struct s',
                type_definition=c_ast.CStruct(
                    name="struct s",
                    content=[],
                    attributes=[
                        c_ast.CAttribute('aligned', c_ast.CNumber(4))
                    ],
                ),
                following_fields=[],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_top_level_struct_variable(self):
        source = """
            struct s1 {
                int x;
                type_t y;
            };
            """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='struct s1',
                type_definition=c_ast.CStruct([
                    c_ast.CField('x', c_ast.CTypeReference('int')),
                    c_ast.CField('y', c_ast.CTypeReference('type_t')),
                ], name="struct s1"),
                following_fields=[],
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_top_level_struct(self):
        source = """
            struct s1 {
                int x;
                type_t y;
            };
            """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='struct s1',
                type_definition=c_ast.CStruct([
                    c_ast.CField('x', c_ast.CTypeReference('int')),
                    c_ast.CField('y', c_ast.CTypeReference('type_t')),
                ], name="struct s1"),
                following_fields=[],
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_top_level_struct_with_attributes(self):
        source = """
            struct s1 {
                int x;
                type_t y;
            } __attribute__((packed)) __attribute__((aligned(2)));
            """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='struct s1',
                type_definition=c_ast.CStruct(
                    content=[
                        c_ast.CField('x', c_ast.CTypeReference('int')),
                        c_ast.CField('y', c_ast.CTypeReference('type_t')),
                    ],
                    attributes=[
                        c_ast.CAttribute('packed'),
                        c_ast.CAttribute('aligned', c_ast.CNumber(2)),
                    ],
                    name="struct s1"
                ),
                following_fields=[],
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_nested_struct(self):
        source = """
            struct s1 {
                int x;
                struct s2 {
                    float *y;
                };
            };
            """
        actual = self.type_manager.parse_c_code(source)
        struct_s2 = c_ast.CStruct([
            c_ast.CField(
                name='y',
                type_definition=c_ast.CPointer(c_ast.CTypeReference('float')),
            )
        ], name="struct s2")
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='struct s1',
                type_definition=c_ast.CStruct([
                    c_ast.CField('x', c_ast.CTypeReference('int')),
                    c_ast.CTypeDefinition(
                        name='struct s2',
                        type_definition=struct_s2,
                        following_fields=[]),
                ], name="struct s1"),
                following_fields=[],
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_nested_struct_and_attributes(self):
        source = """
            struct s1 {
                int __attribute__((aligned(16))) x;
                struct s2 {
                    float *y __attribute__((packed));
                } __attribute__((packed));
            };
            """
        actual = self.type_manager.parse_c_code(source)
        struct_s2 = c_ast.CStruct(
            name="struct s2",
            content=[
                c_ast.CField(
                    name='y',
                    type_definition=c_ast.CPointer(
                        c_ast.CTypeReference('float'),
                    ),
                    attributes=[
                        c_ast.CAttribute('packed'),
                    ],
                ),
            ],
            attributes=[
                c_ast.CAttribute('packed'),
            ],
        )
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='struct s1',
                type_definition=c_ast.CStruct([
                    c_ast.CField(
                        name='x',
                        type_definition=c_ast.CTypeReference('int'),
                        attributes=[
                            c_ast.CAttribute('aligned', c_ast.CNumber(16)),
                        ],
                    ),
                    c_ast.CTypeDefinition(
                        name='struct s2',
                        type_definition=struct_s2,
                        following_fields=[]),
                ], name="struct s1"),
                following_fields=[],
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_nested_struct_with_fields(self):
        source = """
            struct s1 {
                int x;
                struct s2 {
                    float *y;
                } z;
            };
            """
        actual = self.type_manager.parse_c_code(source)
        struct_s2 = c_ast.CTypeDefinition(
            name="struct s2",
            type_definition=c_ast.CStruct([
                c_ast.CField(
                    name='y',
                    type_definition=c_ast.CPointer(
                        c_ast.CTypeReference('float')),
                )
            ], name="struct s2")
        )
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='struct s1',
                type_definition=c_ast.CStruct([
                    c_ast.CField('x', c_ast.CTypeReference('int')),
                    c_ast.CField(
                        name='z',
                        type_definition=struct_s2,
                    )
                ], name="struct s1"),
                following_fields=[],
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_nested_struct_with_following_fields_and_attributes(self):
        source = """
            struct s1 {
                int __attribute__((aligned(16))) x;
                struct s2 {
                    float *y __attribute__((packed));
                } __attribute__((packed)) z, *v, u[42][] __attribute__((aligned(8)));
            };
            """
        actual = self.type_manager.parse_c_code(source)
        struct_s2 = c_ast.CTypeDefinition(
            name='struct s2',
            type_definition=c_ast.CStruct(
                name="struct s2",
                content=[
                    c_ast.CField(
                        name='y',
                        type_definition=c_ast.CPointer(
                            c_ast.CTypeReference('float'),
                        ),
                        attributes=[
                            c_ast.CAttribute('packed'),
                        ],
                    ),
                ],
                attributes=[
                    c_ast.CAttribute('packed'),
                ],
            )
        )
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='struct s1',
                type_definition=c_ast.CStruct([
                    c_ast.CField(
                        name='x',
                        type_definition=c_ast.CTypeReference('int'),
                        attributes=[
                            c_ast.CAttribute('aligned', c_ast.CNumber(16)),
                        ],
                    ),
                    c_ast.CField(name="z", type_definition=struct_s2),
                    c_ast.CField('v', c_ast.CPointer(struct_s2)),
                    c_ast.CField(
                        name='u',
                        type_definition=c_ast.CArray(
                            length=c_ast.CNumber(42),
                            type_definition=c_ast.CArray(
                                length=c_ast.CNumber(0),
                                type_definition=struct_s2)),
                        attributes=[
                            c_ast.CAttribute(
                                'aligned',
                                c_ast.CNumber(8),
                            ),
                        ],
                    ),
                ], name="struct s1"),
                following_fields=[],
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_simple_typedef_with_attribute_before_type(self):
        source = """
        typedef __attribute__((packed)) struct s struct_s_packed_t;
        """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypedef(
                name='struct_s_packed_t',
                type_definition=c_ast.CTypeReference('struct s'),
                attributes=[
                    c_ast.CAttribute('packed'),
                ],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_simple_typedef_with_attribute_after_type(self):
        source = """
        typedef struct s __attribute__((packed)) struct_s_packed_t;
        """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypedef(
                name='struct_s_packed_t',
                type_definition=c_ast.CTypeReference('struct s'),
                attributes=[
                    c_ast.CAttribute('packed'),
                ],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_simple_typedef_with_attribute_after_name(self):
        source = """
                typedef struct s struct_s_packed_t __attribute__((packed));
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypedef(
                name='struct_s_packed_t',
                type_definition=c_ast.CTypeReference('struct s'),
                attributes=[
                    c_ast.CAttribute('packed'),
                ],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_simple_typedef_with_attribute_in_all_three_places(self):
        source = """
                typedef __attribute__((packed)) struct s __attribute__((packed))
                        struct_s_packed_t    __attribute__((packed));
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypedef(
                name='struct_s_packed_t',
                type_definition=c_ast.CTypeReference('struct s'),
                attributes=[
                    c_ast.CAttribute('packed'),
                    c_ast.CAttribute('packed'),
                    c_ast.CAttribute('packed'),
                ],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_simple_typedef_with_packed_and_aligned_2_attributes(self):
        source = """
            typedef unsigned int unsigned_int_t_packed_aligned_2
                __attribute__((packed)) __attribute__((aligned(2)));
            """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypedef(
                name='unsigned_int_t_packed_aligned_2',
                type_definition=c_ast.CTypeReference('unsigned int'),
                attributes=[
                    c_ast.CAttribute('packed'),
                    c_ast.CAttribute('aligned', c_ast.CNumber(2)),
                ]
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_simple_typedef_with_aligned_2_and_packed_attributes(self):
        source = """
            typedef unsigned int unsigned_int_t_aligned_2_packed
                __attribute__((aligned(2))) __attribute__((packed));
            """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypedef(
                name='unsigned_int_t_aligned_2_packed',
                type_definition=c_ast.CTypeReference('unsigned int'),
                attributes=[
                    c_ast.CAttribute('aligned', c_ast.CNumber(2)),
                    c_ast.CAttribute('packed'),
                ]
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_struct_with_pointer_to_function_field(self):
        source = """
                struct s {
                    unsigned (*p)(u8 x, u16 y, void *q,
                            unsigned long z, unsigned u);
                };
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='struct s',
                type_definition=c_ast.CStruct([
                    c_ast.CField(
                        name='p',
                        type_definition=c_ast.CPointer(c_ast.CFunction()),
                    ),
                ], name="struct s"),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_struct_with_volatile_field(self):
        source = """
                struct s {
                    volatile int x;
                };
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='struct s',
                type_definition=c_ast.CStruct([
                    c_ast.CField(
                        name='x',
                        type_definition=c_ast.CTypeReference('int'),
                    ),
                ], name="struct s"),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_empty_union(self):
        source = """
                union u {};
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='union u',
                type_definition=c_ast.CUnion([], name='union u'),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_empty_anonymous_union(self):
        source = """
                union {};
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name="union __unknown_union_1",
                type_definition=c_ast.CUnion([],
                                             name='union __unknown_union_1'),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_union_with_fields(self):
        source = """
                union u {
                        int a, b;
                        union u *p;
                };
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='union u',
                type_definition=c_ast.CUnion([
                    c_ast.CField(
                        name='a',
                        type_definition=c_ast.CTypeReference('int'),
                    ),
                    c_ast.CField(
                        name='b',
                        type_definition=c_ast.CTypeReference('int'),
                    ),
                    c_ast.CField(
                        name='p',
                        type_definition=c_ast.CPointer(
                            type_definition=c_ast.CTypeReference('union u'),
                        ),
                    ),
                ], name='union u'),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_anonymous_union_with_fields(self):
        source = """
                union {
                    struct s s1;
                    struct s s2;
                };
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name="union __unknown_union_1",
                type_definition=c_ast.CUnion([
                    c_ast.CField(
                        name='s1',
                        type_definition=c_ast.CTypeReference('struct s'),
                    ),
                    c_ast.CField(
                        name='s2',
                        type_definition=c_ast.CTypeReference('struct s'),
                    ),
                ], name="union __unknown_union_1"),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_union_with_following_fields(self):
        source = """
                union u {
                        int a, b;
                        union u *p;
                } u1, u2;
                """
        actual = self.type_manager.parse_c_code(source)
        union_u = c_ast.CUnion([
            c_ast.CField(
                name='a',
                type_definition=c_ast.CTypeReference('int'),
            ),
            c_ast.CField(
                name='b',
                type_definition=c_ast.CTypeReference('int'),
            ),
            c_ast.CField(
                name='p',
                type_definition=c_ast.CPointer(
                    type_definition=c_ast.CTypeReference('union u'),
                ),
            ),
        ], name="union u")
        expected = c_ast.CProgram([
            c_ast.CField(
                name="u1",
                type_definition=c_ast.CTypeDefinition(
                    name='union u',
                    type_definition=union_u,
                ),
            ),
            c_ast.CField(
                name="u2",
                type_definition=c_ast.CTypeDefinition(
                    name='union u',
                    type_definition=union_u,
                ),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_anonymous_union_with_following_fields(self):
        source = """
                union {
                    struct s s1;
                    struct s s2;
                } u1, u2;
                """
        actual = self.type_manager.parse_c_code(source)
        union = c_ast.CTypeDefinition(
            name='union __unknown_union_0',
            type_definition=c_ast.CUnion([
                c_ast.CField(
                    name='s1',
                    type_definition=c_ast.CTypeReference('struct s'),
                ),
                c_ast.CField(
                    name='s2',
                    type_definition=c_ast.CTypeReference('struct s'),
                ),
            ], name='union __unknown_union_0')
        )
        expected = c_ast.CProgram([
            c_ast.CField(
                name="u1",
                type_definition=union
            ),
            c_ast.CField(
                name='u2',
                type_definition=union,
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_nested_union(self):
        source = """
            union u1 {
                int x;
                union u2 {
                    float *y;
                };
            };
            """
        actual = self.type_manager.parse_c_code(source)
        union_u2 = c_ast.CUnion([
            c_ast.CField(
                name='y',
                type_definition=c_ast.CPointer(c_ast.CTypeReference('float')),
            )
        ], name="union u2")
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='union u1',
                type_definition=c_ast.CUnion([
                    c_ast.CField('x', c_ast.CTypeReference('int')),
                    c_ast.CTypeDefinition(
                        name='union u2',
                        type_definition=union_u2,
                        following_fields=[]),
                ], name="union u1"),
                following_fields=[],
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_nested_union_and_attributes(self):
        source = """
            union u1 {
                int __attribute__((aligned(16))) x;
                union u2 {
                    float *y __attribute__((packed));
                };
            } __attribute__((packed)) u, v __attribute__((aligned(4)));
            """
        actual = self.type_manager.parse_c_code(source)
        union_u2 = c_ast.CUnion([
            c_ast.CField(
                name='y',
                type_definition=c_ast.CPointer(c_ast.CTypeReference('float')),
                attributes=[
                    c_ast.CAttribute('packed'),
                ],
            )
        ], name="union u2")
        union_u1 = c_ast.CUnion(
            content=[
                c_ast.CField(
                    name='x',
                    type_definition=c_ast.CTypeReference('int'),
                    attributes=[
                        c_ast.CAttribute('aligned', c_ast.CNumber(16)),
                    ],
                ),
                c_ast.CTypeDefinition(
                    name='union u2',
                    type_definition=union_u2,
                    following_fields=[],
                ),
            ],
            attributes=[
                c_ast.CAttribute('packed'),
            ],
            name="union u1"
        )
        expected = c_ast.CProgram([
            c_ast.CField(
                name="u",
                type_definition=c_ast.CTypeDefinition(
                    name='union u1',
                    type_definition=union_u1,
                )
            ),
            c_ast.CField(
                name="v",
                type_definition=c_ast.CTypeDefinition(
                    name='union u1',
                    type_definition=union_u1,
                ),
                attributes=[
                    c_ast.CAttribute('aligned', c_ast.CNumber(4)),
                ],
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_nested_union_with_fields(self):
        source = """
            union u1 {
                int x;
                union u2 {
                    float *y;
                } z;
            };
            """
        actual = self.type_manager.parse_c_code(source)
        union_u2 = c_ast.CUnion(
            [
                c_ast.CField(
                    name='y',
                    type_definition=c_ast.CPointer(
                        c_ast.CTypeReference('float')),
                )
            ],
            name="union u2",
        )
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='union u1',
                type_definition=c_ast.CUnion(
                    [
                        c_ast.CField('x', c_ast.CTypeReference('int')),
                        c_ast.CField(
                            'z',
                            c_ast.CTypeDefinition(
                                name='union u2',
                                type_definition=union_u2,
                            )
                        )
                    ],
                    name="union u1",
                ),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_union_with_pointer_to_function_field(self):
        source = """
                union u {
                    unsigned (*p)(u8 x, u16 y, void *q,
                            unsigned long z, unsigned u);
                };
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='union u',
                type_definition=c_ast.CUnion([
                    c_ast.CField(
                        name='p',
                        type_definition=c_ast.CPointer(c_ast.CFunction()),
                    ),
                ], name="union u"),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_union_with_volatile_field(self):
        source = """
                union u {
                    volatile int x;
                };
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='union u',
                type_definition=c_ast.CUnion([
                    c_ast.CField(
                        name='x',
                        type_definition=c_ast.CTypeReference('int'),
                    ),
                ], name="union u"),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_union_with_typeof_field(self):
        source = """
                union u {
                    __typeof__(struct s) s1;
                };
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='union u',
                type_definition=c_ast.CUnion([
                    c_ast.CField(
                        name='s1',
                        type_definition=c_ast.CTypeReference(
                            '__typeof__(struct s)',
                        )
                    ),
                ], name="union u"),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_union_with_pointer_to_typeof_field(self):
        source = """
                union u {
                    __typeof__(struct s) *s1;
                };
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='union u',
                type_definition=c_ast.CUnion([
                    c_ast.CField(
                        name='s1',
                        type_definition=c_ast.CPointer(
                            type_definition=c_ast.CTypeReference(
                                name='__typeof__(struct s)',
                            ),
                        ),
                    ),
                ], name="union u"),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_structs_and_unions(self):
        source = """
                struct ftrace_branch_data {
                 char *func;
                 char *file;
                 unsigned line;
                 union {
                    struct {
                     unsigned long correct;
                     unsigned long incorrect;
                    };
                    struct {
                     unsigned long miss;
                     unsigned long hit;
                    };
                    unsigned long miss_hit[2];
                 };
                };
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='struct ftrace_branch_data',
                type_definition=c_ast.CStruct([
                    c_ast.CField(
                        name='func',
                        type_definition=c_ast.CPointer(
                            type_definition=c_ast.CTypeReference('char'),
                        ),
                    ),
                    c_ast.CField(
                        name='file',
                        type_definition=c_ast.CPointer(
                            type_definition=c_ast.CTypeReference('char'),
                        ),
                    ),
                    c_ast.CField(
                        name='line',
                        type_definition=c_ast.CTypeReference('unsigned'),
                    ),
                    c_ast.CTypeDefinition(
                        name="union __unknown_union_9",
                        type_definition=c_ast.CUnion([
                            c_ast.CTypeDefinition(
                                name="struct __unknown_struct_6",
                                type_definition=c_ast.CStruct([
                                    c_ast.CField(
                                        name='correct',
                                        type_definition=c_ast.CTypeReference(
                                            'unsigned long',
                                        )
                                    ),
                                    c_ast.CField(
                                        name='incorrect',
                                        type_definition=c_ast.CTypeReference(
                                            'unsigned long',
                                        )
                                    ),
                                ], name="struct __unknown_struct_6"),
                            ),
                            c_ast.CTypeDefinition(
                                name="struct __unknown_struct_8",
                                type_definition=c_ast.CStruct([
                                    c_ast.CField(
                                        name='miss',
                                        type_definition=c_ast.CTypeReference(
                                            'unsigned long',
                                        )
                                    ),
                                    c_ast.CField(
                                        name='hit',
                                        type_definition=c_ast.CTypeReference(
                                            'unsigned long',
                                        )
                                    ),
                                ], name="struct __unknown_struct_8"),
                            ),
                            c_ast.CField(
                                name='miss_hit',
                                type_definition=c_ast.CArray(
                                    length=c_ast.CNumber(2),
                                    type_definition=c_ast.CTypeReference(
                                        'unsigned long',
                                    ),
                                ),
                            ),
                        ], name="union __unknown_union_9"),
                    ),
                ], name="struct ftrace_branch_data"),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_simple_typedef(self):
        source = """
                typedef int t;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypedef(
                name='t',
                type_definition=c_ast.CTypeReference('int'),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_typedef_to_pointer_to_struct(self):
        source = """
                typedef struct s *p;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypedef(
                name='p',
                type_definition=c_ast.CPointer(c_ast.CTypeReference(
                    'struct s')),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_typedef_to_struct_array(self):
        source = """
                typedef struct s t[7];
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypedef(
                name='t',
                type_definition=c_ast.CArray(
                    length=c_ast.CNumber(7),
                    type_definition=c_ast.CTypeReference('struct s'),
                ),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_typedef_to_pointer_to_function(self):
        source = """
                typedef void (*fun_t)(int);
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypedef(
                name='fun_t',
                type_definition=c_ast.CPointer(c_ast.CFunction()),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_typedef_to_function(self):
        source = """
                typedef void *fun_t(int);
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypedef(
                name='fun_t',
                type_definition=c_ast.CFunction(),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_typedef_to_function_with_parenthesis(self):
        source = """
                typedef void (fun_t)(int);
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypedef(
                name='fun_t',
                type_definition=c_ast.CFunction(),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_with_typedef_with_struct_definition(self):
        source = """
                typedef struct s {
                    int x;
                    struct s *p;
                } s_t;
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypedef(
                name='s_t',
                type_definition=c_ast.CTypeDefinition(
                    name='struct s',
                    type_definition=c_ast.CStruct([
                        c_ast.CField('x', c_ast.CTypeReference('int')),
                        c_ast.CField(
                            name='p',
                            type_definition=c_ast.CPointer(
                                c_ast.CTypeReference('struct s'),
                            ),
                        ),
                    ], name="struct s")
                )
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_typedef_with_union_definition_and_pointer(self):
        source = """
        typedef union u {} *t;
        """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypedef(
                name='t',
                type_definition=c_ast.CPointer(
                    type_definition=c_ast.CTypeDefinition(
                        name='union u',
                        type_definition=c_ast.CUnion(
                            [], name="union u"),
                    )
                )
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_enum_definition(self):
        source = """
            enum e {
                OPTION_ONE = 2,
                OPTION_TWO = 2 + 1
            };
            """
        parsed_c_ast = self.type_manager.parse_c_code(source)
        actual = parsed_c_ast.content[0].type_definition
        expected = c_ast.CEnum(
            fields=[
                c_ast.CEnumField(
                    name="OPTION_ONE",
                    value=c_ast.CNumber(2)),
                c_ast.CEnumField(
                    name="OPTION_TWO",
                    value=c_ast.CFunctionCall(
                        "+", [c_ast.CNumber(2), c_ast.CNumber(1)]))
            ], name="enum e"
        )
        self.assertASTEqual(actual, expected)

    def test_parse_enum_definition_with_expression(self):
        source = """
            enum e {
                OPTION_ONE = 2 + 5,
            };
            """
        parsed_c_ast = self.type_manager.parse_c_code(source)
        actual = parsed_c_ast.content[0].type_definition
        expected = c_ast.CEnum(
            fields=[
                c_ast.CEnumField(
                    name="OPTION_ONE",
                    value=c_ast.CFunctionCall(
                        "+",
                        [c_ast.CNumber(2), c_ast.CNumber(5)]
                    )
                )], name="enum e"
        )
        self.assertASTEqual(actual, expected)

    def test_parse_struct_with_superfluous_semicolon_after_a_field(self):
        source = """
                struct s {
                    int x;;
                };
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='struct s',
                type_definition=c_ast.CStruct([
                    c_ast.CField(
                        name='x',
                        type_definition=c_ast.CTypeReference('int'),
                    ),
                ], name="struct s"),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_union_with_only_semicolon_inside(self):
        source = """
                union {;};
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name="union __unknown_union_1",
                type_definition=c_ast.CUnion(
                    [],
                    name="union __unknown_union_1"),
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_union_with_superfluous_semicolon_after_a_field(self):
        source = """
                union u {
                    int x;;
                };
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypeDefinition(
                name='union u',
                type_definition=c_ast.CUnion([
                    c_ast.CField(
                        name='x',
                        type_definition=c_ast.CTypeReference('int'),
                    ),
                ], name='union u'),
            ),
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_attributed_with_format_typedef_to_pointer_to_function(self):
        source = """
                typedef __attribute__((format(printf, 1, 0)))
                    int (*printk_func_t)(char *fmt, va_list args);
                """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CTypedef(
                name='printk_func_t',
                type_definition=c_ast.CPointer(c_ast.CFunction()),
                attributes=[c_ast.CAttribute('format')],
            )
        ])
        self.assertASTEqual(actual, expected)

    def test_parse_attribute_with_expression(self):
        source = """
        spinlock_t _xmit_lock __attribute__((__aligned__(1 << 6))) ;
        """
        actual = self.type_manager.parse_c_code(source)
        expected = c_ast.CProgram([
            c_ast.CField(
                name='_xmit_lock',
                type_definition=c_ast.CTypeReference("spinlock_t"),
                attributes=[c_ast.CAttribute(
                    '__aligned__', parameters=[
                        c_ast.CFunctionCall(
                            function_name='<<',
                            arguments=[
                                c_ast.CNumber(1),
                                c_ast.CNumber(6),
                            ],
                        ),
                    ])],
            )
        ])
        self.assertASTEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
