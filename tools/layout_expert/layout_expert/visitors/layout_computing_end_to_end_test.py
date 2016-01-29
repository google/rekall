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
from layout_expert.layout import layout
from layout_expert.lib import type_manager as type_manager_module


class TestLayoutComputingVisitor(unittest.TestCase):

    # All the test cases verified with GCC compilation and DWARF extraction.

    def setUp(self):
        self.type_manager = type_manager_module.TypeManager()
        self.parser = self.type_manager.parser

    def test_empty_struct(self):
        source = """
                struct s {};
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)
        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=0,
            bit_alignment=8,
            fields=[],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_empty_struct(self):
        source = """
                struct e {};
                struct s {
                    struct e e1;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=0,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='e1',
                    layout=layout.Layout(
                        bit_size=0,
                        bit_alignment=8,
                        fields=[],
                    ),
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_two_empty_structs(self):
        source = """
                struct e {};
                struct s {
                    struct e e1, e2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_e_layout = layout.Layout(
            bit_size=0,
            bit_alignment=8,
            fields=[],
        )
        expected = layout.Layout(
            bit_size=0,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='e1',
                    layout=struct_e_layout
                ),
                layout.Field(
                    bit_offset=0,
                    name='e2',
                    layout=struct_e_layout
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_empty_struct_and_empty_struct(self):
        source = """
                struct e {};
                struct s {
                    struct e e1;
                    struct e e2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_e_layout = layout.Layout(
            bit_size=0,
            bit_alignment=8,
            fields=[],
        )
        expected = layout.Layout(
            bit_size=0,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='e1',
                    layout=struct_e_layout
                ),
                layout.Field(
                    bit_offset=0,
                    name='e2',
                    layout=struct_e_layout
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_array_of_10_empty_structs(self):
        source = """
                struct e {};
                struct s {
                    struct e t[10];
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_e_layout = layout.Layout(
            bit_size=0,
            bit_alignment=8,
            fields=[],
        )
        expected = layout.Layout(
            bit_size=0,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='t',
                    layout=layout.ArrayLayout(
                        bit_size=0,
                        bit_alignment=8,
                        length=10,
                        member_layout=struct_e_layout,
                    ),
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_one_char(self):
        source = """
                struct s {
                    char c;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=8,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_one_short(self):
        source = """
                struct s {
                    short s;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=16,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='s',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_one_int(self):
        source = """
                struct s {
                    int i;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=32,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='i',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_enum_field(self):
        source = """
                enum e {
                    FOO,
                    BAR,
                };
                struct s {
                    enum e e1;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=32,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='e1',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    ),
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_one_long(self):
        source = """
                struct s {
                    long l;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_int(self):
        source = """
                struct s {
                    char c;
                    int i;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='i',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_int_and_char(self):
        source = """
                struct s {
                    int i;
                    char c;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='i',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_int_and_long(self):
        source = """
                struct s {
                    char c;
                    int i;
                    long l;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='i',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_int_and_char(self):
        source = """
                struct s {
                    long l;
                    int i;
                    char c;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='i',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
                layout.Field(
                    bit_offset=96,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_and_int(self):
        source = """
                struct s {
                    long l;
                    int i;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='i',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_int_and_long(self):
        source = """
                struct s {
                    int i;
                    long l;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='i',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_array_of_10_structs_with_one_char(self):
        source = """
                struct c {
                    char c;
                };
                struct s {
                    struct c t[10];
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_c_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                )
            ]
        )
        expected = layout.Layout(
            bit_size=80,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='t',
                    layout=layout.ArrayLayout(
                        bit_size=80,
                        bit_alignment=8,
                        length=10,
                        member_layout=struct_c_layout,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_long(self):
        source = """
                struct s {
                    char c;
                    long l;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_and_char(self):
        source = """
                struct s {
                    long l;
                    char c;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_long_packed_and_fields(self):
        source = """
                struct s {
                    long l;
                    char c;
                } __attribute__((packed)) v1, v2, v3;
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=72,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_long_and_field_packed(self):
        source = """
                struct s {
                    char c;
                    long l;
                } x __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_three_chars(self):
        source = """
                struct s {
                    char c1;
                    char c2;
                    char c3;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=24,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='c2',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='c3',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_three_ints(self):
        source = """
                struct s {
                    int i1;
                    int i2;
                    int i3;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=96,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='i1',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='i2',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='i3',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_three_chars_struct(self):
        source = """
                struct c {
                    char c1;
                    char c2;
                    char c3;
                };
                struct s {
                    char c1;
                    struct c s1;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        struct_c_layout = layout.Layout(
            bit_size=24,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=8,
                    name='c2',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=16,
                    name='c3',
                    layout=char_layout,
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=32,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=8,
                    name='s1',
                    layout=struct_c_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_three_int_struct(self):
        source = """
                struct i {
                    int i1;
                    int i2;
                    int i3;
                };
                struct s {
                    char c1;
                    struct i s1;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        int_layout = layout.Layout(
            bit_size=32,
            bit_alignment=32,
        )
        struct_c_layout = layout.Layout(
            bit_size=96,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='i1',
                    layout=int_layout,
                ),
                layout.Field(
                    bit_offset=32,
                    name='i2',
                    layout=int_layout,
                ),
                layout.Field(
                    bit_offset=64,
                    name='i3',
                    layout=int_layout,
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    ),
                ),
                layout.Field(
                    bit_offset=32,
                    name='s1',
                    layout=struct_c_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_char_struct_and_char(self):
        source = """
                struct r {
                    long l;
                    char c;
                };
                struct s {
                    struct r r1;
                    char c;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        struct_r_layout = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    ),
                ),
                layout.Field(
                    bit_offset=64,
                    name='c',
                    layout=char_layout,
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=192,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=struct_r_layout
                ),
                layout.Field(
                    bit_offset=128,
                    name='c',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_long_struct_and_char(self):
        source = """
                struct r {
                    char c;
                    long l;
                };
                struct s {
                    struct r r1;
                    char c;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        struct_r_layout = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=64,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    ),
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=192,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=struct_r_layout
                ),
                layout.Field(
                    bit_offset=128,
                    name='c',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_char_struct_packed_and_char(self):
        source = """
                struct r {
                    long l;
                    char c;
                };
                struct s {
                    struct r r1 __attribute__((packed));
                    char c;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        struct_r_layout_packed = layout.Layout(
            bit_size=128,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    ),
                ),
                layout.Field(
                    bit_offset=64,
                    name='c',
                    layout=char_layout,
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=136,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=struct_r_layout_packed,
                ),
                layout.Field(
                    bit_offset=128,
                    name='c',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_long_struct_packed_and_char(self):
        source = """
                struct r {
                    char c;
                    long l;
                };
                struct s {
                    struct r r1 __attribute__((packed));
                    char c;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        struct_r_layout_packed = layout.Layout(
            bit_size=128,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=64,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    ),
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=136,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=struct_r_layout_packed,
                ),
                layout.Field(
                    bit_offset=128,
                    name='c',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_long_char_struct_and_char(self):
        source = """
                struct r {
                    long l;
                    char c;
                };
                struct s {
                    struct r r1;
                    char c;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        struct_r_layout = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    ),
                ),
                layout.Field(
                    bit_offset=64,
                    name='c',
                    layout=char_layout,
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=136,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=struct_r_layout
                ),
                layout.Field(
                    bit_offset=128,
                    name='c',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_char_long_struct_and_char(self):
        source = """
                struct r {
                    char c;
                    long l;
                };
                struct s {
                    struct r r1;
                    char c;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        struct_r_layout = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=64,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    ),
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=136,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=struct_r_layout
                ),
                layout.Field(
                    bit_offset=128,
                    name='c',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_aligned_2_and_packed_struct_with_char_and_long(self):
        source = """
                struct s {
                    char c;
                    long l;
                } __attribute__((aligned(2))) __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=80,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=8,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    ),
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_aligned_2_packed_struct_with_char_and_long(
            self):
        source = """
                struct r {
                    char c;
                    long l;
                } __attribute__((aligned(2))) __attribute__((packed));

                struct s {
                    char c;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        struct_r_layout = layout.Layout(
            bit_size=80,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=8,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    ),
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=96,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=16,
                    name='r',
                    layout=struct_r_layout,
                )
            ]
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_long_char(self):
        source = """
                struct s {
                    char c1;
                    long l;
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=192,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=64,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=128,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_packed_long_char(self):
        source = """
                struct s {
                    char c1 __attribute__((packed));
                    long l;
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=192,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=64,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=128,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_long_packed_char(self):
        source = """
                struct s {
                    char c1;
                    long l __attribute__((packed));
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=80,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=8,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=72,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_long_packed_with_underscores_char(self):
        source = """
                struct s {
                    char c1;
                    long l __attribute__((__packed__));
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=80,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=8,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=72,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_long_char_packed(self):
        source = """
                struct s {
                    char c1;
                    long l;
                    char c2 __attribute__((packed));
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=192,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=64,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=128,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_packed_long_char_packed(self):
        source = """
                struct s {
                    char c1 __attribute__((packed));
                    long l;
                    char c2 __attribute__((packed));
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=192,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=64,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=128,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_long_char_all_packed(self):
        source = """
                struct s {
                    char __attribute__((packed)) c1;
                    long __attribute__((packed)) l;
                    char __attribute__((packed)) c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=80,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=8,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=72,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_long_aligned_1_char(self):
        source = """
                struct s {
                    char c1;
                    long l __attribute__((aligned(1)));
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=192,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=64,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=128,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_long_aligned_with_underscores_1_char(self):
        source = """
                struct s {
                    char c1;
                    long l __attribute__((__aligned__(1)));
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=192,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=64,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=128,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_long_aligned_2_char(self):
        source = """
                struct s {
                    char c1;
                    long l __attribute__((aligned(2)));
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=192,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=64,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=128,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_long_aligned_1_packed_char(self):
        source = """
                struct s {
                    char c1;
                    long l __attribute__((aligned(1))) __attribute__((packed));
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=80,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=8,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=72,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_long_aligned_2_packed_char(self):
        source = """
                struct s {
                    char c1;
                    long l __attribute__((aligned(2))) __attribute__((packed));
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=96,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=16,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=16,
                    )
                ),
                layout.Field(
                    bit_offset=80,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_char_long_char(self):
        source = """
                struct s {
                    char c1;
                    long l;
                    char c2;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=80,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=8,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=72,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_char_char(self):
        source = """
                struct s {
                    long l;
                    char c1;
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=72,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_packed_char_char(self):
        source = """
                struct s {
                    long l __attribute__((packed));
                    char c1;
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=80,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=72,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_char_packed_char(self):
        source = """
                struct s {
                    long l;
                    char c1 __attribute__((packed));
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=72,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_char_char_packed(self):
        source = """
                struct s {
                    long l;
                    char c1;
                    char c2 __attribute__((packed));
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=72,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_char_packed_char_packed(self):
        source = """
                struct s {
                    long l;
                    char c1 __attribute__((packed));
                    char c2 __attribute__((packed));
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=72,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_char_char_all_packed(self):
        source = """
                struct s {
                    long l    __attribute__((packed));
                    char c1 __attribute__((packed));
                    char c2 __attribute__((packed));
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=80,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=72,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_char_aligned_1_char(self):
        source = """
                struct s {
                    long l;
                    char c1 __attribute__((aligned(1)));
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=72,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_char_aligned_2_char(self):
        source = """
                struct s {
                    long l;
                    char c1 __attribute__((aligned(2)));
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='c1',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=16,
                    ),
                ),
                layout.Field(
                    bit_offset=72,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_char_aligned_1_packed_char(self):
        source = """
                struct s {
                    long l;
                    char c1 __attribute__((aligned(1)));
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=72,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_char_aligned_2_packed_char(self):
        source = """
                struct s {
                    long l;
                    char c1 __attribute__((aligned(2)));
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='c1',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=16,
                    ),
                ),
                layout.Field(
                    bit_offset=72,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_long_char_char(self):
        source = """
                struct s {
                    long l;
                    char c1;
                    char c2;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=80,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=72,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_long_struct_packed(self):
        source = """
                struct s {
                    struct r {
                        char c;
                        long l;
                    } r1 __attribute__((packed));
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        long_layout = layout.Layout(
            bit_size=64,
            bit_alignment=64,
        )
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=128,
                        bit_alignment=8,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='c',
                                layout=char_layout,
                            ),
                            layout.Field(
                                bit_offset=64,
                                name='l',
                                layout=long_layout,
                            ),
                        ]
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_packed_char_long_struct(self):
        source = """
                struct s {
                    struct r {
                        char c;
                        long l;
                    } __attribute__((packed)) r1;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        long_layout = layout.Layout(
            bit_size=64,
            bit_alignment=64,
        )
        expected = layout.Layout(
            bit_size=72,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=72,
                        bit_alignment=8,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='c',
                                layout=char_layout,
                            ),
                            layout.Field(
                                bit_offset=8,
                                name='l',
                                layout=long_layout,
                            ),
                        ]
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_char_long_struct_packed(self):
        source = """
                struct s {
                    char c;
                    struct r {
                        char c;
                        long l;
                    } r1 __attribute__((packed));
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        long_layout = layout.Layout(
            bit_size=64,
            bit_alignment=64,
        )
        expected = layout.Layout(
            bit_size=136,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=8,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=128,
                        bit_alignment=8,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='c',
                                layout=char_layout,
                            ),
                            layout.Field(
                                bit_offset=64,
                                name='l',
                                layout=long_layout,
                            ),
                        ]
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_packed_char_long_struct(self):
        source = """
                struct s {
                    char c;
                    struct r {
                        char c;
                        long l;
                    } __attribute__((packed)) r1;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        long_layout = layout.Layout(
            bit_size=64,
            bit_alignment=64,
        )
        expected = layout.Layout(
            bit_size=80,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=8,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=72,
                        bit_alignment=8,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='c',
                                layout=char_layout,
                            ),
                            layout.Field(
                                bit_offset=8,
                                name='l',
                                layout=long_layout,
                            ),
                        ]
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_packed_array_of_10_char_long_structs(self):
        source = """
                struct r {
                    char c;
                    long l;
                };
                struct s {
                    struct r __attribute__((packed)) t[10] __attribute__((packed));
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        long_layout = layout.Layout(
            bit_size=64,
            bit_alignment=64,
        )
        expected = layout.Layout(
            bit_size=1280,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='t',
                    layout=layout.ArrayLayout(
                        bit_size=1280,
                        bit_alignment=8,
                        length=10,
                        member_layout=layout.Layout(
                            bit_size=128,
                            bit_alignment=64,
                            fields=[
                                layout.Field(
                                    bit_offset=0,
                                    name='c',
                                    layout=char_layout,
                                ),
                                layout.Field(
                                    bit_offset=64,
                                    name='l',
                                    layout=long_layout,
                                ),
                            ]
                        ),
                    ),
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_packed_long_and_long(self):
        source = """
                struct s {
                    char c;
                    long l1 __attribute__((packed)), l2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        long_layout = layout.Layout(
            bit_size=64,
            bit_alignment=64,
        )
        expected = layout.Layout(
            bit_size=192,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=8,
                    name='l1',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=8,
                    ),
                ),
                layout.Field(
                    bit_offset=128,
                    name='l2',
                    layout=long_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_long_packed_and_long(self):
        source = """
                struct s {
                    char c;
                    long __attribute__((packed)) l1;
                    long l2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        long_layout = layout.Layout(
            bit_size=64,
            bit_alignment=64,
        )
        expected = layout.Layout(
            bit_size=192,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=8,
                    name='l1',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=8,
                    ),
                ),
                layout.Field(
                    bit_offset=128,
                    name='l2',
                    layout=long_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_packed_two_longs(self):
        source = """
                struct s {
                    char c;
                    long __attribute__((packed)) l1, l2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=136,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=8,
                    name='l1',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=8,
                    ),
                ),
                layout.Field(
                    bit_offset=72,
                    name='l2',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=8,
                    ),
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_and_char_struct_packed_and_char(self):
        source = """
                struct s {
                    struct r {
                        long l;
                        char c;
                    } r1 __attribute__((packed));
                    char c;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        long_layout = layout.Layout(
            bit_size=64,
            bit_alignment=64,
        )
        expected = layout.Layout(
            bit_size=136,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=128,
                        bit_alignment=8,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='l',
                                layout=long_layout,
                            ),
                            layout.Field(
                                bit_offset=64,
                                name='c',
                                layout=char_layout,
                            ),
                        ]
                    )
                ),
                layout.Field(
                    bit_offset=128,
                    name='c',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_packed_long_char_struct_and_char(self):
        source = """
                struct s {
                    struct r {
                        long l;
                        char c;
                    } __attribute__((packed)) r1;
                    char c;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        long_layout = layout.Layout(
            bit_size=64,
            bit_alignment=64,
        )
        expected = layout.Layout(
            bit_size=80,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=72,
                        bit_alignment=8,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='l',
                                layout=long_layout,
                            ),
                            layout.Field(
                                bit_offset=64,
                                name='c',
                                layout=char_layout,
                            ),
                        ]
                    )
                ),
                layout.Field(
                    bit_offset=72,
                    name='c',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_and_char_packed_and_char(self):
        source = """
                struct r {
                    long l;
                    char c;
                };
                struct s {
                    struct r __attribute__((packed)) r1 __attribute__((packed));
                    char c;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        long_layout = layout.Layout(
            bit_size=64,
            bit_alignment=64,
        )
        expected = layout.Layout(
            bit_size=136,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=128,
                        bit_alignment=8,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='l',
                                layout=long_layout,
                            ),
                            layout.Field(
                                bit_offset=64,
                                name='c',
                                layout=char_layout,
                            ),
                        ]
                    )
                ),
                layout.Field(
                    bit_offset=128,
                    name='c',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_long_char_struct_packed_t_packed_and_char_packed(
            self,
    ):
        source = """
                struct r {
                    long l;
                    char c;
                };

                typedef __attribute__((packed)) struct r __attribute__((packed))
                    struct_r_packed_t __attribute__((packed));

                struct s {
                    struct_r_packed_t __attribute__((packed)) r1 __attribute__((packed));
                    char __attribute__((packed)) c __attribute__((packed));
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        long_layout = layout.Layout(
            bit_size=64,
            bit_alignment=64,
        )
        expected = layout.Layout(
            bit_size=136,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=128,
                        bit_alignment=8,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='l',
                                layout=long_layout,
                            ),
                            layout.Field(
                                bit_offset=64,
                                name='c',
                                layout=char_layout,
                            ),
                        ]
                    )
                ),
                layout.Field(
                    bit_offset=128,
                    name='c',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_struct_with_long_char_t_packed_and_char_packed(
            self,
    ):
        source = """
                typedef struct {
                    long l;
                    char c;
                } struct_r_packed_t __attribute__((packed));

                struct s {
                    struct_r_packed_t __attribute__((packed)) r1 __attribute__((packed));
                    char __attribute__((packed)) c __attribute__((packed));
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        long_layout = layout.Layout(
            bit_size=64,
            bit_alignment=64,
        )
        expected = layout.Layout(
            bit_size=136,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=128,
                        bit_alignment=8,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='l',
                                layout=long_layout,
                            ),
                            layout.Field(
                                bit_offset=64,
                                name='c',
                                layout=char_layout,
                            ),
                        ]
                    )
                ),
                layout.Field(
                    bit_offset=128,
                    name='c',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_three_int_bitfields(self):
        source = """
                struct s {
                    int x : 1, y : 2, z : 3;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=32,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=1,
                    name='y',
                    layout=layout.Layout(
                        bit_size=2,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=3,
                    name='z',
                    layout=layout.Layout(
                        bit_size=3,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_three_separate_int_bitfields(self):
        source = """
                struct s {
                    int x : 1;
                    int y : 2;
                    int z : 3;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=32,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=1,
                    name='y',
                    layout=layout.Layout(
                        bit_size=2,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=3,
                    name='z',
                    layout=layout.Layout(
                        bit_size=3,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_three_long_bitfields(self):
        source = """
                struct s {
                    long x : 1, y : 2, z : 3;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=1,
                    name='y',
                    layout=layout.Layout(
                        bit_size=2,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=3,
                    name='z',
                    layout=layout.Layout(
                        bit_size=3,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_three_separate_long_bitfields(self):
        source = """
                struct s {
                    long x : 1;
                    long y : 2;
                    long z : 3;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=1,
                    name='y',
                    layout=layout.Layout(
                        bit_size=2,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=3,
                    name='z',
                    layout=layout.Layout(
                        bit_size=3,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_int_and_long_bitfields(self):
        source = """
                struct s {
                    int x : 4;
                    long y : 5;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=4,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=4,
                    name='y',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_and_int_bitfields(self):
        source = """
                struct s {
                    long x : 4;
                    int y : 5;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=4,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=4,
                    name='y',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_int_and_large_long_bitfields(self):
        source = """
                struct s {
                    int x : 1;
                    long y : 60;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=1,
                    name='y',
                    layout=layout.Layout(
                        bit_size=60,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_and_large_int_bitfields(self):
        source = """
                struct s {
                    long x : 1;
                    int y : 30;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=1,
                    name='y',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_large_int_and_medium_long_bitfields(self):
        source = """
                struct s {
                    int x : 30;
                    long y : 30;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=30,
                    name='y',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_medium_long_and_large_int_bitfields(self):
        source = """
                struct s {
                    long x : 30;
                    int y : 30;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='y',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_30_and_int_15(self):
        source = """
                struct s {
                    long x : 30;
                    int y : 15;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='y',
                    layout=layout.Layout(
                        bit_size=15,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_30_and_int_5(self):
        source = """
                struct s {
                    long x : 30;
                    int y : 5;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='y',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_30_and_int_3(self):
        source = """
                struct s {
                    long x : 30;
                    int y : 3;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='y',
                    layout=layout.Layout(
                        bit_size=3,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_30_and_int_2(self):
        source = """
                struct s {
                    long x : 30;
                    int y : 2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=30,
                    name='y',
                    layout=layout.Layout(
                        bit_size=2,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_60_and_int_5(self):
        source = """
                struct s {
                    long x : 60;
                    int y : 5;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=60,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='y',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_60_and_int_4(self):
        source = """
                struct s {
                    long x : 60;
                    int y : 4;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=60,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=60,
                    name='y',
                    layout=layout.Layout(
                        bit_size=4,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_5_and_char_4(self):
        source = """
                struct s {
                    long x : 5;
                    char y : 4;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='y',
                    layout=layout.Layout(
                        bit_size=4,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_5_and_char_3(self):
        source = """
                struct s {
                    long x : 5;
                    char y : 3;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=5,
                    name='y',
                    layout=layout.Layout(
                        bit_size=3,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_5_and_short_4(self):
        source = """
                struct s {
                    long x : 5;
                    short y : 4;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=5,
                    name='y',
                    layout=layout.Layout(
                        bit_size=4,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_5_and_short_3(self):
        source = """
                struct s {
                    long x : 5;
                    short y : 3;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=5,
                    name='y',
                    layout=layout.Layout(
                        bit_size=3,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_40_and_short_7(self):
        source = """
                struct s {
                    long x : 40;
                    short y : 7;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=40,
                    name='y',
                    layout=layout.Layout(
                        bit_size=7,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_40_and_short_8(self):
        source = """
                struct s {
                    long x : 40;
                    short y : 8;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=40,
                    name='y',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_40_and_short_9(self):
        source = """
                struct s {
                    long x : 40;
                    short y : 9;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=48,
                    name='y',
                    layout=layout.Layout(
                        bit_size=9,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_long_30_and_long_30(self):
        source = """
                struct s {
                    long x : 30;
                    long y : 30;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=30,
                    name='y',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_short_10_and_long_7(self):
        source = """
                struct s {
                    short x : 10;
                    long y : 7;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=10,
                    name='y',
                    layout=layout.Layout(
                        bit_size=7,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_short_10_and_long_6(self):
        source = """
                struct s {
                    short x : 10;
                    long y : 6;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=10,
                    name='y',
                    layout=layout.Layout(
                        bit_size=6,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_short_10_and_long_21(self):
        source = """
                struct s {
                    short x : 10;
                    long y : 21;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=10,
                    name='y',
                    layout=layout.Layout(
                        bit_size=21,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_short_10_and_long_22(self):
        source = """
                struct s {
                    short x : 10;
                    long y : 22;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=10,
                    name='y',
                    layout=layout.Layout(
                        bit_size=22,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_short_10_and_long_23(self):
        source = """
                struct s {
                    short x : 10;
                    long y : 23;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=10,
                    name='y',
                    layout=layout.Layout(
                        bit_size=23,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_short_10_and_long_53(self):
        source = """
                struct s {
                    short x : 10;
                    long y : 53;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=10,
                    name='y',
                    layout=layout.Layout(
                        bit_size=53,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_short_10_and_long_54(self):
        source = """
                struct s {
                    short x : 10;
                    long y : 54;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=10,
                    name='y',
                    layout=layout.Layout(
                        bit_size=54,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_short_10_and_long_55(self):
        source = """
                struct s {
                    short x : 10;
                    long y : 55;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='y',
                    layout=layout.Layout(
                        bit_size=55,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_struct_long_30_and_long_30(self):
        source = """
                struct r {
                    long x : 30;
                    long y : 30;
                };

                struct s {
                    char c;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='r',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='x',
                                layout=layout.Layout(
                                    bit_size=30,
                                    bit_alignment=64,
                                    bit_field=True,
                                )
                            ),
                            layout.Field(
                                bit_offset=30,
                                name='y',
                                layout=layout.Layout(
                                    bit_size=30,
                                    bit_alignment=64,
                                    bit_field=True,
                                )
                            ),
                        ],
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_30_int_30_and_long_1(self):
        source = """
                struct s {
                    long x : 30;
                    int y : 30;
                    long z : 1;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='y',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=62,
                    name='z',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_30_int_30_and_long_2(self):
        source = """
                struct s {
                    long x : 30;
                    int y : 30;
                    long z : 2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='y',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=62,
                    name='z',
                    layout=layout.Layout(
                        bit_size=2,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_30_int_30_and_long_3(self):
        source = """
                struct s {
                    long x : 30;
                    int y : 30;
                    long z : 3;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='y',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='z',
                    layout=layout.Layout(
                        bit_size=3,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_30_int_30_and_long_4(self):
        source = """
                struct s {
                    long x : 30;
                    int y : 30;
                    long z : 4;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='y',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='z',
                    layout=layout.Layout(
                        bit_size=4,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_30_int_30_and_long_5(self):
        source = """
                struct s {
                    long x : 30;
                    int y : 30;
                    long z : 5;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='y',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='z',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_int_30_and_long_40(self):
        source = """
                struct s {
                    int x : 30;
                    long y : 40;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='y',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_40_and_int_30(self):
        source = """
                struct s {
                    long x : 40;
                    int y : 30;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='y',
                    layout=layout.Layout(
                        bit_size=30,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_three_long_40(self):
        source = """
                struct s {
                    long x : 40;
                    long y : 40;
                    long z : 40;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=192,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='y',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=128,
                    name='z',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_40_long_40_and_packed_long_40(self):
        source = """
                struct s {
                    long x : 40;
                    long y : 40;
                    long __attribute__((packed)) z : 40;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=192,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='y',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=104,
                    name='z',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_40_packed_long_40_and_long_40(self):
        source = """
                struct s {
                    long x : 40;
                    long __attribute__((packed)) y : 40;
                    long z : 40;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=40,
                    name='y',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=80,
                    name='z',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_packed_long_40_long_40_and_long_40(self):
        source = """
                struct s {
                    long __attribute__((packed)) x : 40;
                    long y : 40;
                    long z : 40;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=192,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='y',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=128,
                    name='z',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_40_packed_long_40_and_packed_long_40(self):
        source = """
                struct s {
                    long x : 40;
                    long __attribute__((packed)) y : 40;
                    long __attribute__((packed)) z : 40;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=40,
                    name='y',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=80,
                    name='z',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_packed_long_40_long_40_and_packed_long_40(self):
        source = """
                struct s {
                    long __attribute__((packed)) x : 40;
                    long y : 40;
                    long __attribute__((packed)) z : 40;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=192,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='y',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=104,
                    name='z',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_packed_long_40_packed_long_40_and_long_40(self):
        source = """
                struct s {
                    long __attribute__((packed)) x : 40;
                    long __attribute__((packed)) y : 40;
                    long z : 40;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=40,
                    name='y',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=80,
                    name='z',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_packed_long_40_packed_long_40_and_packed_long_40(self):
        source = """
                struct s {
                    long __attribute__((packed)) x : 40;
                    long __attribute__((packed)) y : 40;
                    long __attribute__((packed)) z : 40;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=120,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=40,
                    name='y',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=80,
                    name='z',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_struct_with_three_packed_longs_40(self):
        source = """
                struct r {
                    long __attribute__((packed)) x : 40;
                    long __attribute__((packed)) y : 40;
                    long __attribute__((packed)) z : 40;
                };

                struct s {
                    char c;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=120,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=40,
                    name='y',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=80,
                    name='z',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    ),
                ),
                layout.Field(
                    bit_offset=8,
                    name='r',
                    layout=struct_r_layout,
                )
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_1_and_struct_with_three_packed_longs_40(self):
        source = """
                struct r {
                    long __attribute__((packed)) x : 40;
                    long __attribute__((packed)) y : 40;
                    long __attribute__((packed)) z : 40;
                };

                struct s {
                    char c : 1;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=120,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=40,
                    name='y',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=80,
                    name='z',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=8,
                        bit_field=True,
                    ),
                ),
                layout.Field(
                    bit_offset=8,
                    name='r',
                    layout=struct_r_layout,
                )
            ],
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_three_long_40(self):
        source = """
                struct s {
                    long x : 40;
                    long y : 40;
                    long z : 40;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=120,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=40,
                    name='y',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=80,
                    name='z',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_packed_struct_with_three_long_40(self):
        source = """
                struct r {
                    long x : 40;
                    long y : 40;
                    long z : 40;
                } __attribute__((packed));

                struct s {
                    char c;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=120,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=40,
                    name='y',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=80,
                    name='z',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    ),
                ),
                layout.Field(
                    bit_offset=8,
                    name='r',
                    layout=struct_r_layout,
                )
            ]

        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_1_and_packed_struct_with_three_long_40(self):
        source = """
                struct r {
                    long x : 40;
                    long y : 40;
                    long z : 40;
                } __attribute__((packed));

                struct s {
                    char c : 1;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=120,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=40,
                    name='y',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=80,
                    name='z',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=8,
                        bit_field=True,
                    ),
                ),
                layout.Field(
                    bit_offset=8,
                    name='r',
                    layout=struct_r_layout,
                )
            ]

        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_40_long_20_and_long_40(self):
        source = """
                struct s {
                    long x : 40;
                    long y : 20;
                    long z : 40;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=40,
                    name='y',
                    layout=layout.Layout(
                        bit_size=20,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=64,
                    name='z',
                    layout=layout.Layout(
                        bit_size=40,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_1_and_short_16(self):
        source = """
                struct s {
                    long x : 1;
                    short y : 16;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='y',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_1_and_short(self):
        source = """
                struct s {
                    long x : 1;
                    short y;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='y',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_1_short_16_and_int(self):
        source = """
                struct s {
                    long x : 1;
                    short y : 16;
                    int z;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='y',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='z',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_1_short_and_int(self):
        source = """
                struct s {
                    long x : 1;
                    short y;
                    int z;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='y',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='z',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_2_short_5_and_int(self):
        source = """
                struct s {
                    long x : 2;
                    short y : 5;
                    int z;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=2,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=2,
                    name='y',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='z',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_3_short_5_and_int(self):
        source = """
                struct s {
                    long x : 3;
                    short y : 5;
                    int z;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=3,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=3,
                    name='y',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='z',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_4_short_5_and_int(self):
        source = """
                struct s {
                    long x : 4;
                    short y : 5;
                    int z;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=4,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=4,
                    name='y',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='z',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_5_char_5_short_5_int_5_char_5_and_short(self):
        source = """
                struct s {
                    long x : 5;
                    char y : 5;
                    short z : 5;
                    int u : 5;
                    char v : 5;
                    short w;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='y',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='z',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=21,
                    name='u',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=26,
                    name='v',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='w',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_5_char_5_short_5_char_5_int_5_char_5_and_short(
            self,
    ):
        source = """
                struct s {
                    long x : 5;
                    char y : 5;
                    short z : 5;
                    char t : 5;
                    int u : 5;
                    char v : 5;
                    short w;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='y',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='z',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=24,
                    name='t',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='u',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=40,
                    name='v',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=48,
                    name='w',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_5_short_5_int_5_and_short(self):
        source = """
                struct s {
                    long x : 5;
                    short z : 5;
                    int u : 5;
                    short w;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=5,
                    name='z',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=10,
                    name='u',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='w',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_long_10_short_10_int_10_and_short(self):
        source = """
                struct s {
                    long x : 10;
                    short z : 10;
                    int u : 10;
                    short w;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='z',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='u',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=48,
                    name='w',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_5_and_char_5(self):
        source = """
                struct s {
                    char x : 5;
                    char y : 5;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=16,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='y',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_struct_with_char_5_and_char_5(self):
        source = """
                struct r {
                    char x : 5;
                    char y : 5;
                };

                struct s {
                    char x;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=16,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='y',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=24,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='r',
                    layout=struct_r_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_1_and_struct_with_char_5_and_char_5(self):
        source = """
                struct r {
                    char x : 5;
                    char y : 5;
                };

                struct s {
                    char x : 1;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=16,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='y',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=24,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='r',
                    layout=struct_r_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_char_7_short_10_and_struct_with_char_5_and_char_5(self):
        source = """
                struct r {
                    char x : 5;
                    char y : 5;
                };

                struct s {
                    char x : 7;
                    short y : 10;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=16,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='y',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=48,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=7,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='y',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='r',
                    layout=struct_r_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_7_short_7_and_struct_with_char_5_and_char_5(self):
        source = """
                struct r {
                    char x : 5;
                    char y : 5;
                };

                struct s {
                    char x : 7;
                    short y : 7;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=16,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='y',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=32,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=7,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=7,
                    name='y',
                    layout=layout.Layout(
                        bit_size=7,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='r',
                    layout=struct_r_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_aligned_32_and_packed_struct_with_char_and_char(self):
        source = """
                struct r {
                    char c;
                } __attribute__((aligned(32)));

                typedef struct r struct_r_t_packed __attribute__((packed));

                struct s {
                    struct_r_t_packed r1;
                    char c;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=512,
            bit_alignment=256,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=256,
                        bit_alignment=256,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='c',
                                layout=layout.Layout(
                                    bit_size=8,
                                    bit_alignment=8,
                                )
                            )
                        ],
                    )
                ),
                layout.Field(
                    bit_offset=256,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_aligned_32_and_packed_struct_with_char(self):
        source = """
                struct r {
                    char c;
                } __attribute__((aligned(32)));

                typedef struct r struct_r_t_packed __attribute__((packed));

                struct s {
                    char c;
                    struct_r_t_packed r1;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=512,
            bit_alignment=256,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=256,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=256,
                        bit_alignment=256,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='c',
                                layout=layout.Layout(
                                    bit_size=8,
                                    bit_alignment=8,
                                )
                            )
                        ],
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_aligned_32_and_packed_struct_packed_with_char_and_char(
            self,
    ):
        source = """
                struct r {
                    char c;
                } __attribute__((aligned(32)));

                typedef struct r struct_r_t_packed __attribute__((packed));

                struct s {
                    struct_r_t_packed r1 __attribute__((packed));
                    char c;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=264,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=256,
                        bit_alignment=8,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='c',
                                layout=layout.Layout(
                                    bit_size=8,
                                    bit_alignment=8,
                                )
                            )
                        ],
                    )
                ),
                layout.Field(
                    bit_offset=256,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_aligned_32_and_packed_packed_struct_with_char(
            self,
    ):
        source = """
                struct r {
                    char c;
                } __attribute__((aligned(32)));

                typedef struct r struct_r_t_packed __attribute__((packed));

                struct s {
                    char c;
                    struct_r_t_packed r1 __attribute__((packed));
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=264,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=256,
                        bit_alignment=8,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='c',
                                layout=layout.Layout(
                                    bit_size=8,
                                    bit_alignment=8,
                                )
                            )
                        ],
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_struct_with_int_t_packed_and_char(
            self,
    ):
        source = """
                struct r {
                    int x;
                };

                typedef struct r struct_r_t_packed __attribute__((packed));

                struct s {
                    struct_r_t_packed r1;
                    char c;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='x',
                                layout=layout.Layout(
                                    bit_size=32,
                                    bit_alignment=32,
                                )
                            )
                        ],
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_struct_with_int_t_packed(
            self,
    ):
        source = """
                struct r {
                    int x;
                };

                typedef struct r struct_r_t_packed __attribute__((packed));

                struct s {
                    char c;
                    struct_r_t_packed r1;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='x',
                                layout=layout.Layout(
                                    bit_size=32,
                                    bit_alignment=32,
                                )
                            )
                        ],
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_struct_with_int_t_packed_packed_and_char(
            self,
    ):
        source = """
                struct r {
                    int x;
                };

                typedef struct r struct_r_t_packed __attribute__((packed));

                struct s {
                    struct_r_t_packed r1 __attribute__((packed));
                    char c;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=40,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=8,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='x',
                                layout=layout.Layout(
                                    bit_size=32,
                                    bit_alignment=32,
                                )
                            )
                        ],
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_struct_with_int_t_packed_packed(
            self,
    ):
        source = """
                struct r {
                    int x;
                };

                typedef struct r struct_r_t_packed __attribute__((packed));

                struct s {
                    char c;
                    struct_r_t_packed r1 __attribute__((packed));
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=40,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=8,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='x',
                                layout=layout.Layout(
                                    bit_size=32,
                                    bit_alignment=32,
                                )
                            )
                        ],
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_with_struct_with_int_t_aligned_2(
            self,
    ):
        source = """
                struct r {
                    int x;
                };

                typedef struct r struct_r_t_aligned_2 __attribute__((aligned(2)));

                struct s {
                    char c;
                    struct_r_t_aligned_2 r1;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=48,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=16,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='x',
                                layout=layout.Layout(
                                    bit_size=32,
                                    bit_alignment=32,
                                )
                            )
                        ],
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_with_struct_with_long_t_aligned_4_packed(
            self,
    ):
        source = """
                struct r {
                    long l;
                };

                typedef struct r struct_r_t_aligned_4_packed
                    __attribute__((aligned(4))) __attribute__((packed));

                struct s {
                    char c;
                    struct_r_t_aligned_4_packed r1;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=96,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='r1',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=32,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='l',
                                layout=layout.Layout(
                                    bit_size=64,
                                    bit_alignment=64,
                                )
                            )
                        ],
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_int_t_aligned_1_aligned_2(
            self,
    ):
        source = """

                typedef int int_t_aligned_1_aligned_2
                        __attribute__((aligned(1))) __attribute__((aligned(2)));

                struct s {
                    char c;
                    int_t_aligned_1_aligned_2 x;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=48,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=16,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_char_and_struct_with_char_and_int_t_aligned_1_aligned_2(
            self,
    ):
        source = """

                typedef int int_t_aligned_1_aligned_2
                        __attribute__((aligned(1))) __attribute__((aligned(2)));

                struct r {
                    char c;
                    int_t_aligned_1_aligned_2 x;
                };

                struct s {
                    char c;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=48,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=16,
                    )
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    ),
                ),
                layout.Field(
                    bit_offset=16,
                    name='r',
                    layout=struct_r_layout,
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_int_t_aligned_2_aligned_1(
            self,
    ):
        source = """

                typedef int int_t_aligned_2_aligned_1
                        __attribute__((aligned(2))) __attribute__((aligned(1)));

                struct s {
                    char c;
                    int_t_aligned_2_aligned_1 x;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=40,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=8,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_char_and_struct_char_and_int_t_aligned_2_aligned_1(
            self,
    ):
        source = """

                typedef int int_t_aligned_2_aligned_1
                        __attribute__((aligned(2))) __attribute__((aligned(1)));

                struct r {
                    char c;
                    int_t_aligned_2_aligned_1 x;
                };

                struct s {
                    char c;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=40,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=8,
                    )
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=48,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    ),
                ),
                layout.Field(
                    bit_offset=8,
                    name='r',
                    layout=struct_r_layout,
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_struct_with_short_1(
            self,
    ):
        source = """
                struct s {
                    short x : 1;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=16,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_struct_with_short_1(
            self,
    ):
        source = """
                struct r {
                    short x : 1;
                };

                struct s {
                    char c;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=16,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=32,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='r',
                    layout=struct_r_layout,
                )
            ]
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_1_and_struct_with_short_1(
            self,
    ):
        source = """
                struct r {
                    short x : 1;
                };

                struct s {
                    char c : 1;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=16,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=32,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='r',
                    layout=struct_r_layout,
                )
            ]
        )
        self.assertEqual(actual, expected)

    def test_struct_with_struct_with_short_1_and_with_char(
            self,
    ):
        source = """
                struct r {
                    short x : 1;
                };

                struct s {
                    struct r r;
                    char c;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=16,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=32,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r',
                    layout=struct_r_layout,
                ),
                layout.Field(
                    bit_offset=16,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_struct_with_struct_with_short_1_and_with_char_1(
            self,
    ):
        source = """
                struct r {
                    short x : 1;
                };

                struct s {
                    struct r r;
                    char c : 1;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=16,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=32,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='r',
                    layout=struct_r_layout,
                ),
                layout.Field(
                    bit_offset=16,
                    name='c',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_struct_with_short_1_and_with_char(
            self,
    ):
        source = """
                struct r {
                    short x : 1;
                };

                struct s {
                    char c1;
                    struct r r;
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=16,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=48,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='r',
                    layout=struct_r_layout,
                ),
                layout.Field(
                    bit_offset=32,
                    name='c2',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_1_and_struct_with_short_1_and_with_char_1(
            self,
    ):
        source = """
                struct r {
                    short x : 1;
                };

                struct s {
                    char c1 : 1;
                    struct r r;
                    char c2 : 1;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=16,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=48,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='r',
                    layout=struct_r_layout,
                ),
                layout.Field(
                    bit_offset=32,
                    name='c2',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_struct_with_int_1_and_packed_char(
            self,
    ):
        source = """
                struct s {
                    int x : 1;
                    char __attribute__((packed)) c __attribute__((packed));
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=32,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_struct_with_packed_int_1_and_packed_char(
            self,
    ):
        source = """
                struct s {
                    int __attribute__((packed)) x : 1;
                    char __attribute__((packed)) c __attribute__((packed));
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=16,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_int_1_and_int(
            self,
    ):
        source = """
                struct s {
                    int x : 1;
                    int y;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=40,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='y',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_int_7_and_int(
            self,
    ):
        source = """
                struct s {
                    int x : 7;
                    int y;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=40,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=7,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='y',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_int_and_int_1(
            self,
    ):
        source = """
                struct s {
                    int x;
                    int y : 1;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=40,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='y',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_int_and_int_7(
            self,
    ):
        source = """
                struct s {
                    int x;
                    int y : 7;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=40,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
                layout.Field(
                    bit_offset=32,
                    name='y',
                    layout=layout.Layout(
                        bit_size=7,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_int_5_and_int_5(
            self,
    ):
        source = """
                struct s {
                    int x : 5;
                    int y : 5;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=16,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=5,
                    name='y',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_int_7_and_int_7(
            self,
    ):
        source = """
                struct s {
                    int x : 7;
                    int y : 7;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=16,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=7,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=7,
                    name='y',
                    layout=layout.Layout(
                        bit_size=7,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_int_5_and_int_31(
            self,
    ):
        source = """
                struct s {
                    int x : 5;
                    int y : 31;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=40,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=5,
                    name='y',
                    layout=layout.Layout(
                        bit_size=31,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_int_7_and_int_31(
            self,
    ):
        source = """
                struct s {
                    int x : 7;
                    int y : 31;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=40,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=7,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=7,
                    name='y',
                    layout=layout.Layout(
                        bit_size=31,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_int_5_and_int_32(
            self,
    ):
        source = """
                struct s {
                    int x : 5;
                    int y : 32;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=40,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=5,
                    name='y',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_int_7_and_int_32(
            self,
    ):
        source = """
                struct s {
                    int x : 7;
                    int y : 32;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=40,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=7,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=7,
                    name='y',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_short_1_short_and_short_1(
            self,
    ):
        source = """
                struct s {
                    short s1 : 1;
                    short s2;
                    short s3 : 1;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=32,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='s1',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='s2',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                        bit_field=False,
                    )
                ),
                layout.Field(
                    bit_offset=24,
                    name='s3',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_struct_char_1_and_packed_struct_with_short_1_short_and_short_1(
            self,
    ):
        source = """
                struct r {
                    short s1 : 1;
                    short s2;
                    short s3 : 1;
                } __attribute__((packed));

                struct s {
                    char c : 1;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        struct_r_layout = layout.Layout(
            bit_size=32,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='s1',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='s2',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                        bit_field=False,
                    )
                ),
                layout.Field(
                    bit_offset=24,
                    name='s3',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ]
        )
        expected = layout.Layout(
            bit_size=40,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='r',
                    layout=struct_r_layout,
                )
            ],
        )
        self.assertEqual(actual, expected)

    def test_union_with_int_char_and_long_42(self):
        source = """
                union u {
                    int x;
                    char c;
                    long l : 42;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)
        union_u = self.type_manager.types['union u']
        actual = self.type_manager.compute_layout(union_u)
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    ),
                ),
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    ),
                ),
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=42,
                        bit_alignment=64,
                        bit_field=True,
                    )
                )
            ],
        )
        self.assertEqual(actual, expected)

    def test_packed_union_with_int_char_and_long_42(
            self,
    ):
        source = """
                union u {
                    int x;
                    char c;
                    long l : 42;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)
        union_u = self.type_manager.types['union u']
        actual = self.type_manager.compute_layout(union_u)
        expected = layout.Layout(
            bit_size=48,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    ),
                ),
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    ),
                ),
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=42,
                        bit_alignment=64,
                        bit_field=True,
                    )
                )
            ],
        )
        self.assertEqual(actual, expected)

    def test_aligned_2_and_packed_union_with_char_and_long(self):
        source = """
                union u {
                    char c;
                    long l;
                } __attribute__((aligned(2))) __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)
        union_u = self.type_manager.types['union u']
        actual = self.type_manager.compute_layout(union_u)
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    ),
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_aligned_2_and_packed_union_with_char_and_long(
            self,
    ):
        source = """
                union u {
                    char c;
                    long l;
                } __attribute__((aligned(2))) __attribute__((packed));

                struct s {
                    char c;
                    union u u;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
        )
        union_u_layout = layout.Layout(
            bit_size=64,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=64,
                        bit_alignment=64,
                    ),
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=80,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=16,
                    name='u',
                    layout=union_u_layout,
                )
            ]
        )
        self.assertEqual(actual, expected)

    def test_packed_union_with_short_1_short_and_short_1(
            self,
    ):
        source = """
                union u {
                    short s1 : 1;
                    short s2;
                    short s3 : 1;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)
        union_u = self.type_manager.types['union u']
        actual = self.type_manager.compute_layout(union_u)
        expected = layout.Layout(
            bit_size=16,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='s1',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=0,
                    name='s2',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                        bit_field=False,
                    )
                ),
                layout.Field(
                    bit_offset=0,
                    name='s3',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_1_and_packed_union_with_short_1_short_and_short_1(
            self,
    ):
        source = """
                union u {
                    short s1 : 1;
                    short s2;
                    short s3 : 1;
                } __attribute__((packed));

                struct s {
                    char c : 1;
                    union u u;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        union_u_layout = layout.Layout(
            bit_size=16,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='s1',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=0,
                    name='s2',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                        bit_field=False,
                    )
                ),
                layout.Field(
                    bit_offset=0,
                    name='s3',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ]
        )
        expected = layout.Layout(
            bit_size=24,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=8,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name='u',
                    layout=union_u_layout,
                )
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_anonymous_struct_with_short_and_int_and_char(
            self,
    ):
        source = """
                struct s {
                    char c1;
                    struct {
                        short s;
                        int x;
                    };
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
            bit_field=False,
        )
        nested_layout = layout.Layout(
            bit_size=64,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='s',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                        bit_field=False,
                    ),
                ),
                layout.Field(
                    bit_offset=32,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                        bit_field=False,
                    ),
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=32,
                    name=None,
                    layout=nested_layout,
                ),
                layout.Field(
                    bit_offset=96,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_struct_with_char_anonymous_struct_and_char(
            self,
    ):
        source = """
                struct r {
                    char c1;
                    struct {
                        short s;
                        int x;
                    };
                    char c2;
                };

                struct s {
                    char c;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
            bit_field=False,
        )
        nested_layout = layout.Layout(
            bit_size=64,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='s',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                        bit_field=False,
                    ),
                ),
                layout.Field(
                    bit_offset=32,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                        bit_field=False,
                    ),
                ),
            ],
        )
        struct_r_layout = layout.Layout(
            bit_size=128,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=32,
                    name=None,
                    layout=nested_layout,
                ),
                layout.Field(
                    bit_offset=96,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=160,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=32,
                    name='r',
                    layout=struct_r_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_anonymous_union_with_short_and_int_and_char(
            self,
    ):
        source = """
                struct s {
                    char c1;
                    union {
                        short s;
                        int x;
                    };
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
            bit_field=False,
        )
        nested_layout = layout.Layout(
            bit_size=32,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='s',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                        bit_field=False,
                    ),
                ),
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                        bit_field=False,
                    ),
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=96,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=32,
                    name=None,
                    layout=nested_layout,
                ),
                layout.Field(
                    bit_offset=64,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_struct_with_char_anonymous_union_and_char(
            self,
    ):
        source = """
                struct r {
                    char c1;
                    union {
                        short s;
                        int x;
                    };
                    char c2;
                };

                struct s {
                    char c;
                    struct r r;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
            bit_field=False,
        )
        nested_layout = layout.Layout(
            bit_size=32,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='s',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                        bit_field=False,
                    ),
                ),
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                        bit_field=False,
                    ),
                ),
            ],
        )
        struct_r_layout = layout.Layout(
            bit_size=96,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=32,
                    name=None,
                    layout=nested_layout,
                ),
                layout.Field(
                    bit_offset=64,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=128,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=32,
                    name='r',
                    layout=struct_r_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_union_with_char_and_anonymous_struct_with_short_and_int_and_char(
            self,
    ):
        source = """
                union u {
                    char c1;
                    struct {
                        short s;
                        int x;
                    };
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)
        union_u = self.type_manager.types['union u']
        actual = self.type_manager.compute_layout(union_u)
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
            bit_field=False,
        )
        nested_layout = layout.Layout(
            bit_size=64,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='s',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                        bit_field=False,
                    ),
                ),
                layout.Field(
                    bit_offset=32,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                        bit_field=False,
                    ),
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=0,
                    name=None,
                    layout=nested_layout,
                ),
                layout.Field(
                    bit_offset=0,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_union_with_char_anonymous_struct_and_char(
            self,
    ):
        source = """
                union u {
                    char c1;
                    struct {
                        short s;
                        int x;
                    };
                    char c2;
                };

                struct s {
                    char c;
                    union u u;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
            bit_field=False,
        )
        nested_layout = layout.Layout(
            bit_size=64,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='s',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                        bit_field=False,
                    ),
                ),
                layout.Field(
                    bit_offset=32,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                        bit_field=False,
                    ),
                ),
            ],
        )
        union_u = layout.Layout(
            bit_size=64,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=0,
                    name=None,
                    layout=nested_layout,
                ),
                layout.Field(
                    bit_offset=0,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=96,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=32,
                    name='u',
                    layout=union_u,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_union_with_char_and_anonymous_union_with_short_and_int_and_char(
            self,
    ):
        source = """
                union u {
                    char c1;
                    union {
                        short s;
                        int x;
                    };
                    char c2;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)
        union_u = self.type_manager.types['union u']
        actual = self.type_manager.compute_layout(union_u)
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
            bit_field=False,
        )
        nested_layout = layout.Layout(
            bit_size=32,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='s',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                        bit_field=False,
                    ),
                ),
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                        bit_field=False,
                    ),
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=32,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=0,
                    name=None,
                    layout=nested_layout,
                ),
                layout.Field(
                    bit_offset=0,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_char_and_union_with_char_anonymous_union_and_char(
            self,
    ):
        source = """
                union u {
                    char c1;
                    union {
                        short s;
                        int x;
                    };
                    char c2;
                };

                struct s {
                    char c;
                    union u u;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        char_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
            bit_field=False,
        )
        nested_layout = layout.Layout(
            bit_size=32,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='s',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=16,
                        bit_field=False,
                    ),
                ),
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                        bit_field=False,
                    ),
                ),
            ],
        )
        union_u = layout.Layout(
            bit_size=32,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=0,
                    name=None,
                    layout=nested_layout,
                ),
                layout.Field(
                    bit_offset=0,
                    name='c2',
                    layout=char_layout,
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c',
                    layout=char_layout,
                ),
                layout.Field(
                    bit_offset=32,
                    name='u',
                    layout=union_u,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_char_1_and_anonymous_packed_struct_with_char_1(
            self,
    ):
        source = """
                struct s {
                    char __attribute__((packed)) c1 : 1;
                    struct {
                        char __attribute__((packed)) c2 : 1;
                    } __attribute__((packed));
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        nested_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c2',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=8,
                        bit_field=True,
                    ),
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=16,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=8,
                        bit_field=True,
                    ),
                ),
                layout.Field(
                    bit_offset=8,
                    name=None,
                    layout=nested_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_char_1_and_anonymous_packed_union_with_char_1(
            self,
    ):
        source = """
                struct s {
                    char __attribute__((packed)) c1 : 1;
                    union {
                        char __attribute__((packed)) c2 : 1;
                    } __attribute__((packed));
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        nested_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c2',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=8,
                        bit_field=True,
                    ),
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=16,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=8,
                        bit_field=True,
                    ),
                ),
                layout.Field(
                    bit_offset=8,
                    name=None,
                    layout=nested_layout,
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_anonymous_packed_union_with_char_1_and_char_1(
            self,
    ):
        source = """
                struct s {
                    union {
                        char __attribute__((packed)) c1 : 1;
                    } __attribute__((packed));
                    char __attribute__((packed)) c2 : 1;
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        nested_layout = layout.Layout(
            bit_size=8,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=8,
                        bit_field=True,
                    ),
                ),
            ],
        )
        expected = layout.Layout(
            bit_size=16,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name=None,
                    layout=nested_layout,
                ),
                layout.Field(
                    bit_offset=8,
                    name='c2',
                    layout=layout.Layout(
                        bit_size=1,
                        bit_alignment=8,
                        bit_field=True,
                    ),
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_with_int_10_unsigned_int_10_and_int_10(
            self,
    ):
        source = """
                struct s {
                    int x : 10;
                    unsigned int y : 10;
                    int z : 10;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=32,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=10,
                    name='y',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=20,
                    name='z',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_struct_with_unsigned_int_10_signed_int_10_and_unsigned_int_10(
            self,
    ):
        source = """
                struct s {
                    unsigned int x : 10;
                    signed int y : 10;
                    unsigned int z : 10;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)
        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=32,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=10,
                    name='y',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=20,
                    name='z',
                    layout=layout.Layout(
                        bit_size=10,
                        bit_alignment=32,
                        bit_field=True,
                    )
                ),
            ]
        )
        self.assertEqual(actual, expected)

    def test_struct_signed_long_5_and_unsigned_short_7(
            self,
    ):
        source = """
                struct s {
                    signed long l : 5;
                    unsigned short s : 7;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=5,
                    name='s',
                    layout=layout.Layout(
                        bit_size=7,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_unsigned_long_5_and_signed_short_7(
            self,
    ):
        source = """
                struct s {
                    unsigned long l : 5;
                    signed short s : 7;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='l',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=5,
                    name='s',
                    layout=layout.Layout(
                        bit_size=7,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_signed_short_5_and_unsigned_long_7(
            self,
    ):
        source = """
                struct s {
                    signed short s : 5;
                    unsigned long l : 7;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='s',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=5,
                    name='l',
                    layout=layout.Layout(
                        bit_size=7,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_struct_unsigned_short_5_and_signed_long_7(
            self,
    ):
        source = """
                struct s {
                    unsigned short s : 5;
                    signed long l : 7;
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=64,
            bit_alignment=64,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='s',
                    layout=layout.Layout(
                        bit_size=5,
                        bit_alignment=16,
                        bit_field=True,
                    )
                ),
                layout.Field(
                    bit_offset=5,
                    name='l',
                    layout=layout.Layout(
                        bit_size=7,
                        bit_alignment=64,
                        bit_field=True,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_compute_layout_sets_array_evaluated_length_field(self):
        element = c_ast.CArray(
            length=c_ast.CFunctionCall(
                function_name='+',
                arguments=[
                    c_ast.CNumber(3),
                    c_ast.CNumber(4),
                ],
            ),
            type_definition=c_ast.CTypeReference('int'),
        )
        self.type_manager.compute_layout(element)
        self.assertEqual(element.evaluated_length, 7)

    def test_struct_with_int_and_int_aligned_64(self):
        source = """
                struct s {
                    int x;
                    int y __attribute__((__aligned__(64)));
                };
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=1024,
            bit_alignment=512,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
                layout.Field(
                    bit_offset=512,
                    name='y',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=512,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_int_and_int_aligned_64(self):
        source = """
                struct s {
                    int x;
                    int y __attribute__((aligned(64)));
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=1024,
            bit_alignment=512,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=32,
                    )
                ),
                layout.Field(
                    bit_offset=512,
                    name='y',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=512,
                    )
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def test_packed_struct_with_char_and_anonymous_struct_with_char_aligned_64(
            self,
    ):
        source = """
                struct s {
                    char c1;
                    struct {
                        char c2 __attribute__((aligned(64)));
                    };
                } __attribute__((packed));
                """
        program = self.parser.parse(source)
        self.type_manager.resolve_dependencies(program)

        actual = self.type_manager.get_type_layout('struct s')
        expected = layout.Layout(
            bit_size=520,
            bit_alignment=8,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='c1',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=8,
                    name=None,
                    layout=layout.Layout(
                        bit_size=512,
                        bit_alignment=512,
                        fields=[
                            layout.Field(
                                bit_offset=0,
                                name='c2',
                                layout=layout.Layout(
                                    bit_size=8,
                                    bit_alignment=512,
                                )
                            )
                        ]
                    ),
                ),
            ],
        )
        self.assertEqual(actual, expected)

    def assertEqual(self, actual, expected):
        message = '\n%s\n!=\n%s' % (actual, expected)
        super(TestLayoutComputingVisitor, self).assertEqual(
            first=actual,
            second=expected,
            msg=message,
        )


if __name__ == '__main__':
    unittest.main()
