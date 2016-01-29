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


import mock

from layout_expert.c_ast import c_ast
from layout_expert.layout import layout
from layout_expert.layout import layout_to_vtype_converter


class TestLayoutToVTypeConverter(unittest.TestCase):

    def setUp(self):
        self.type_description_visitor = mock.MagicMock()
        self.layout_to_vtype_converter = (
            layout_to_vtype_converter.LayoutToVTypeConverter(
                self.type_description_visitor,
            )
        )

    def test_to_vtype_with_layout_with_no_fields(self):
        layout_to_convert = layout.Layout(
            bit_size=40,
            bit_alignment=16,
            fields=[],
        )
        type_definition = c_ast.CStruct([])
        actual = self.layout_to_vtype_converter.to_vtype(
            layout_to_convert,
            type_definition,
            'some_types',
        )
        expected = [5, {}]
        self.assertEqual(actual, expected)

    def test_to_vtype_with_layout_with_one_field(self):
        layout_to_convert = layout.Layout(
            bit_size=32,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=32,
                        bit_alignment=16,
                    )
                )
            ],
        )
        type_definition = c_ast.CStruct([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('some_type'),
            ),
        ])
        self.type_description_visitor.get_description.return_value = (
            'some_description'
        )
        actual = self.layout_to_vtype_converter.to_vtype(
            layout_to_convert,
            type_definition,
            'some_types',
        )
        self.type_description_visitor.get_description.assert_called_with(
            c_ast.CTypeReference('some_type'),
            'some_types',
        )
        expected = [4, {'x': [0, 'some_description']}]
        self.assertEqual(actual, expected)

    def test_to_vtype_with_layout_with_three_fields(self):
        layout_to_convert = layout.Layout(
            bit_size=48,
            bit_alignment=32,
            fields=[
                layout.Field(
                    bit_offset=0,
                    name='x',
                    layout=layout.Layout(
                        bit_size=16,
                        bit_alignment=8,
                    )
                ),
                layout.Field(
                    bit_offset=16,
                    name='y',
                    layout=layout.Layout(
                        bit_size=8,
                        bit_alignment=32,
                    )
                ),
                layout.Field(
                    bit_offset=24,
                    name='z',
                    layout=layout.Layout(
                        bit_size=24,
                        bit_alignment=16,
                    )
                ),
            ],
        )
        some_type = c_ast.CTypeReference('some_type')
        some_other_type = c_ast.CTypeReference('some_other_type')
        type_definition = c_ast.CStruct([
            c_ast.CField(
                name='x',
                type_definition=some_type,
            ),
            c_ast.CField(
                name='y',
                type_definition=some_other_type,
            ),
            c_ast.CField(
                name='z',
                type_definition=some_type,
            ),
        ])
        self.type_description_visitor.get_description.side_effect = (
            'some_description',
            'some_other_description',
            'some_description',
        )
        actual = self.layout_to_vtype_converter.to_vtype(
            layout_to_convert,
            type_definition,
            'some_types',
        )
        expected_get_description_calls = [
            mock.call(some_type, 'some_types'),
            mock.call(some_other_type, 'some_types'),
            mock.call(some_type, 'some_types'),
        ]
        self.assertEqual(
            self.type_description_visitor.get_description.call_args_list,
            expected_get_description_calls,
        )
        expected = [
            6, {
                'x': [0, 'some_description'],
                'y': [2, 'some_other_description'],
                'z': [3, 'some_description'],
            }
        ]
        self.assertEqual(actual, expected)

    def test_to_vtype_with_layout_with_bit_field(self):
        layout_to_convert = layout.Layout(
            bit_size=48,
            bit_alignment=16,
            fields=[
                layout.Field(
                    bit_offset=33,
                    name='x',
                    layout=layout.Layout(
                        bit_size=9,
                        bit_alignment=16,
                        bit_field=True,
                    )
                )
            ],
        )
        type_definition = c_ast.CStruct([
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('some_type'),
                bit_size=9,
            ),
        ])
        self.type_description_visitor.get_description.return_value = [
            'some_type']
        actual = self.layout_to_vtype_converter.to_vtype(
            layout_to_convert,
            type_definition,
            'some_types',
        )
        self.type_description_visitor.get_description.assert_called_with(
            c_ast.CTypeReference('some_type'),
            'some_types',
        )
        expected = [
            6, {
                'x': [
                    4, [
                        'BitField', {
                            'start_bit': 1,
                            'end_bit': 10,
                            'target': 'some_type',
                        }
                    ],
                ],
            },
        ]
        self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
