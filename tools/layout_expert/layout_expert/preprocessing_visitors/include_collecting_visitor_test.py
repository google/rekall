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

from layout_expert.c_ast import pre_ast
from layout_expert.preprocessing_visitors import include_collecting_visitor


class TestIncludeCollectingVisitor(unittest.TestCase):

    def setUp(self):
        self.include_collector = (
            include_collecting_visitor.IncludeCollectingVisitor()
        )

    def test_collect_includes_with_file(self):
        mock_node = mock.MagicMock()
        node = pre_ast.File(mock_node)
        mock_node.accept.return_value = 42
        actual = self.include_collector.collect_includes(node)
        expected = 42
        self.assertEqual(actual, expected)

    def test_collect_includes_with_include(self):
        node = pre_ast.Include(
            path='some_path',
            quotes_type='some_qutes_type',
        )
        actual = self.include_collector.collect_includes(node)
        expected = [node]
        self.assertEqual(actual, expected)

    def test_collect_includes_with_pragma(self):
        node = pre_ast.Pragma('some_arguments')
        actual = self.include_collector.collect_includes(node)
        expected = []
        self.assertEqual(actual, expected)

    def test_collect_includes_with_error(self):
        node = pre_ast.Error('some_message')
        actual = self.include_collector.collect_includes(node)
        expected = []
        self.assertEqual(actual, expected)

    def test_collect_includes_with_define_object_like(self):
        node = pre_ast.DefineObjectLike(
            name='some_name',
            replacement='some_replacement',
        )
        actual = self.include_collector.collect_includes(node)
        expected = []
        self.assertEqual(actual, expected)

    def test_collect_includes_with_define_function_like(self):
        node = pre_ast.DefineFunctionLike(
            name='some_name',
            arguments='some_arguments',
            replacement='some_replacement',
        )
        actual = self.include_collector.collect_includes(node)
        expected = []
        self.assertEqual(actual, expected)

    def test_collect_includes_with_undef(self):
        node = pre_ast.Undef('some_name')
        actual = self.include_collector.collect_includes(node)
        expected = []
        self.assertEqual(actual, expected)

    def test_collect_includes_with_if(self):
        mock_conditiona_block_1 = mock.MagicMock()
        mock_conditiona_block_2 = mock.MagicMock()
        mock_conditiona_block_3 = mock.MagicMock()
        node = pre_ast.If(
            conditional_blocks=[
                mock_conditiona_block_1,
                mock_conditiona_block_2,
                mock_conditiona_block_3,
            ],
        )
        mock_conditiona_block_1.accept.return_value = [33, 42]
        mock_conditiona_block_2.accept.return_value = []
        mock_conditiona_block_3.accept.return_value = ['foo', 'bar']
        actual = self.include_collector.collect_includes(node)
        expected = [33, 42, 'foo', 'bar']
        self.assertEqual(actual, expected)

    def test_collect_includes_with_conditional_block(self):
        node = pre_ast.ConditionalBlock(
            conditional_expression='some_expression',
            content=[pre_ast.Include("33", "<")],
        )
        actual = self.include_collector.collect_includes(node)
        self.assertEqual(actual, [pre_ast.Include("33", "<")])

    def test_collect_includes_with_composite_block(self):
        mock_conditiona_block_1 = mock.MagicMock()
        mock_conditiona_block_2 = mock.MagicMock()
        mock_conditiona_block_3 = mock.MagicMock()
        node = pre_ast.CompositeBlock([
            mock_conditiona_block_1,
            mock_conditiona_block_2,
            mock_conditiona_block_3,
        ])
        mock_conditiona_block_1.accept.return_value = [33]
        mock_conditiona_block_2.accept.return_value = []
        mock_conditiona_block_3.accept.return_value = ['foo', 42]
        actual = self.include_collector.collect_includes(node)
        expected = [33, 'foo', 42]
        self.assertEqual(actual, expected)

    def test_collect_includes_with_text_block(self):
        node = pre_ast.TextBlock('some_content')
        actual = self.include_collector.collect_includes(node)
        expected = []
        self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
