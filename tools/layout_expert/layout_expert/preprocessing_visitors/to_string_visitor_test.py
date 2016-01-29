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
from layout_expert.preprocessing_visitors import to_string_visitor


class TestToStringVisitor(unittest.TestCase):

    def setUp(self):
        self.to_string_visitor = to_string_visitor.ToStringVisitor()

    def test_to_string_with_file(self):
        mock_node = mock.MagicMock()
        node = pre_ast.File(mock_node)
        mock_node.accept.side_effect = (
            lambda visitor, parts: parts.extend(('foo', 'bar', '42'))
        )
        actual = self.to_string_visitor.to_string(node)
        expected = 'foo bar 42'
        self.assertEqual(actual, expected)

    def test_to_string_with_composite_block(self):
        mock_node_1 = mock.MagicMock()
        mock_node_2 = mock.MagicMock()
        mock_node_3 = mock.MagicMock()
        node = pre_ast.CompositeBlock([
            mock_node_1,
            mock_node_2,
            mock_node_3,
        ])
        mock_node_1.accept.side_effect = (
            lambda visitor, parts: parts.extend(('foo', 'bar', '42'))
        )
        mock_node_2.accept.side_effect = (
            lambda visitor, parts: parts.extend(())
        )
        mock_node_3.accept.side_effect = (
            lambda visitor, parts: parts.extend(('33 24',))
        )
        actual = self.to_string_visitor.to_string(node)
        expected = 'foo bar 42 33 24'
        self.assertEqual(actual, expected)

    def test_to_string_with_text_block(self):
        node = pre_ast.TextBlock('some text content')
        actual = self.to_string_visitor.to_string(node)
        expected = 'some text content'
        self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
