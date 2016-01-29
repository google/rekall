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
from layout_expert.config_parser import config_parser


class TestConfigParser(unittest.TestCase):

    def setUp(self):
        self.parser = config_parser.ConfigParser()

    def test_parse_with_empty_config(self):
        config = ''
        actual = self.parser.parse(config)
        expected = {}
        self.assertEqual(actual, expected)

    def test_parse_with_whitespace_config(self):
        config = '   \t  \t\t   '
        actual = self.parser.parse(config)
        expected = {}
        self.assertEqual(actual, expected)

    def test_parse_with_whitespace_multiline_config(self):
        config = '  \t\t  \n\t\n\n\t\t\t\n '
        actual = self.parser.parse(config)
        expected = {}
        self.assertEqual(actual, expected)

    def test_parse_with_yes_flag(self):
        config = 'FLAG=y'
        actual = self.parser.parse(config)
        expected = {'FLAG': c_ast.CNumber(1)}
        self.assertEqual(actual, expected)

    def test_parse_with_module_flag(self):
        config = 'FLAG=m'
        actual = self.parser.parse(config)
        expected = {'FLAG_MODULE': c_ast.CNumber(1)}
        self.assertEqual(actual, expected)

    def test_parse_with_integer_flag(self):
        config = 'FLAG=42'
        actual = self.parser.parse(config)
        expected = {'FLAG': c_ast.CNumber(42)}
        self.assertEqual(actual, expected)

    def test_parse_with_hexadecimal_integer_flag(self):
        config = 'CONFIG_ILLEGAL_POINTER_VALUE=0xdead000000000000'
        actual = self.parser.parse(config)
        expected = {
            'CONFIG_ILLEGAL_POINTER_VALUE': c_ast.CNumber(0xdead000000000000),
        }
        self.assertEqual(actual, expected)

    def test_parse_with_empty_string_flag(self):
        config = 'FLAG=""'
        actual = self.parser.parse(config)
        expected = {'FLAG': c_ast.CLiteral('')}
        self.assertEqual(actual, expected)

    def test_parse_with_string_flag(self):
        config = 'FLAG="33"'
        actual = self.parser.parse(config)
        expected = {'FLAG': c_ast.CLiteral('33')}
        self.assertEqual(actual, expected)

    def test_parse_with_comment_no_flag(self):
        config = '# FLAG is not set'
        actual = self.parser.parse(config)
        expected = {}
        self.assertEqual(actual, expected)

    def test_parse_with_comment(self):
        config = '# some comment'
        actual = self.parser.parse(config)
        expected = {}
        self.assertEqual(actual, expected)

    def test_parse_with_multiline_config(self):
        config = '\n'.join((
            '',
            'FLAG_1=42',
            'CONFIG_FLAG_2=33',
            '# CONFIG_FLAG_3 is not set',
            '',
            '# some other comment',
            'CONFIG_FLAG_4=y',
            '\t\t',
            'CONFIG_FLAG_5=m',
            '',
            '',
        ))
        actual = self.parser.parse(config)
        expected = {
            'FLAG_1': c_ast.CNumber(42),
            'CONFIG_FLAG_2': c_ast.CNumber(33),
            'CONFIG_FLAG_4': c_ast.CNumber(1),
            'CONFIG_FLAG_5_MODULE': c_ast.CNumber(1),
        }
        self.assertEqual(actual, expected)

    def test_parse_with_value_n(self):
        config = 'FLAG=n'
        with self.assertRaises(config_parser.UnknownConfigLineFormatException):
            self.parser.parse(config)

    def test_parse_with_other_wrong_value(self):
        config = 'FLAG=123f'
        with self.assertRaises(config_parser.UnknownConfigLineFormatException):
            self.parser.parse(config)

    def test_parse_with_wrong_flag_name(self):
        config = 'CONFIG FLAG=y'
        with self.assertRaises(config_parser.UnknownConfigLineFormatException):
            self.parser.parse(config)

    def test_parse_with_wrong_line(self):
        config = 'CONFIG FLAG'
        with self.assertRaises(config_parser.UnknownConfigLineFormatException):
            self.parser.parse(config)


if __name__ == '__main__':
    unittest.main()
