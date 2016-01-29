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
from layout_expert.preprocessing_visitors import macro_expander
from layout_expert.preprocessing_visitors import preprocessing_visitor
from layout_expert.preprocessing_parser import preprocessing_parser


class TestPreprocessingVisitor(c_ast_test.CASTTestCase):

    def setUp(self):
        self.macros = preprocessing_parser.Macros()
        self.parser = preprocessing_parser.PreprocessingParser()
        self.visitor = preprocessing_visitor.PreprocessingVisitor(self.macros)
        self.macro_expander = macro_expander.MacroParser(self.macros)

    def test_ifdef(self):
        parsed_pre_ast = self.parser.parse("""
    #define BAZ    1024
    int Some(text);
    # if BAZ > 1000
      #define BOO 2
      int more_Text();
    # else
      #define BOO 4
    #endif
    """)

        # Learn about the macros defined above.
        actual = self.visitor.preprocess(parsed_pre_ast)
        expected = pre_ast.CompositeBlock([
            pre_ast.TextBlock(
                content='int Some(text);'
            ),
            pre_ast.CompositeBlock([
                pre_ast.TextBlock(
                    content='int more_Text();'
                )
            ])
        ])
        self.assertASTEqual(actual, expected)

        # Make sure that the right macro was defined.
        self.assertASTEqual(
            self.macros.object_likes["BOO"],
            pre_ast.DefineObjectLike(
                name="BOO",
                replacement="2"))


if __name__ == '__main__':
    unittest.main()
