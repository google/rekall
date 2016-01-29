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
from layout_expert.lib import type_manager
from layout_expert.visitors import expression_evaluator_visitor


class TestExpressionEvaluatorVisitor(unittest.TestCase):

    def f1(self, evaluator, x, y, **_):
        _ = evaluator
        self.x.append(x)
        self.y.append(y)
        return 33

    def f2(self, evaluator, z, **_):
        _ = evaluator
        self.z.append(z)
        return 42

    def setUp(self):
        self.variables = {
            'a': c_ast.CNumber(1),
            'c': c_ast.CNumber(2),
        }
        self.x = []
        self.y = []
        self.z = []
        self.functions = {
            'f1': self.f1,
            'f2': self.f2,
        }

        type_manager_obj = type_manager.TypeManager()
        type_manager_obj.functions.update(self.functions)
        type_manager_obj.variables.update(self.variables)

        self.expression_evaluator = (
            expression_evaluator_visitor.ExpressionEvaluatorVisitor(
                type_manager_obj
            )
        )

    def test_visit_function_call(self):
        function_call = c_ast.CFunctionCall(
            function_name='f1',
            arguments=[
                c_ast.CNumber(24),
                c_ast.CLiteral('literal'),
            ],
        )
        actual = self.expression_evaluator.evaluate(function_call)
        self.assertEqual(actual, 33)
        self.assertEqual(self.x, [24])
        self.assertEqual(self.y, ['literal'])

    def test_visit_nested_expression(self):
        expression = c_ast.CNestedExpression(
            opener='(',
            content=c_ast.CVariable('a'),
            closer=')',
        )
        actual = self.expression_evaluator.evaluate(expression)
        self.assertEqual(actual, 1)

    def test_visit_variable(self):
        variable = c_ast.CVariable('c')
        actual = self.expression_evaluator.evaluate(variable)
        self.assertEqual(actual, 2)

    def test_visit_number(self):
        number = c_ast.CNumber(42)
        actual = self.expression_evaluator.evaluate(number)
        self.assertEqual(actual, 42)

    def test_visit_literal(self):
        literal = c_ast.CLiteral('value')
        actual = self.expression_evaluator.evaluate(literal)
        self.assertEqual(actual, 'value')


if __name__ == '__main__':
    unittest.main()
