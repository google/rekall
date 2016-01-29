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


from layout_expert.builtins import functions
from layout_expert.c_ast import c_ast


class TestGet64BitFunctions(unittest.TestCase):

    def setUp(self):
        self.functions = functions.get_arithmetic_functions()
        self.evaluator = lambda x: x

    def test_get_type_independent_functions_with_unary_plus(self):
        actual = self.functions['+'](self.evaluator, 42)
        self.assertEqual(actual, 42)

    def test_get_type_independent_functions_with_binary_plus(self):
        actual = self.functions['+'](self.evaluator, 3, 4)
        self.assertEqual(actual, 7)

    def test_get_type_independent_functions_with_unary_minus(self):
        actual = self.functions['-'](self.evaluator, 33)
        self.assertEqual(actual, -33)

    def test_get_type_independent_functions_with_binary_minus(self):
        actual = self.functions['-'](self.evaluator, 5, 7)
        self.assertEqual(actual, -2)

    def test_get_type_independent_functions_with_logical_negation(self):
        actual = self.functions['!'](self.evaluator, True)
        self.assertEqual(actual, False)
        actual = self.functions['!'](self.evaluator, False)
        self.assertEqual(actual, True)

    def test_get_type_independent_functions_with_bitwise_negation(self):
        actual = self.functions['~'](self.evaluator, 42)
        self.assertEqual(actual, -43)

    def test_get_type_independent_functions_with_multiplication(self):
        actual = self.functions['*'](self.evaluator, 5, 7)
        self.assertEqual(actual, 35)

    def test_get_type_independent_functions_with_division(self):
        actual = self.functions['/'](self.evaluator, 33, 5)
        self.assertEqual(actual, 6)
        actual = self.functions['/'](self.evaluator, 21, 7)
        self.assertEqual(actual, 3)

    def test_get_type_independent_functions_with_modulo(self):
        actual = self.functions['%'](self.evaluator, 33, 5)
        self.assertEqual(actual, 3)
        actual = self.functions['%'](self.evaluator, 21, 7)
        self.assertEqual(actual, 0)

    def test_get_type_independent_functions_with_shift_left(self):
        actual = self.functions['<<'](self.evaluator, 5, 2)
        self.assertEqual(actual, 20)

    def test_get_type_independent_functions_with_shift_right(self):
        actual = self.functions['>>'](self.evaluator, 42, 3)
        self.assertEqual(actual, 5)

    def test_get_type_independent_functions_with_less_than(self):
        less_than = self.functions['<']
        self.assertEqual(less_than(self.evaluator, 4, 5), True)
        self.assertEqual(less_than(self.evaluator, 5, 4), False)
        self.assertEqual(less_than(self.evaluator, 4, 4), False)

    def test_get_type_independent_functions_with_greater_than(self):
        greater_than = self.functions['>']
        self.assertEqual(greater_than(self.evaluator, 4, 5), False)
        self.assertEqual(greater_than(self.evaluator, 5, 4), True)
        self.assertEqual(greater_than(self.evaluator, 4, 4), False)

    def test_get_type_independent_functions_with_less_or_equal(self):
        less_or_equal = self.functions['<=']
        self.assertEqual(less_or_equal(self.evaluator, 4, 5), True)
        self.assertEqual(less_or_equal(self.evaluator, 5, 4), False)
        self.assertEqual(less_or_equal(self.evaluator, 4, 4), True)

    def test_get_type_independent_functions_with_greater_or_equal(self):
        greater_or_equal = self.functions['>=']
        self.assertEqual(greater_or_equal(self.evaluator, 4, 5), False)
        self.assertEqual(greater_or_equal(self.evaluator, 5, 4), True)
        self.assertEqual(greater_or_equal(self.evaluator, 4, 4), True)

    def test_get_type_independent_functions_with_equal(self):
        equal = self.functions['==']
        self.assertEqual(equal(self.evaluator, 4, 5), False)
        self.assertEqual(equal(self.evaluator, 5, 4), False)
        self.assertEqual(equal(self.evaluator, 4, 4), True)

    def test_get_type_independent_functions_with_not_equal(self):
        not_equal = self.functions['!=']
        self.assertEqual(not_equal(self.evaluator, 4, 5), True)
        self.assertEqual(not_equal(self.evaluator, 5, 4), True)
        self.assertEqual(not_equal(self.evaluator, 4, 4), False)

    def test_get_type_independent_functions_with_bitwise_and(self):
        actual = self.functions['&'](self.evaluator, 42, 33)
        self.assertEqual(actual, 32)

    def test_get_type_independent_functions_with_bitwise_xor(self):
        actual = self.functions['^'](self.evaluator, 42, 33)
        self.assertEqual(actual, 11)

    def test_get_type_independent_functions_with_bitwise_or(self):
        actual = self.functions['|'](self.evaluator, 42, 24)
        self.assertEqual(actual, 58)

    def test_get_type_independent_functions_with_logical_and(self):
        and_ = self.functions['&&']
        self.assertEqual(and_(self.evaluator, True, True), True)
        self.assertEqual(and_(self.evaluator, True, False), False)
        self.assertEqual(and_(self.evaluator, False, True), False)
        self.assertEqual(and_(self.evaluator, False, False), False)

    def test_get_type_independent_functions_with_logical_or(self):
        or_ = self.functions['||']
        self.assertEqual(or_(self.evaluator, True, True), True)
        self.assertEqual(or_(self.evaluator, True, False), True)
        self.assertEqual(or_(self.evaluator, False, True), True)
        self.assertEqual(or_(self.evaluator, False, False), False)

    def test_get_type_independent_functions_with_ternary_conditional(self):
        actual = self.functions['?:'](self.evaluator, True, 42, 33)
        self.assertEqual(actual, 42)
        actual = self.functions['?:'](self.evaluator, False, 42, 33)
        self.assertEqual(actual, 33)

    def test_get_type_independent_functions_with_cast(self):
        actual = self.functions['()'](self.evaluator, 'type_name', 'value')
        self.assertEqual(actual, 'value')



class TestGetPreprocessorAnd64BitFunctions(unittest.TestCase):

    def setUp(self):
        self.functions = functions.get_arithmetic_functions()

    def evaluator(self, x):
        if isinstance(x, (c_ast.CNumber, c_ast.CVariable)):
            return x.value

        return x

    def test_unary_plus(self):
        actual = self.functions['+'](self.evaluator, c_ast.CNumber(42))
        self.assertEqual(actual, c_ast.CNumber(42))

    def test_binary_plus(self):
        actual = self.functions['+'](
            self.evaluator,
            c_ast.CNumber(3),
            c_ast.CNumber(4),
        )
        self.assertEqual(actual, c_ast.CNumber(7))

    def test_unary_minus(self):
        actual = self.functions['-'](self.evaluator, c_ast.CNumber(33))
        self.assertEqual(actual, c_ast.CNumber(-33))

    def test_binary_minus(self):
        actual = self.functions['-'](
            self.evaluator,
            c_ast.CNumber(5),
            c_ast.CNumber(7),
        )
        self.assertEqual(actual, c_ast.CNumber(-2))

    def test_logical_negation(self):
        actual = self.functions['!'](self.evaluator, c_ast.CNumber(1))
        self.assertEqual(actual, c_ast.CNumber(0))
        actual = self.functions['!'](self.evaluator, c_ast.CNumber(0))
        self.assertEqual(actual, c_ast.CNumber(1))

    def test_bitwise_negation(self):
        actual = self.functions['~'](self.evaluator, c_ast.CNumber(42))
        self.assertEqual(actual, c_ast.CNumber(-43))

    def test_multiplication(self):
        actual = self.functions['*'](
            self.evaluator,
            c_ast.CNumber(5),
            c_ast.CNumber(7),
        )
        self.assertEqual(actual, c_ast.CNumber(35))

    def test_division(self):
        actual = self.functions['/'](
            self.evaluator,
            c_ast.CNumber(33),
            c_ast.CNumber(5),
        )
        self.assertEqual(actual, c_ast.CNumber(6))
        actual = self.functions['/'](
            self.evaluator,
            c_ast.CNumber(21),
            c_ast.CNumber(7),
        )
        self.assertEqual(actual, c_ast.CNumber(3))

    def test_modulo(self):
        actual = self.functions['%'](
            self.evaluator,
            c_ast.CNumber(33),
            c_ast.CNumber(5),
        )
        self.assertEqual(actual, c_ast.CNumber(3))
        actual = self.functions['%'](
            self.evaluator,
            c_ast.CNumber(21),
            c_ast.CNumber(7),
        )

        self.assertEqual(actual, c_ast.CNumber(0))

    def test_shift_left(self):
        actual = self.functions['<<'](
            self.evaluator,
            c_ast.CNumber(5),
            c_ast.CNumber(2),
        )
        self.assertEqual(actual, c_ast.CNumber(20))

    def test_shift_right(self):
        actual = self.functions['>>'](
            self.evaluator,
            c_ast.CNumber(42),
            c_ast.CNumber(3),
        )
        self.assertEqual(actual, c_ast.CNumber(5))

    def test_less_than(self):
        less_than = self.functions['<']
        self.assertEqual(
            less_than(self.evaluator, c_ast.CNumber(4), c_ast.CNumber(5)),
            c_ast.CNumber(1)
        )
        self.assertEqual(
            less_than(self.evaluator, c_ast.CNumber(5), c_ast.CNumber(4)),
            c_ast.CNumber(0)
        )
        self.assertEqual(
            less_than(self.evaluator, c_ast.CNumber(4), c_ast.CNumber(4)),
            c_ast.CNumber(0)
        )

    def test_greater_than(self):
        greater_than = self.functions['>']
        self.assertEqual(
            greater_than(self.evaluator, c_ast.CNumber(4), c_ast.CNumber(5)),
            c_ast.CNumber(0)
        )
        self.assertEqual(
            greater_than(self.evaluator, c_ast.CNumber(5), c_ast.CNumber(4)),
            c_ast.CNumber(1)
        )
        self.assertEqual(
            greater_than(self.evaluator, c_ast.CNumber(4), c_ast.CNumber(4)),
            c_ast.CNumber(0)
        )

    def test_less_or_equal(self):
        less_or_equal = self.functions['<=']
        self.assertEqual(
            less_or_equal(self.evaluator, c_ast.CNumber(4), c_ast.CNumber(5)),
            c_ast.CNumber(1)
        )
        self.assertEqual(
            less_or_equal(self.evaluator, c_ast.CNumber(5), c_ast.CNumber(4)),
            c_ast.CNumber(0)
        )
        self.assertEqual(
            less_or_equal(self.evaluator, c_ast.CNumber(4), c_ast.CNumber(4)),
            c_ast.CNumber(1)
        )

    def test_greater_or_equal(self):
        greater_or_equal = self.functions['>=']
        self.assertEqual(
            greater_or_equal(
                self.evaluator, c_ast.CNumber(4), c_ast.CNumber(5)),
            c_ast.CNumber(0)
        )
        self.assertEqual(
            greater_or_equal(
                self.evaluator, c_ast.CNumber(5), c_ast.CNumber(4)),
            c_ast.CNumber(1)
        )
        self.assertEqual(
            greater_or_equal(
                self.evaluator, c_ast.CNumber(4), c_ast.CNumber(4)),
            c_ast.CNumber(1)
        )

    def test_equal(self):
        equal = self.functions['==']
        self.assertEqual(
            equal(self.evaluator, c_ast.CNumber(4), c_ast.CNumber(5)),
            c_ast.CNumber(0)
        )
        self.assertEqual(
            equal(self.evaluator, c_ast.CNumber(5), c_ast.CNumber(4)),
            c_ast.CNumber(0)
        )
        self.assertEqual(
            equal(self.evaluator, c_ast.CNumber(4), c_ast.CNumber(4)),
            c_ast.CNumber(1)
        )

    def test_not_equal(self):
        not_equal = self.functions['!=']
        self.assertEqual(
            not_equal(self.evaluator, c_ast.CNumber(4), c_ast.CNumber(5)),
            c_ast.CNumber(1)
        )
        self.assertEqual(
            not_equal(self.evaluator, c_ast.CNumber(5), c_ast.CNumber(4)),
            c_ast.CNumber(1)
        )
        self.assertEqual(
            not_equal(self.evaluator, c_ast.CNumber(4), c_ast.CNumber(4)),
            c_ast.CNumber(0)
        )

    def test_bitwise_and(self):
        actual = self.functions['&'](
            self.evaluator,
            c_ast.CNumber(42),
            c_ast.CNumber(33),
        )
        self.assertEqual(actual, c_ast.CNumber(32))

    def test_bitwise_xor(self):
        actual = self.functions['^'](
            self.evaluator,
            c_ast.CNumber(42),
            c_ast.CNumber(33),
        )
        self.assertEqual(actual, c_ast.CNumber(11))

    def test_bitwise_or(self):
        actual = self.functions['|'](
            self.evaluator,
            c_ast.CNumber(42),
            c_ast.CNumber(24),
        )
        self.assertEqual(actual, c_ast.CNumber(58))

    def test_logical_and(self):
        and_ = self.functions['&&']
        self.assertEqual(
            and_(self.evaluator, c_ast.CNumber(1), c_ast.CNumber(1)),
            c_ast.CNumber(1),
        )
        self.assertEqual(
            and_(self.evaluator, c_ast.CNumber(1), c_ast.CNumber(0)),
            c_ast.CNumber(0),
        )
        self.assertEqual(
            and_(self.evaluator, c_ast.CNumber(0), c_ast.CNumber(1)),
            c_ast.CNumber(0),
        )
        self.assertEqual(
            and_(self.evaluator, c_ast.CNumber(0), c_ast.CNumber(0)),
            c_ast.CNumber(0),
        )

    def test_logical_or(self):
        or_ = self.functions['||']
        self.assertEqual(
            or_(self.evaluator, c_ast.CNumber(1), c_ast.CNumber(1)),
            c_ast.CNumber(1),
        )
        self.assertEqual(
            or_(self.evaluator, c_ast.CNumber(1), c_ast.CNumber(0)),
            c_ast.CNumber(1),
        )
        self.assertEqual(
            or_(self.evaluator, c_ast.CNumber(0), c_ast.CNumber(1)),
            c_ast.CNumber(1),
        )
        self.assertEqual(
            or_(self.evaluator, c_ast.CNumber(0), c_ast.CNumber(0)),
            c_ast.CNumber(0),
        )

    def test_ternary_conditional(self):
        actual = self.functions['?:'](
            self.evaluator,
            True,
            c_ast.CNumber(42),
            c_ast.CNumber(33),
        )
        self.assertEqual(actual, c_ast.CNumber(42))
        actual = self.functions['?:'](
            self.evaluator,
            False,
            c_ast.CNumber(42),
            c_ast.CNumber(33),
        )
        self.assertEqual(actual, c_ast.CNumber(33))

    def test_cast(self):
        actual = self.functions[
            '()'](self.evaluator, 'type_name', 'value')
        self.assertEqual(actual, 'value')


if __name__ == '__main__':
    unittest.main()
