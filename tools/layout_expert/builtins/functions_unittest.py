from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest



from rekall.layout_expert.builtins import functions
from rekall.layout_expert.c_ast import c_ast


class TestGet64BitFunctions(unittest.TestCase):

  def setUp(self):
    self.functions = functions.get_64bit_functions()

  def test_get_type_independent_functions_with_unary_plus(self):
    actual = self.functions['+'](42)
    self.assertEqual(actual, 42)

  def test_get_type_independent_functions_with_binary_plus(self):
    actual = self.functions['+'](3, 4)
    self.assertEqual(actual, 7)

  def test_get_type_independent_functions_with_unary_minus(self):
    actual = self.functions['-'](33)
    self.assertEqual(actual, -33)

  def test_get_type_independent_functions_with_binary_minus(self):
    actual = self.functions['-'](5, 7)
    self.assertEqual(actual, -2)

  def test_get_type_independent_functions_with_logical_negation(self):
    actual = self.functions['!'](True)
    self.assertEqual(actual, False)
    actual = self.functions['!'](False)
    self.assertEqual(actual, True)

  def test_get_type_independent_functions_with_bitwise_negation(self):
    actual = self.functions['~'](42)
    self.assertEqual(actual, -43)

  def test_get_type_independent_functions_with_defined(self):
    defined = self.functions['defined']
    self.assertEqual(defined(33), True)
    self.assertEqual(defined(0), True)
    self.assertEqual(defined(-42), True)
    self.assertEqual(defined(None), False)

  def test_get_type_independent_functions_with_multiplication(self):
    actual = self.functions['*'](5, 7)
    self.assertEqual(actual, 35)

  def test_get_type_independent_functions_with_division(self):
    actual = self.functions['/'](33, 5)
    self.assertEqual(actual, 6)
    actual = self.functions['/'](21, 7)
    self.assertEqual(actual, 3)

  def test_get_type_independent_functions_with_modulo(self):
    actual = self.functions['%'](33, 5)
    self.assertEqual(actual, 3)
    actual = self.functions['%'](21, 7)
    self.assertEqual(actual, 0)

  def test_get_type_independent_functions_with_shift_left(self):
    actual = self.functions['<<'](5, 2)
    self.assertEqual(actual, 20)

  def test_get_type_independent_functions_with_shift_right(self):
    actual = self.functions['>>'](42, 3)
    self.assertEqual(actual, 5)

  def test_get_type_independent_functions_with_less_than(self):
    less_than = self.functions['<']
    self.assertEqual(less_than(4, 5), True)
    self.assertEqual(less_than(5, 4), False)
    self.assertEqual(less_than(4, 4), False)

  def test_get_type_independent_functions_with_greater_than(self):
    greater_than = self.functions['>']
    self.assertEqual(greater_than(4, 5), False)
    self.assertEqual(greater_than(5, 4), True)
    self.assertEqual(greater_than(4, 4), False)

  def test_get_type_independent_functions_with_less_or_equal(self):
    less_or_equal = self.functions['<=']
    self.assertEqual(less_or_equal(4, 5), True)
    self.assertEqual(less_or_equal(5, 4), False)
    self.assertEqual(less_or_equal(4, 4), True)

  def test_get_type_independent_functions_with_greater_or_equal(self):
    greater_or_equal = self.functions['>=']
    self.assertEqual(greater_or_equal(4, 5), False)
    self.assertEqual(greater_or_equal(5, 4), True)
    self.assertEqual(greater_or_equal(4, 4), True)

  def test_get_type_independent_functions_with_equal(self):
    equal = self.functions['==']
    self.assertEqual(equal(4, 5), False)
    self.assertEqual(equal(5, 4), False)
    self.assertEqual(equal(4, 4), True)

  def test_get_type_independent_functions_with_not_equal(self):
    not_equal = self.functions['!=']
    self.assertEqual(not_equal(4, 5), True)
    self.assertEqual(not_equal(5, 4), True)
    self.assertEqual(not_equal(4, 4), False)

  def test_get_type_independent_functions_with_bitwise_and(self):
    actual = self.functions['&'](42, 33)
    self.assertEqual(actual, 32)

  def test_get_type_independent_functions_with_bitwise_xor(self):
    actual = self.functions['^'](42, 33)
    self.assertEqual(actual, 11)

  def test_get_type_independent_functions_with_bitwise_or(self):
    actual = self.functions['|'](42, 24)
    self.assertEqual(actual, 58)

  def test_get_type_independent_functions_with_logical_and(self):
    and_ = self.functions['&&']
    self.assertEqual(and_(True, True), True)
    self.assertEqual(and_(True, False), False)
    self.assertEqual(and_(False, True), False)
    self.assertEqual(and_(False, False), False)

  def test_get_type_independent_functions_with_logical_or(self):
    or_ = self.functions['||']
    self.assertEqual(or_(True, True), True)
    self.assertEqual(or_(True, False), True)
    self.assertEqual(or_(False, True), True)
    self.assertEqual(or_(False, False), False)

  def test_get_type_independent_functions_with_ternary_conditional(self):
    actual = self.functions['?:'](True, 42, 33)
    self.assertEqual(actual, 42)
    actual = self.functions['?:'](False, 42, 33)
    self.assertEqual(actual, 33)

  def test_get_type_independent_functions_with_cast(self):
    actual = self.functions['()']('type_name', 'value')
    self.assertEqual(actual, 'value')


class TestGetPreprocessorFunctions(unittest.TestCase):

  def setUp(self):
    self.preprocessor_functions = functions.get_preprocessor_functions()

  def test_macro_concatenation(self):
    actual = self.preprocessor_functions['##'](
        c_ast.CVariable('foo_'),
        c_ast.CNumber(42),
    )
    self.assertEqual(actual, 'foo_42')


class TestGetPreprocessorAnd64BitFunctions(unittest.TestCase):

  def setUp(self):
    self.preprocessor_and_64bit_functions = (
        functions.get_preprocessor_and_64bit_functions()
    )

  def test_macro_concatenation(self):
    actual = self.preprocessor_and_64bit_functions['##'](
        c_ast.CVariable('foo_'),
        c_ast.CNumber(42),
    )
    self.assertEqual(actual, 'foo_42')

  def test_unary_plus(self):
    actual = self.preprocessor_and_64bit_functions['+'](c_ast.CNumber(42))
    self.assertEqual(actual, c_ast.CNumber(42))

  def test_binary_plus(self):
    actual = self.preprocessor_and_64bit_functions['+'](
        c_ast.CNumber(3),
        c_ast.CNumber(4),
    )
    self.assertEqual(actual, c_ast.CNumber(7))

  def test_unary_minus(self):
    actual = self.preprocessor_and_64bit_functions['-'](c_ast.CNumber(33))
    self.assertEqual(actual, c_ast.CNumber(-33))

  def test_binary_minus(self):
    actual = self.preprocessor_and_64bit_functions['-'](
        c_ast.CNumber(5),
        c_ast.CNumber(7),
    )
    self.assertEqual(actual, c_ast.CNumber(-2))

  def test_logical_negation(self):
    actual = self.preprocessor_and_64bit_functions['!'](c_ast.CNumber(1))
    self.assertEqual(actual, c_ast.CNumber(0))
    actual = self.preprocessor_and_64bit_functions['!'](c_ast.CNumber(0))
    self.assertEqual(actual, c_ast.CNumber(1))

  def test_bitwise_negation(self):
    actual = self.preprocessor_and_64bit_functions['~'](c_ast.CNumber(42))
    self.assertEqual(actual, c_ast.CNumber(-43))

  def test_multiplication(self):
    actual = self.preprocessor_and_64bit_functions['*'](
        c_ast.CNumber(5),
        c_ast.CNumber(7),
    )
    self.assertEqual(actual, c_ast.CNumber(35))

  def test_division(self):
    actual = self.preprocessor_and_64bit_functions['/'](
        c_ast.CNumber(33),
        c_ast.CNumber(5),
    )
    self.assertEqual(actual, c_ast.CNumber(6))
    actual = self.preprocessor_and_64bit_functions['/'](
        c_ast.CNumber(21),
        c_ast.CNumber(7),
    )
    self.assertEqual(actual, c_ast.CNumber(3))

  def test_modulo(self):
    actual = self.preprocessor_and_64bit_functions['%'](
        c_ast.CNumber(33),
        c_ast.CNumber(5),
    )
    self.assertEqual(actual, c_ast.CNumber(3))
    actual = self.preprocessor_and_64bit_functions['%'](
        c_ast.CNumber(21),
        c_ast.CNumber(7),
    )

    self.assertEqual(actual, c_ast.CNumber(0))

  def test_shift_left(self):
    actual = self.preprocessor_and_64bit_functions['<<'](
        c_ast.CNumber(5),
        c_ast.CNumber(2),
    )
    self.assertEqual(actual, c_ast.CNumber(20))

  def test_shift_right(self):
    actual = self.preprocessor_and_64bit_functions['>>'](
        c_ast.CNumber(42),
        c_ast.CNumber(3),
    )
    self.assertEqual(actual, c_ast.CNumber(5))

  def test_less_than(self):
    less_than = self.preprocessor_and_64bit_functions['<']
    self.assertEqual(
        less_than(c_ast.CNumber(4), c_ast.CNumber(5)),
        c_ast.CNumber(1)
    )
    self.assertEqual(
        less_than(c_ast.CNumber(5), c_ast.CNumber(4)),
        c_ast.CNumber(0)
    )
    self.assertEqual(
        less_than(c_ast.CNumber(4), c_ast.CNumber(4)),
        c_ast.CNumber(0)
    )

  def test_greater_than(self):
    greater_than = self.preprocessor_and_64bit_functions['>']
    self.assertEqual(
        greater_than(c_ast.CNumber(4), c_ast.CNumber(5)),
        c_ast.CNumber(0)
    )
    self.assertEqual(
        greater_than(c_ast.CNumber(5), c_ast.CNumber(4)),
        c_ast.CNumber(1)
    )
    self.assertEqual(
        greater_than(c_ast.CNumber(4), c_ast.CNumber(4)),
        c_ast.CNumber(0)
    )

  def test_less_or_equal(self):
    less_or_equal = self.preprocessor_and_64bit_functions['<=']
    self.assertEqual(
        less_or_equal(c_ast.CNumber(4), c_ast.CNumber(5)),
        c_ast.CNumber(1)
    )
    self.assertEqual(
        less_or_equal(c_ast.CNumber(5), c_ast.CNumber(4)),
        c_ast.CNumber(0)
    )
    self.assertEqual(
        less_or_equal(c_ast.CNumber(4), c_ast.CNumber(4)),
        c_ast.CNumber(1)
    )

  def test_greater_or_equal(self):
    greater_or_equal = self.preprocessor_and_64bit_functions['>=']
    self.assertEqual(
        greater_or_equal(c_ast.CNumber(4), c_ast.CNumber(5)),
        c_ast.CNumber(0)
    )
    self.assertEqual(
        greater_or_equal(c_ast.CNumber(5), c_ast.CNumber(4)),
        c_ast.CNumber(1)
    )
    self.assertEqual(
        greater_or_equal(c_ast.CNumber(4), c_ast.CNumber(4)),
        c_ast.CNumber(1)
    )

  def test_equal(self):
    equal = self.preprocessor_and_64bit_functions['==']
    self.assertEqual(
        equal(c_ast.CNumber(4), c_ast.CNumber(5)),
        c_ast.CNumber(0)
    )
    self.assertEqual(
        equal(c_ast.CNumber(5), c_ast.CNumber(4)),
        c_ast.CNumber(0)
    )
    self.assertEqual(
        equal(c_ast.CNumber(4), c_ast.CNumber(4)),
        c_ast.CNumber(1)
    )

  def test_not_equal(self):
    not_equal = self.preprocessor_and_64bit_functions['!=']
    self.assertEqual(
        not_equal(c_ast.CNumber(4), c_ast.CNumber(5)),
        c_ast.CNumber(1)
    )
    self.assertEqual(
        not_equal(c_ast.CNumber(5), c_ast.CNumber(4)),
        c_ast.CNumber(1)
    )
    self.assertEqual(
        not_equal(c_ast.CNumber(4), c_ast.CNumber(4)),
        c_ast.CNumber(0)
    )

  def test_bitwise_and(self):
    actual = self.preprocessor_and_64bit_functions['&'](
        c_ast.CNumber(42),
        c_ast.CNumber(33),
    )
    self.assertEqual(actual, c_ast.CNumber(32))

  def test_bitwise_xor(self):
    actual = self.preprocessor_and_64bit_functions['^'](
        c_ast.CNumber(42),
        c_ast.CNumber(33),
    )
    self.assertEqual(actual, c_ast.CNumber(11))

  def test_bitwise_or(self):
    actual = self.preprocessor_and_64bit_functions['|'](
        c_ast.CNumber(42),
        c_ast.CNumber(24),
    )
    self.assertEqual(actual, c_ast.CNumber(58))

  def test_logical_and(self):
    and_ = self.preprocessor_and_64bit_functions['&&']
    self.assertEqual(
        and_(c_ast.CNumber(1), c_ast.CNumber(1)),
        c_ast.CNumber(1),
    )
    self.assertEqual(
        and_(c_ast.CNumber(1), c_ast.CNumber(0)),
        c_ast.CNumber(0),
    )
    self.assertEqual(
        and_(c_ast.CNumber(0), c_ast.CNumber(1)),
        c_ast.CNumber(0),
    )
    self.assertEqual(
        and_(c_ast.CNumber(0), c_ast.CNumber(0)),
        c_ast.CNumber(0),
    )

  def test_logical_or(self):
    or_ = self.preprocessor_and_64bit_functions['||']
    self.assertEqual(
        or_(c_ast.CNumber(1), c_ast.CNumber(1)),
        c_ast.CNumber(1),
    )
    self.assertEqual(
        or_(c_ast.CNumber(1), c_ast.CNumber(0)),
        c_ast.CNumber(1),
    )
    self.assertEqual(
        or_(c_ast.CNumber(0), c_ast.CNumber(1)),
        c_ast.CNumber(1),
    )
    self.assertEqual(
        or_(c_ast.CNumber(0), c_ast.CNumber(0)),
        c_ast.CNumber(0),
    )

  def test_ternary_conditional(self):
    actual = self.preprocessor_and_64bit_functions['?:'](
        True,
        c_ast.CNumber(42),
        c_ast.CNumber(33),
    )
    self.assertEqual(actual, c_ast.CNumber(42))
    actual = self.preprocessor_and_64bit_functions['?:'](
        False,
        c_ast.CNumber(42),
        c_ast.CNumber(33),
    )
    self.assertEqual(actual, c_ast.CNumber(33))

  def test_cast(self):
    actual = self.preprocessor_and_64bit_functions['()']('type_name', 'value')
    self.assertEqual(actual, 'value')


if __name__ == '__main__':
  unittest.main()
