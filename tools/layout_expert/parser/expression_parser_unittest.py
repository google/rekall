from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys
import unittest

import pyparsing

from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.c_ast import pre_ast
from rekall.layout_expert.parser import expression_parser


sys.setrecursionlimit(10000)


class TestExpressionParser(unittest.TestCase):
  """Test class for the expression_parser() method.

  Note that the operator precedence is tested only partially since it is
  provided by the external pyparsing.infixNotation(...) function.
  """

  def setUp(self):
    self.parser = expression_parser.expression_parser()
    self.unary_operators = '+', '-', '!', '~'
    self.binary_operators = (
        '##',
        '*', '/', '%',
        '+', '-',
        '<<', '>>',
        '<', '<=', '>', '>=',
        '==', '!=',
        '&',
        '^',
        '|',
        '&&',
        '||',
    )

  def test_parse_zero(self):
    source = '0'
    expected = c_ast.CNumber(0)
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_positive_integer(self):
    source = '42'
    expected = c_ast.CNumber(42)
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_negative_integer(self):
    source = '-33'
    expected = c_ast.CFunctionCall(
        function_name='-',
        arguments=[c_ast.CNumber(33)],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_hex_integer(self):
    source = '0xaf72'
    expected = c_ast.CNumber(44914)
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_hex_integer_without_letters_as_digits(self):
    source = '0x4233'
    expected = c_ast.CNumber(16947)
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_negative_hex_integer(self):
    source = '-0xabcd'
    expected = c_ast.CFunctionCall(
        function_name='-',
        arguments=[c_ast.CNumber(43981)],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_zero_with_suffix(self):
    source = '0u'
    expected = c_ast.CNumber(0)
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_positive_integer_with_suffix(self):
    source = '314U'
    expected = c_ast.CNumber(314)
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_negative_integer_with_suffix(self):
    source = '-272l'
    expected = c_ast.CFunctionCall(
        function_name='-',
        arguments=[c_ast.CNumber(272)],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_hex_integer_with_suffix(self):
    source = '0xaf72L'
    expected = c_ast.CNumber(44914)
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_hex_integer_without_letters_as_digits_with_suffix(self):
    source = '0x4233ll'
    expected = c_ast.CNumber(16947)
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_negative_hex_integer_with_suffix(self):
    source = '-0xdcbaLL'
    expected = c_ast.CFunctionCall(
        function_name='-',
        arguments=[c_ast.CNumber(56506)],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_hex_integer_with_two_suffixes(self):
    source = '0xaf72UL'
    expected = c_ast.CNumber(44914)
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_usigned_long_long_literal(self):
    source = '2357ull'
    expected = c_ast.CNumber(2357)
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_variable(self):
    source = 'CONFIG_SOMETHING'
    expected = c_ast.CVariable('CONFIG_SOMETHING')
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_number_in_parentheses(self):
    source = '(42)'
    expected = c_ast.CNestedExpression(
        opener='(',
        content=c_ast.CNumber(42),
        closer=')',
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_variable_in_parentheses(self):
    source = '(x)'
    expected = c_ast.CNestedExpression(
        opener='(',
        content=c_ast.CVariable('x'),
        closer=')',
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_unary_operator_and_parentheses(self):
    source = '-(33)'
    expected = c_ast.CFunctionCall(
        function_name='-',
        arguments=[
            c_ast.CNestedExpression(
                opener='(',
                content=c_ast.CNumber(33),
                closer=')',
            ),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_function_call_with_no_arguments(self):
    source = 'f()'
    expected = c_ast.CFunctionCall(
        function_name='f',
        arguments=[],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_function_call_with_one_argument(self):
    source = 'f(a)'
    expected = c_ast.CFunctionCall(
        function_name='f',
        arguments=[c_ast.CVariable('a')],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_function_call_with_multiword_argument(self):
    source = 'f(union u)'
    expected = c_ast.CFunctionCall(
        function_name='f',
        arguments=[
            pre_ast.CompositeBlock([
                c_ast.CVariable('union'),
                c_ast.CVariable('u'),
            ]),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_function_call_with_argument_with_dots(self):
    source = 'f(.init.text)'
    expected = c_ast.CFunctionCall(
        function_name='f',
        arguments=[
            c_ast.CLiteral('.init.text'),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_function_call_with_two_arguments(self):
    source = 'f(a, 42)'
    expected = c_ast.CFunctionCall(
        function_name='f',
        arguments=[
            c_ast.CVariable('a'),
            c_ast.CNumber(42),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_function_call_with_five_arguments(self):
    source = 'f(2, 3, 5, 7, 11)'
    expected = c_ast.CFunctionCall(
        function_name='f',
        arguments=[
            c_ast.CNumber(2),
            c_ast.CNumber(3),
            c_ast.CNumber(5),
            c_ast.CNumber(7),
            c_ast.CNumber(11),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_attribute(self):
    source = '__attribute__((x))'
    expected = c_ast.CFunctionCall(
        function_name='__attribute__',
        arguments=[
            c_ast.CNestedExpression(
                opener='(',
                content=c_ast.CVariable('x'),
                closer=')',
            ),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_defined(self):
    source = 'defined CONFIG_SOMETHING'
    expected = c_ast.CFunctionCall(
        function_name='defined',
        arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_not_defined(self):
    source = '!defined CONFIG_SOMETHING'
    expected = c_ast.CFunctionCall(
        function_name='!',
        arguments=[
            c_ast.CFunctionCall(
                function_name='defined',
                arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
            ),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_defined_with_parentheses(self):
    source = 'defined (CONFIG_SOMETHING)'
    expected = c_ast.CFunctionCall(
        function_name='defined',
        arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_not_defined_with_parentheses(self):
    source = '!defined (CONFIG_SOMETHING)'
    expected = c_ast.CFunctionCall(
        function_name='!',
        arguments=[
            c_ast.CFunctionCall(
                function_name='defined',
                arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
            ),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_defined_function_like(self):
    source = 'defined(CONFIG_SOMETHING)'
    expected = c_ast.CFunctionCall(
        function_name='defined',
        arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_not_defined_function_like(self):
    source = '!defined(CONFIG_SOMETHING)'
    expected = c_ast.CFunctionCall(
        function_name='!',
        arguments=[
            c_ast.CFunctionCall(
                function_name='defined',
                arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
            ),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_cast_expression(self):
    source = '(int) x'
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CFunctionCall(
        function_name='()',
        arguments=[
            c_ast.CLiteral('int'),
            c_ast.CVariable('x'),
        ],
    )
    self.assertEqual(actual.asList(), [expected])

  def test_parse_cast_to_typeof_expression(self):
    source = '(typeof(32)) x'
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CFunctionCall(
        function_name='()',
        arguments=[
            c_ast.CLiteral('typeof(32)'),
            c_ast.CVariable('x'),
        ],
    )
    self.assertEqual(actual.asList(), [expected])

  def test_parse_cast_to_pointer_with_space(self):
    source = '(int *) x'
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CFunctionCall(
        function_name='()',
        arguments=[
            c_ast.CLiteral('int *'),
            c_ast.CVariable('x'),
        ],
    )
    self.assertEqual(actual.asList(), [expected])

  def test_parse_cast_to_pointer_without_space(self):
    source = '(void*) x'
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CFunctionCall(
        function_name='()',
        arguments=[
            c_ast.CLiteral('void*'),
            c_ast.CVariable('x'),
        ],
    )
    self.assertEqual(actual.asList(), [expected])

  def test_parse_cast_expression_without_parentheses(self):
    source = 'int x'
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parseString(source, parseAll=True)

  def test_multiplication_in_parentheses_and_binary_minus(self):
    # This is tricky because it's not a cast and an unary minus.
    # To fully distinguish those cases we would need to know what identifiers
    # are types and what identifiers are variables, e.g.
    #     (x) - y
    # depends on the meaning of x. If x is a type then it can be a cast and
    # an unary minus, if x is a variable then it is a binary minus.
    source = '(a * b) - c'
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CFunctionCall(
        function_name='-',
        arguments=[
            c_ast.CNestedExpression(
                opener='(',
                content=c_ast.CFunctionCall(
                    function_name='*',
                    arguments=[
                        c_ast.CVariable('a'),
                        c_ast.CVariable('b'),
                    ],
                ),
                closer=')'
            ),
            c_ast.CVariable('c'),
        ],
    )
    self.assertEqual(actual.asList(), [expected])

  def test_parse_parentheses_and_binary_plus(self):
    source = '(a) + b'
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CFunctionCall(
        function_name='+',
        arguments=[
            c_ast.CNestedExpression(
                opener='(',
                content=c_ast.CVariable('a'),
                closer=')',
            ),
            c_ast.CVariable('b'),
        ],
    )
    self.assertEqual(actual.asList(), [expected])

  def test_parse_complex_parentheses_expression(self):
    source = '(((x) + (y)) & ~(y))'
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CNestedExpression(
        opener='(',
        content=c_ast.CFunctionCall(
            function_name='&',
            arguments=[
                c_ast.CNestedExpression(
                    opener='(',
                    content=c_ast.CFunctionCall(
                        function_name='+',
                        arguments=[
                            c_ast.CNestedExpression(
                                opener='(',
                                content=c_ast.CVariable('x'),
                                closer=')',
                            ),
                            c_ast.CNestedExpression(
                                opener='(',
                                content=c_ast.CVariable('y'),
                                closer=')',
                            ),
                        ],
                    ),
                    closer=')',
                ),
                c_ast.CFunctionCall(
                    function_name='~',
                    arguments=[
                        c_ast.CNestedExpression(
                            opener='(',
                            content=c_ast.CVariable('y'),
                            closer=')',
                        ),
                    ],
                ),
            ],
        ),
        closer=')',
    )
    self.assertEqual(actual.asList(), [expected])

  def test_parse_array_expression(self):
    source = 't[x]'
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CFunctionCall(
        function_name='[]',
        arguments=[
            c_ast.CVariable('t'),
            c_ast.CVariable('x'),
        ],
    )
    self.assertEqual(actual.asList(), [expected])

  def test_parse_multidimensional_array_expression(self):
    source = 't[x][y]'
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CFunctionCall(
        function_name='[]',
        arguments=[
            c_ast.CFunctionCall(
                function_name='[]',
                arguments=[
                    c_ast.CVariable('t'),
                    c_ast.CVariable('x'),
                ],
            ),
            c_ast.CVariable('y'),
        ],
    )
    self.assertEqual(actual.asList(), [expected])

  def test_parse_unary_operator_with_number(self):
    for unary_operator in self.unary_operators:
      source = unary_operator + '33'
      actual = self.parser.parseString(source, parseAll=True)[0]
      expected = c_ast.CFunctionCall(
          function_name=unary_operator,
          arguments=[c_ast.CNumber(33)],
      )
      self.assertEqual(actual, expected)

  def test_parse_unary_operator_with_variable(self):
    for unary_operator in self.unary_operators:
      source = unary_operator + 'CONFIG_SOMETHING'
      actual = self.parser.parseString(source, parseAll=True)[0]
      expected = c_ast.CFunctionCall(
          function_name=unary_operator,
          arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
      )
      self.assertEqual(actual, expected)

  def test_parse_binary_operator_with_number_and_variable(self):
    for binary_operator in self.binary_operators:
      source = 'CONFIG_SOMETHING' + binary_operator + '42'
      actual = self.parser.parseString(source, parseAll=True)[0]
      expected = c_ast.CFunctionCall(
          function_name=binary_operator,
          arguments=[
              c_ast.CVariable('CONFIG_SOMETHING'),
              c_ast.CNumber(42),
          ]
      )
      self.assertEqual(actual, expected)

  def test_parse_binary_operator_with_variable_and_number(self):
    for binary_operator in self.binary_operators:
      source = '51' + binary_operator + 'CONFIG_SOMETHING'
      actual = self.parser.parseString(source, parseAll=True)[0]
      expected = c_ast.CFunctionCall(
          function_name=binary_operator,
          arguments=[
              c_ast.CNumber(51),
              c_ast.CVariable('CONFIG_SOMETHING'),
          ]
      )
      self.assertEqual(actual, expected)

  def test_parse_binary_operator_with_function_calls(self):
    source = 'defined(CONFIG_SOMETHING) && defined(CONFIG_SOMETHING_ELSE)'
    expected = c_ast.CFunctionCall(
        function_name='&&',
        arguments=[
            c_ast.CFunctionCall(
                function_name='defined',
                arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
            ),
            c_ast.CFunctionCall(
                function_name='defined',
                arguments=[c_ast.CVariable('CONFIG_SOMETHING_ELSE')],
            ),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_ternary_conditional(self):
    source = 'a ? b : c'
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CFunctionCall(
        function_name='?:',
        arguments=[
            c_ast.CVariable('a'),
            c_ast.CVariable('b'),
            c_ast.CVariable('c'),
        ],
    )
    self.assertEqual(actual.asList(), [expected])

  def test_parse_same_precedence_operators_plus_and_minus(self):
    source = 'a + b - c'
    expected = c_ast.CFunctionCall(
        function_name='-',
        arguments=[
            c_ast.CFunctionCall(
                function_name='+',
                arguments=[
                    c_ast.CVariable('a'),
                    c_ast.CVariable('b'),
                ],
            ),
            c_ast.CVariable('c'),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_same_precedence_operators_minus_and_plus(self):
    source = 'a - b + c'
    expected = c_ast.CFunctionCall(
        function_name='+',
        arguments=[
            c_ast.CFunctionCall(
                function_name='-',
                arguments=[
                    c_ast.CVariable('a'),
                    c_ast.CVariable('b'),
                ],
            ),
            c_ast.CVariable('c'),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_same_precedence_operators_plus_and_plus(self):
    source = 'a + b + c'
    expected = c_ast.CFunctionCall(
        function_name='+',
        arguments=[
            c_ast.CFunctionCall(
                function_name='+',
                arguments=[
                    c_ast.CVariable('a'),
                    c_ast.CVariable('b'),
                ],
            ),
            c_ast.CVariable('c'),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_addition_and_multiplication_precedence(self):
    source = 'a + b * c'
    expected = c_ast.CFunctionCall(
        function_name='+',
        arguments=[
            c_ast.CVariable('a'),
            c_ast.CFunctionCall(
                function_name='*',
                arguments=[
                    c_ast.CVariable('b'),
                    c_ast.CVariable('c'),
                ]
            )
        ]
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_parentheses_with_addition_and_multiplication(self):
    source = '(a + b) * c'
    expected = c_ast.CFunctionCall(
        function_name='*',
        arguments=[
            c_ast.CNestedExpression(
                opener='(',
                content=
                c_ast.CFunctionCall(
                    function_name='+',
                    arguments=[
                        c_ast.CVariable('a'),
                        c_ast.CVariable('b'),
                    ],
                ),
                closer=')',
            ),
            c_ast.CVariable('c'),
        ]
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_binary_operators_with_parentheses_on_left(self):
    source = '(x == 4 && y >= 3) || y > 4'
    expected = c_ast.CFunctionCall(
        function_name='||',
        arguments=[
            c_ast.CNestedExpression(
                opener='(',
                content=c_ast.CFunctionCall(
                    function_name='&&',
                    arguments=[
                        c_ast.CFunctionCall(
                            function_name='==',
                            arguments=[
                                c_ast.CVariable('x'),
                                c_ast.CNumber(4),
                            ],
                        ),
                        c_ast.CFunctionCall(
                            function_name='>=',
                            arguments=[
                                c_ast.CVariable('y'),
                                c_ast.CNumber(3),
                            ]
                        ),
                    ],
                ),
                closer=')',
            ),
            c_ast.CFunctionCall(
                function_name='>',
                arguments=[
                    c_ast.CVariable('y'),
                    c_ast.CNumber(4),
                ],
            ),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_comparison_and_shift_with_parentheses_on_right(self):
    source = 'x < (1 << 14)'
    expected = c_ast.CFunctionCall(
        function_name='<',
        arguments=[
            c_ast.CVariable('x'),
            c_ast.CNestedExpression(
                opener='(',
                content=c_ast.CFunctionCall(
                    function_name='<<',
                    arguments=[
                        c_ast.CNumber(1),
                        c_ast.CNumber(14),
                    ]
                ),
                closer=')',
            ),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_binary_operators_with_parentheses_on_right(self):
    source = 'x < 4 || (y == 4 && z < 1)'
    expected = c_ast.CFunctionCall(
        function_name='||',
        arguments=[
            c_ast.CFunctionCall(
                function_name='<',
                arguments=[
                    c_ast.CVariable('x'),
                    c_ast.CNumber(4),
                ],
            ),
            c_ast.CNestedExpression(
                opener='(',
                content=c_ast.CFunctionCall(
                    function_name='&&',
                    arguments=[
                        c_ast.CFunctionCall(
                            function_name='==',
                            arguments=[
                                c_ast.CVariable('y'),
                                c_ast.CNumber(4),
                            ],
                        ),
                        c_ast.CFunctionCall(
                            function_name='<',
                            arguments=[
                                c_ast.CVariable('z'),
                                c_ast.CNumber(1),
                            ],
                        ),
                    ],
                ),
                closer=')',
            ),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_logical_or_and_negation(self):
    source = 'someFunction(a) || !defined(b) || c < 2'
    expected = c_ast.CFunctionCall(
        function_name='||',
        arguments=[
            c_ast.CFunctionCall(
                function_name='||',
                arguments=[
                    c_ast.CFunctionCall(
                        function_name='someFunction',
                        arguments=[c_ast.CVariable('a')],
                    ),
                    c_ast.CFunctionCall(
                        function_name='!',
                        arguments=[
                            c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[c_ast.CVariable('b')],
                            )
                        ],
                    ),
                ],
            ),
            c_ast.CFunctionCall(
                function_name='<',
                arguments=[
                    c_ast.CVariable('c'),
                    c_ast.CNumber(2),
                ],
            ),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_unary_operator_on_expression_in_parentheses(self):
    source = '!(x > 0 || y == 0)'
    expected = c_ast.CFunctionCall(
        function_name='!',
        arguments=[
            c_ast.CNestedExpression(
                opener='(',
                content=c_ast.CFunctionCall(
                    function_name='||',
                    arguments=[
                        c_ast.CFunctionCall(
                            function_name='>',
                            arguments=[
                                c_ast.CVariable('x'),
                                c_ast.CNumber(0),
                            ],
                        ),
                        c_ast.CFunctionCall(
                            function_name='==',
                            arguments=[
                                c_ast.CVariable('y'),
                                c_ast.CNumber(0),
                            ],
                        ),
                    ],
                ),
                closer=')',
            ),
        ],
    )
    actual = self.parser.parseString(source, parseAll=True)
    self.assertEqual(actual.asList(), [expected])

  def test_parse_sizeof(self):
    source = 'sizeof(struct s*)'
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CFunctionCall(
        function_name='sizeof',
        arguments=[c_ast.CLiteral('struct s*')],
    )
    self.assertEquals(actual.asList(), [expected])

  def test_parse_sizeof_with_double_underscores_of_array(self):
    source = '__sizeof__(unsigned int[42])'
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CFunctionCall(
        function_name='__sizeof__',
        arguments=[c_ast.CLiteral('unsigned int[42]')],
    )
    self.assertEquals(actual.asList(), [expected])

  def test_parse_alignof_with_double_underscores(self):
    source = '__alignof__(struct s*)'
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CFunctionCall(
        function_name='__alignof__',
        arguments=[c_ast.CLiteral('struct s*')],
    )
    self.assertEquals(actual.asList(), [expected])

  def test_parse_alignof_with_double_underscores_of_array(self):
    source = '__alignof__(unsigned int[42])'
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CFunctionCall(
        function_name='__alignof__',
        arguments=[c_ast.CLiteral('unsigned int[42]')],
    )
    self.assertEquals(actual.asList(), [expected])

  def test_parse_offsetof_expression(self):
    source = '((size_t)&((struct raw_spinlock *)0)->dep_map)'
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CFunctionCall(
        function_name='offsetof',
        arguments=[
            c_ast.CLiteral('struct raw_spinlock'),
            c_ast.CLiteral('dep_map'),
        ],
    )
    self.assertEqual(actual.asList(), [expected])

  def test_parse_offsetof_expression_with_additional_parentheses(self):
    source = '(((size_t)&((struct raw_spinlock *)0)->dep_map))'
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CNestedExpression(
        opener='(',
        content=c_ast.CFunctionCall(
            function_name='offsetof',
            arguments=[
                c_ast.CLiteral('struct raw_spinlock'),
                c_ast.CLiteral('dep_map'),
            ],
        ),
        closer=')',
    )
    self.assertEqual(actual.asList(), [expected])

  def test_parse_sizeof_and_binary_plus_operators_and_additional_parentheses(
      self,
  ):
    source = """
        (
            sizeof(struct ymmh_struct)
            + sizeof(struct lwp_struct)
            + sizeof(struct mpx_struct)
        )
        """
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CNestedExpression(
        opener='(',
        content=c_ast.CFunctionCall(
            function_name='+',
            arguments=[
                c_ast.CFunctionCall(
                    function_name='+',
                    arguments=[
                        c_ast.CFunctionCall(
                            function_name='sizeof',
                            arguments=[c_ast.CLiteral('struct ymmh_struct')],
                        ),
                        c_ast.CFunctionCall(
                            function_name='sizeof',
                            arguments=[c_ast.CLiteral('struct lwp_struct')],
                        ),
                    ],
                ),
                c_ast.CFunctionCall(
                    function_name='sizeof',
                    arguments=[c_ast.CLiteral('struct mpx_struct')],
                ),
            ],
        ),
        closer=')',
    )
    self.assertEqual(actual.asList(), [expected])

  def test_parse_sizeof_and_binary_operators(self):
    source = """
        ((((1 << 0)) + (8 * sizeof(long)) - 1) / (8 * sizeof(long)))
        """
    actual = self.parser.parseString(source, parseAll=True)
    expected = c_ast.CNestedExpression(
        opener='(',
        content=c_ast.CFunctionCall(
            function_name='/',
            arguments=[
                c_ast.CNestedExpression(
                    opener='(',
                    content=c_ast.CFunctionCall(
                        function_name='-',
                        arguments=[
                            c_ast.CFunctionCall(
                                function_name='+',
                                arguments=[
                                    c_ast.CNestedExpression(
                                        opener='(',
                                        content=c_ast.CNestedExpression(
                                            opener='(',
                                            content=c_ast.CFunctionCall(
                                                function_name='<<',
                                                arguments=[
                                                    c_ast.CNumber(1),
                                                    c_ast.CNumber(0),
                                                ],
                                            ),
                                            closer=')',
                                        ),
                                        closer=')',
                                    ),
                                    c_ast.CNestedExpression(
                                        opener='(',
                                        content=c_ast.CFunctionCall(
                                            function_name='*',
                                            arguments=[
                                                c_ast.CNumber(8),
                                                c_ast.CFunctionCall(
                                                    function_name='sizeof',
                                                    arguments=[
                                                        c_ast.CLiteral('long'),
                                                    ],
                                                ),
                                            ],
                                        ),
                                        closer=')',
                                    ),
                                ],
                            ),
                            c_ast.CNumber(1),
                        ],
                    ),
                    closer=')',
                ),
                c_ast.CNestedExpression(
                    opener='(',
                    content=c_ast.CFunctionCall(
                        function_name='*',
                        arguments=[
                            c_ast.CNumber(8),
                            c_ast.CFunctionCall(
                                function_name='sizeof',
                                arguments=[c_ast.CLiteral('long')],
                            ),
                        ],
                    ),
                    closer=')',
                ),
            ],
        ),
        closer=')',
    )
    self.assertEqual(actual.asList(), [expected])

  def assertEqual(self, actual, expected):
    message = '\n%s\n!=\n%s' % (actual, expected)
    super(TestExpressionParser, self).assertEqual(actual, expected, message)

if __name__ == '__main__':
  unittest.main()
