from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import re
import unittest


import mock

from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.parser import expression_parser
from rekall.layout_expert.preprocessing_visitors import macro_expander


class MacroExpanderTest(unittest.TestCase):

  def setUp(self):
    self.expression_parser = expression_parser.expression_parser()
    self.expression_evaluator = mock.MagicMock()
    self.macro_expander = macro_expander.MacroExpander(
        self.expression_parser,
        self.expression_evaluator,
    )

  def test_expand_with_empty_source(self):
    source = ''
    actual = self.macro_expander.expand(source)
    expected = ''
    self.assertEqual(actual, expected)

  def test_expand_with_simple_identifier(self):
    source = 'foo'
    self.expression_evaluator.evaluate.return_value = c_ast.CNumber(42)
    actual = self.macro_expander.expand(source)
    self.expression_evaluator.evaluate.assert_called_with(
        c_ast.CVariable('foo'),
    )
    expected = '42'
    self.assertEqual(actual, expected)

  def test_expand_with_function_call(self):
    source = 'foo(bar, 42)'
    self.expression_evaluator.evaluate.return_value = c_ast.CVariable('baz')
    actual = self.macro_expander.expand(source)
    self.expression_evaluator.evaluate.assert_called_with(
        c_ast.CFunctionCall(
            function_name='foo',
            arguments=[
                c_ast.CVariable('bar'),
                c_ast.CNumber(42),
            ],
        ),
    )
    expected = 'baz'
    self.assertEqual(actual, expected)

  def test_expand_with_binary_operator(self):
    source = 'foo + 42'
    self.expression_evaluator.evaluate.return_value = c_ast.CFunctionCall(
        function_name='+',
        arguments=[
            c_ast.CVariable('bar'),
            c_ast.CNumber(42),
        ]
    )
    actual = self.macro_expander.expand(source)
    self.expression_evaluator.evaluate.assert_called_with(
        c_ast.CFunctionCall(
            function_name='+',
            arguments=[
                c_ast.CVariable('foo'),
                c_ast.CNumber(42),
            ],
        ),
    )
    expected = 'bar + 42'
    self.assertEqual(actual, expected)

  def test_expand_struct_definition(self):
    source = """
        struct s {
          FOO bar;
          BAR(33, 51) *baz[42];
        };
        """
    struct_evaluation = c_ast.CVariable('struct')
    s_evaluation = c_ast.CVariable('s')
    foo_evaluation = c_ast.CVariable('int')
    bar_evaluation = c_ast.CVariable('x')
    bar_of_33_51_baz_42_evaluation = c_ast.CFunctionCall(
        function_name='*',
        arguments=[
            c_ast.CVariable('float'),
            c_ast.CFunctionCall(
                function_name='[]',
                arguments=[
                    c_ast.CVariable('y'),
                    c_ast.CNumber(42),
                ],
            ),
        ],
    )
    self.expression_evaluator.evaluate.side_effect = (
        struct_evaluation,
        s_evaluation,
        foo_evaluation,
        bar_evaluation,
        bar_of_33_51_baz_42_evaluation,
    )
    actual = self.macro_expander.expand(source)
    expected = """
      struct s {
        int x ;
        float * y[42] ;
      };
      """
    self.assertEqual(actual, expected)

  def test_expand_with_typedef_function_pointer(self):
    source = 'typedef void (*foo)(bar);'
    self.expression_evaluator.evaluate.side_effect = (
        'typedef',
        'void',
        'foo',
        '(int)',
    )
    actual = self.macro_expander.expand(source)
    expected = 'typedef void (* foo ) (int) ;'
    self.assertEqual(actual, expected)

  def test_expand_function_declaration(self):
    source = """
        int foo1(int x);
        """
    self.expression_evaluator.evaluate.side_effect = (
        'int',
        'f(int y)',
    )
    actual = self.macro_expander.expand(source)
    expected = 'int f(int y) ;'
    self.assertEqual(actual, expected)

  def test_expand_multiword_macro_parameter(self):
    source = """
        foo(union u)
        """
    self.expression_evaluator.evaluate.side_effect = (
        'f(union u, 42)',
    )
    actual = self.macro_expander.expand(source)
    expected = 'f(union u, 42)'
    self.assertEqual(actual, expected)

  def test_expand_attribute_name(self):
    source = """
        int x __attribute__((foo));
        """
    self.expression_evaluator.evaluate.side_effect = (
        'int',
        'x',
        '__attribute__((packed))',
    )
    actual = self.macro_expander.expand(source)
    expected = 'int x __attribute__((packed)) ;'
    self.assertEqual(actual, expected)

  def test_expand_attribute_argument(self):
    source = """
        int x __attribute__((__aligned__(foo)));
        """
    self.expression_evaluator.evaluate.side_effect = (
        'int',
        'x',
        '__attribute__((__aligned__(32)))',
    )
    actual = self.macro_expander.expand(source)
    expected = 'int x __attribute__((__aligned__(32))) ;'
    self.assertEqual(actual, expected)

  def assertEqual(self, actual, expected):
    normalized_actual = self._normalize_spaces(actual).strip()
    normalized_expected = self._normalize_spaces(expected).strip()
    message = '\n%s\n!=\n%s' % (normalized_actual, normalized_expected)
    super(MacroExpanderTest, self).assertEqual(
        first=normalized_actual,
        second=normalized_expected,
        msg=message,
    )

  def _normalize_spaces(self, string):
    return re.sub(r'\s+', ' ', string)


if __name__ == '__main__':
  unittest.main()
