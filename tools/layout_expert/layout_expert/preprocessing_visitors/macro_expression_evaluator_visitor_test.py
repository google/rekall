from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

# pylint: disable=eval-used
import sys
sys.setrecursionlimit(25000)

import unittest

from layout_expert.c_ast import c_ast_test
from layout_expert.c_ast import pre_ast
from layout_expert.parsers import expression_parser
from layout_expert.preprocessing_visitors import macro_expander
from layout_expert.preprocessing_parser import preprocessing_parser
from layout_expert.preprocessing_visitors import macro_expression_evaluator_visitor


class MacroExpressionEvaluatorVisitorTest(c_ast_test.CASTTestCase):

    def setUp(self):
        self.macros = preprocessing_parser.Macros(config_flags={})
        self.macro_expander = macro_expander.MacroParser(self.macros)
        self.expression_parser = expression_parser.ExpressionParser()
        self.expression_evaluator = (
            macro_expression_evaluator_visitor.MacroExpressionEvaluatorVisitor(
                self.macros))

    def test_evaluation(self):
        expressions = [
            ("( 4 * 10000 +  8 *  100 +  4 )", (4 * 10000 + 8 * 100 + 4)),
            ("((((1000000000L <<  2) /  ("
             "(1000000000L + 250 / 2 ) / 250 ) ) <<  ( ( 31 -  8 ) -  2 ))"
             "&  0x80000000 )",
             ((int((1000000000L << 2) / (
                 (1000000000L + 250 / 2) / 250)) << int((31 - 8) - 2))
              & 0x80000000)
             ),
            ("(((32768) +(~(~(((1UL) <<12) -1)))) &~(~(~(((1UL) <<12) -1))))",
             (((32768) + (~(~(((1L) << 12) - 1)))) & ~(~(~(((1L) << 12) - 1)))))
        ]
        for expression, expected in expressions:
            expression_ast = self.expression_parser.parse(expression)
            result = self.expression_evaluator.evaluate(expression_ast)
            self.assertEqual(result, expected)

    def test_shortcut_operations(self):
        code = ("defined _FILE_OFFSET_BITS && _FILE_OFFSET_BITS == 64")
        actual = self.macro_expander.expand(code)
        expected = "_FILE_OFFSET_BITS&&_FILE_OFFSET_BITS==64"
        self.assertEqualWhitespace(actual, expected)

        # Because _FILE_OFFSET_BITS is not defined, we will evaluate it to 0
        expression_ast = self.expression_parser.parse(expected)
        result = self.expression_evaluator.evaluate(expression_ast)
        self.assertEqual(result, 0)

    def test_ternary_operations(self):
        self.macros.add_object_likes(
            __BYTE_ORDER=pre_ast.DefineObjectLike(
                name="__BYTE_ORDER", replacement="2"
            ))

        expressions = [
            ("defined(__BYTE_ORDER) ? __BYTE_ORDER == 20 : 1", 0),
            ("defined(__BYTE_ORDER) ? __BYTE_ORDER == 2 : 0", 1),
            ("!defined(__BYTE_ORDER) ? __BYTE_ORDER == 2 : 0", 0),
        ]

        for code, expected in expressions:
            actual = self.macro_expander.expand(code)
            expression_ast = self.expression_parser.parse(actual)
            result = self.expression_evaluator.evaluate(expression_ast)
            self.assertEqual(result, expected)


if __name__ == '__main__':
    unittest.main()
