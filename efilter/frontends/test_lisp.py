import unittest

from efilter import expression
from efilter.frontends import lisp


class ParserTest(unittest.TestCase):
    def assertQueryMatches(self, query, expected):
        parser = lisp.Parser(query)
        actual = parser.root
        self.assertEqual(expected, actual)

    def testBasic(self):
        self.assertQueryMatches(
            ("==", ("var", "foo"), "bar"),
            expression.Equivalence(
                expression.Binding("foo"),
                expression.Literal("bar")))
