import unittest

from efilter.frontends.experiments import dotty
from efilter import expression


class TokenizerTest(unittest.TestCase):
    def assertQueryMatches(self, query, expected):
        tokenizer = dotty.Tokenizer(query)
        actual = [(token.name, token.value) for token in tokenizer.parse()]
        self.assertEqual(expected, actual)

    def testLiterals(self):
        queries = [
            ("0xf", [15]),
            ("234.7  15\n ", [234.7, 15]),
            ("  15 0x15 '0x15' ' 52.6'", [15, 21, "0x15", " 52.6"])]

        for query, values in queries:
            expected = [("literal", val) for val in values]
            self.assertQueryMatches(query, expected)

    def testKeywords(self):
        query = "5 + 5 == 10 and 'foo' =~ 'foo'"
        expected = [
            ("literal", 5),
            ("infix", "+"),
            ("literal", 5),
            ("infix", "=="),
            ("literal", 10),
            ("infix", "and"),
            ("literal", "foo"),
            ("infix", "=~"),
            ("literal", "foo")]
        self.assertQueryMatches(query, expected)

    def testWhitespace(self):
        query = "20 not in 10"
        expected = [
            ("literal", 20),
            ("infix", "not in"),
            ("literal", 10)]
        self.assertQueryMatches(query, expected)

    def testLists(self):
        query = "'foo' in ('foo', 'bar')"
        expected = [
            ("literal", "foo"),
            ("infix", "in"),
            ("lparen", "("),
            ("literal", "foo"),
            ("comma", ","),
            ("literal", "bar"),
            ("rparen", ")")]
        self.assertQueryMatches(query, expected)

    def testPeeking(self):
        query = "1 in (5, 10) == ProcessPid"
        tokenizer = dotty.Tokenizer(query)
        tokenizer.next_token()
        self.assertEquals(tokenizer.peek(2).name, "lparen")
        self.assertEquals(tokenizer.current_token.value, 1)
        self.assertEquals(tokenizer.peek(20), None)
        self.assertEquals(tokenizer.current_token.value, 1)
        self.assertEquals(tokenizer.next_token().value, "in")
        self.assertEquals(tokenizer.current_token.value, "in")
        self.assertEquals(tokenizer.next_token().name, "lparen")
        self.assertEquals(tokenizer.next_token().value, 5)
        self.assertEquals(tokenizer.peek().name, "comma")
        self.assertEquals(tokenizer.next_token().name, "comma")
        self.assertEquals(tokenizer.next_token().value, 10)


class ParserTest(unittest.TestCase):
    def assertQueryMatches(self, query, expected, params=None):
        parser = dotty.Parser(query, params=params)
        actual = parser.parse()
        self.assertEqual(expected, actual)

    def assertQueryRaises(self, query, params=None):
        parser = dotty.Parser(query, params=params)
        self.assertRaises(dotty.errors.EfilterParseError, parser.parse)

    def testLiterals(self):
        query = "0xff"
        expected = expression.Literal(255)
        self.assertQueryMatches(query, expected)

    def testDescendQuery(self):
        query = "Process where (name == 'init' and pid == 1)"
        expected = expression.Let(
            expression.Binding("Process"),
            expression.Intersection(
                expression.Equivalence(
                    expression.Binding("name"),
                    expression.Literal("init")
                ),
                expression.Equivalence(
                    expression.Binding("pid"),
                    expression.Literal(1))))
        self.assertQueryMatches(query, expected)

    def testDescendShorthand(self):
        query = "ProcessParent.ProcessParent.ProcessName"
        expected = expression.Let(
            expression.Binding("ProcessParent"),
            expression.Let(
                expression.Binding("ProcessParent"),
                expression.Binding("ProcessName")))
        self.assertQueryMatches(query, expected)

    def testEquivalence(self):
        query = "10 == 10"
        expected = expression.Equivalence(
            expression.Literal(10),
            expression.Literal(10))
        self.assertQueryMatches(query, expected)

    def testPrecedence(self):
        query = "5 == 1 * 5 and ProcessName == 'init'"
        expected = expression.Intersection(
            expression.Equivalence(
                expression.Literal(5),
                expression.Product(
                    expression.Literal(1),
                    expression.Literal(5))),
            expression.Equivalence(
                expression.Binding("ProcessName"),
                expression.Literal("init")))
        self.assertQueryMatches(query, expected)

    def testParensBaseline(self):
        query = "3 + 2 * 5"
        expected = expression.Sum(
            expression.Literal(3),
            expression.Product(
                expression.Literal(2),
                expression.Literal(5)))

        self.assertQueryMatches(query, expected)

    def testParens(self):
        query = "(3 + 2) * 5"
        expected = expression.Product(
            expression.Sum(
                expression.Literal(3),
                expression.Literal(2)),
            expression.Literal(5))

        self.assertQueryMatches(query, expected)

    def testPrefixMinus(self):
        query = "-(5 + 5)"
        expected = expression.Product(
            expression.Literal(-1),
            expression.Sum(
                expression.Literal(5),
                expression.Literal(5)))

        self.assertQueryMatches(query, expected)

    def testPrefixMinusHighPrecedence(self):
        query = "-5 + 5"
        expected = expression.Sum(
            expression.Product(
                expression.Literal(-1),
                expression.Literal(5)),
            expression.Literal(5))

        self.assertQueryMatches(query, expected)

    def testPrefixMinusLowPrecedence(self):
        query = "-5 * 5"
        expected = expression.Product(
            expression.Literal(-1),
            expression.Product(
                expression.Literal(5),
                expression.Literal(5)))

        self.assertQueryMatches(query, expected)

    def testLetSingle(self):
        query = "ProcessParent where ProcessCommand == 'init'"
        expected = expression.Let(
            expression.Binding("ProcessParent"),
            expression.Equivalence(
                expression.Binding("ProcessCommand"),
                expression.Literal("init")))

        self.assertQueryMatches(query, expected)

    def testLetSubexpr(self):
        query = ("ProcessParent where (ProcessCommand == 'init' and "
                 "ProcessPid == 1)")
        expected = expression.Let(
            expression.Binding("ProcessParent"),
            expression.Intersection(
                expression.Equivalence(
                    expression.Binding("ProcessCommand"),
                    expression.Literal("init")),
                expression.Equivalence(
                    expression.Binding("ProcessPid"),
                    expression.Literal(1))))

        self.assertQueryMatches(query, expected)

    def testLetSingleAny(self):
        query = "any ProcessParent where ProcessCommand == 'init'"
        expected = expression.LetAny(
            expression.Binding("ProcessParent"),
            expression.Equivalence(
                expression.Binding("ProcessCommand"),
                expression.Literal("init")))

        self.assertQueryMatches(query, expected)

    def testLetSubexprEach(self):
        query = "each ProcessChildren where ProcessCommand == 'foo'"
        expected = expression.LetEach(
            expression.Binding("ProcessChildren"),
            expression.Equivalence(
                expression.Binding("ProcessCommand"),
                expression.Literal("foo")))

        self.assertQueryMatches(query, expected)

    def testLists(self):
        query = "'foo' in ('foo', 'bar') and 1 not in (5, 2, 3,17)"
        expected = expression.Intersection(
            expression.Membership(
                expression.Literal("foo"),
                expression.Literal(("foo", "bar"))),
            expression.Complement(
                expression.Membership(
                    expression.Literal(1),
                    expression.Literal((5, 2, 3, 17)))))

        self.assertQueryMatches(query, expected)

    def testBigQuery(self):
        query = ("(ProcessPid == 1 and ProcessCommand in ('init', 'initd')) "
                 "or any ProcessChildren where (ProcessCommand not in "
                 "('launchd', 'foo'))")
        expected = expression.Union(
            expression.Intersection(
                expression.Equivalence(
                    expression.Binding("ProcessPid"),
                    expression.Literal(1)),
                expression.Membership(
                    expression.Binding("ProcessCommand"),
                    expression.Literal(("init", "initd")))),
            expression.LetAny(
                expression.Binding("ProcessChildren"),
                expression.Complement(
                    expression.Membership(
                        expression.Binding("ProcessCommand"),
                        expression.Literal(("launchd", "foo"))))))

        self.assertQueryMatches(query, expected)

    def testLooseAnyError(self):
        query = "any ProcessCommand == 'init'"
        self.assertQueryRaises(query)

    def testMissingClosingParens(self):
        query = "ProcessPid in (1,5"
        self.assertQueryRaises(query)

    def testNestedParens(self):
        query = "ProcessPid in ((1,2))"
        expected = expression.Membership(
            expression.Binding("ProcessPid"),
            expression.Literal((1, 2)))
        self.assertQueryMatches(query, expected)

    def testHasComponent(self):
        query = "has component Process"
        expected = expression.ComponentLiteral("Process")
        self.assertQueryMatches(query, expected)

    def testTemplateReplacements(self):
        query = "ProcessPid == {}"
        params = [1]
        exptected = expression.Equivalence(
            expression.Binding("ProcessPid"),
            expression.Literal(1))
        self.assertQueryMatches(query, exptected, params=params)

        query = "ProcessPid == {pid}"
        params = {"pid": 1}
        exptected = expression.Equivalence(
            expression.Binding("ProcessPid"),
            expression.Literal(1))
        self.assertQueryMatches(query, exptected, params=params)

    def testParamFailures(self):
        query = "{foo} == 1"
        params = ["ProcessPid"]
        self.assertQueryRaises(query, params=params)

        # Even fixing the above, the left side should be a literal, not a
        # binding.
        query = "{foo} == 1"
        params = {"foo": "ProcessPid"}
        exptected = expression.Equivalence(
            expression.Literal("ProcessPid"),
            expression.Literal(1))
        self.assertQueryMatches(query, exptected, params=params)

    def testParenParsing(self):
        # This query should fail on the lose 'name' token:
        query = ("BufferPurpose == 'zones' and any BufferContext where"
                 " (AllocationZone name == {zone_name})")
        params = dict(zone_name="foo")
        parser = dotty.Parser(query, params=params)
        try:
            parser.parse()
        except dotty.errors.EfilterParseError as e:
            self.assertEqual(e.token.value, 'name')

    def testMultipleLiterals(self):
        query = "ProcessBinding foo foo bar 15"
        self.assertQueryRaises(query)
