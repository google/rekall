from rekall import testlib
from rekall.entities.query import efilter
from rekall.entities.query import expression


class TokenizerTest(testlib.RekallBaseUnitTestCase):
    def assertQueryMatches(self, query, expected):
        tokenizer = efilter.Tokenizer(query)
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
        query = "20 is not 10"
        expected = [
            ("literal", 20),
            ("infix", "is not"),
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
        query = "1 in (5, 10) == Process/pid"
        tokenizer = efilter.Tokenizer(query)
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


class ParserTest(testlib.RekallBaseUnitTestCase):
    def assertQueryMatches(self, query, expected, params=None):
        parser = efilter.Parser(query, params=params)
        actual = parser.parse()
        self.assertEqual(expected, actual)

    def assertQueryRaises(self, query, params=None):
        parser = efilter.Parser(query, params=params)
        self.assertRaises(efilter.ParseError, parser.parse)

    def testLiterals(self):
        query = "0xff"
        expected = expression.Literal(255)
        self.assertQueryMatches(query, expected)

    def testEquivalence(self):
        query = "10 is 10"
        expected = expression.Equivalence(
            expression.Literal(10),
            expression.Literal(10))
        self.assertQueryMatches(query, expected)

    def testPrecedence(self):
        query = "5 == 1 * 5 and Process/name is 'init'"
        expected = expression.Intersection(
            expression.Equivalence(
                expression.Literal(5),
                expression.Product(
                    expression.Literal(1),
                    expression.Literal(5))),
            expression.Equivalence(
                expression.Binding("Process/name"),
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
        query = "Process/parent->Process/command is 'init'"
        expected = expression.Let(
            expression.Binding("Process/parent"),
            expression.Equivalence(
                expression.Binding("Process/command"),
                expression.Literal("init")))

        self.assertQueryMatches(query, expected)

    def testLetSubexpr(self):
        query = ("Process/parent matches (Process/command is 'init' and "
                 "Process/pid is 1)")
        expected = expression.Let(
            expression.Binding("Process/parent"),
            expression.Intersection(
                expression.Equivalence(
                    expression.Binding("Process/command"),
                    expression.Literal("init")),
                expression.Equivalence(
                    expression.Binding("Process/pid"),
                    expression.Literal(1))))

        self.assertQueryMatches(query, expected)

    def testLetSingleAny(self):
        query = "any Process/parent->Process/command is 'init'"
        expected = expression.LetAny(
            expression.Binding("Process/parent"),
            expression.Equivalence(
                expression.Binding("Process/command"),
                expression.Literal("init")))

        self.assertQueryMatches(query, expected)

    def testLetSubexprEach(self):
        query = "each Process/children matches Process/command is 'foo'"
        expected = expression.LetEach(
            expression.Binding("Process/children"),
            expression.Equivalence(
                expression.Binding("Process/command"),
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
        query = ("(Process/pid is 1 and Process/command in ('init', 'initd')) "
                 "or any Process/children matches (Process/command not in "
                 "('launchd', 'foo'))")
        expected = expression.Union(
            expression.Intersection(
                expression.Equivalence(
                    expression.Binding("Process/pid"),
                    expression.Literal(1)),
                expression.Membership(
                    expression.Binding("Process/command"),
                    expression.Literal(("init", "initd")))),
            expression.LetAny(
                expression.Binding("Process/children"),
                expression.Complement(
                    expression.Membership(
                        expression.Binding("Process/command"),
                        expression.Literal(("launchd", "foo"))))))

        self.assertQueryMatches(query, expected)

    def testLooseAnyError(self):
        query = "any Process/command is 'init'"
        self.assertQueryRaises(query)

    def testMissingClosingParens(self):
        query = "Process/pid in (1,5"
        self.assertQueryRaises(query)

    def testNestedParens(self):
        query = "Process/pid in ((1,2))"
        expected = expression.Membership(
            expression.Binding("Process/pid"),
            expression.Literal((1, 2)))
        self.assertQueryMatches(query, expected)

    def testHasComponent(self):
        query = "has component Process"
        expected = expression.ComponentLiteral("Process")
        self.assertQueryMatches(query, expected)

    def testTemplateReplacements(self):
        query = "Process/pid == {}"
        params = [1]
        exptected = expression.Equivalence(
            expression.Binding("Process/pid"),
            expression.Literal(1))
        self.assertQueryMatches(query, exptected, params=params)

        query = "Process/pid == {pid}"
        params = {"pid": 1}
        exptected = expression.Equivalence(
            expression.Binding("Process/pid"),
            expression.Literal(1))
        self.assertQueryMatches(query, exptected, params=params)

    def testParamFailures(self):
        query = "{foo} == 1"
        params = ["Process/pid"]
        self.assertQueryRaises(query, params=params)

        # Even fixing the above, the left side should be a literal, not a
        # binding.
        query = "{foo} == 1"
        params = {"foo": "Process/pid"}
        exptected = expression.Equivalence(
            expression.Literal("Process/pid"),
            expression.Literal(1))
        self.assertQueryMatches(query, exptected, params=params)

    def testParenParsing(self):
        # This query should fail on the lose 'name' token:
        query = ("Buffer/purpose is 'zones' and any Buffer/context matches"
                 " (Allocation/zone name is {zone_name})")
        params = dict(zone_name="foo")
        parser = efilter.Parser(query, params=params)
        try:
            parser.parse()
        except efilter.ParseError as e:
            self.assertEqual(e.token.value, 'name')

    def testMultipleLiterals(self):
        query = "Process/binding foo foo bar 15"
        self.assertQueryRaises(query)
