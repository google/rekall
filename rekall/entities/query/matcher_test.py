from rekall import testlib

from rekall.entities.query import query as entity_query


class MatcherTest(testlib.RekallBaseUnitTestCase):
    def assertQueryMatches(self, query, bindings):
        m = entity_query.Query(query).execute("QueryMatcher", "match",
                                              bindings=bindings)
        self.assertIsNotNone(m)

    def testBasic(self):
        query = "Process/pid is 1"
        bindings = {"Process/pid": 1}
        self.assertQueryMatches(query, bindings)

    def testRecursion(self):
        bindings = {"Process/parent": {"Process/pid": 1}}

        query = "Process/parent matches Process/pid is 1"
        self.assertQueryMatches(query, bindings)

        query = ("any Process/parent matches (Process/pid is 1 or "
                 "Process/command is 'foo')")
        self.assertQueryMatches(query, bindings)
