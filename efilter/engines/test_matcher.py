import unittest

from efilter import query


class MatcherTest(unittest.TestCase):
    def assertQueryMatches(self, source, bindings):
        q = query.Query(source)
        match = q.run_engine("filter", bindings=bindings)
        self.assertIsNotNone(match)

    def testBasic(self):
        q = "Process/pid is 1"
        bindings = {"Process/pid": 1}
        self.assertQueryMatches(q, bindings)

    def testRecursion(self):
        bindings = {"Process/parent": {"Process/pid": 1}}

        q = "Process/parent matches Process/pid is 1"
        self.assertQueryMatches(q, bindings)

        q = ("any Process/parent matches (Process/pid is 1 or "
             "Process/command is 'foo')")
        self.assertQueryMatches(q, bindings)
