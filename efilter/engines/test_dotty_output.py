import unittest

from efilter import query


class DottyOutputTest(unittest.TestCase):
    def assertOutput(self, original, output):
        q = query.Query(original, syntax="dotty")
        actual_output = q.run_engine("dotty_output")
        self.assertEqual(output, actual_output)

    def testBasic(self):
        self.assertOutput(original="5 + 5 == 10",
                          output="5 + 5 == 10")

    def testSimpleLet(self):
        self.assertOutput(original="Process.name == 'foo'",
                          output="Process.name == 'foo'")

    def testWhere(self):
        self.assertOutput(
            original="Process.parent where (name == 'foo' and pid == 5)",
            output="Process.parent where (name == 'foo' and pid == 5)")

    def testAnywhere(self):
        self.assertOutput(
            original="any Process.parent where (name == 'foo')",
            output="any Process.parent where (name == 'foo')")
