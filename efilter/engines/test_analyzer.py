import unittest

from efilter import query


class RuleAnalyzerTest(unittest.TestCase):
    def analyzeQuery(self, source):
        q = query.Query(source, syntax="dotty")
        return q.run_engine("analyzer")

    def analyzeLegacyQuery(self, source):
        q = query.Query(source, syntax="dotty")
        return q.run_engine("analyzer")

    def testBasic(self):
        analysis = self.analyzeQuery("ProcessName == 'init'")
        self.assertIn("ProcessName", analysis.symbols)

    def testMembership(self):
        analysis = self.analyzeQuery("ProcessName in ('init', 'launchd')")
        self.assertIn("ProcessName", analysis.symbols)
        self.assertIn("ProcessName", analysis.eq_indexables)

    def testScoped(self):
        analysis = self.analyzeQuery("Process.name == 'foo'")
        self.assertIn("Process", analysis.symbols)
        self.assertIn("Process.name", analysis.symbols)
        self.assertIn("Process.name", analysis.eq_indexables)

    def testNested(self):
        analysis = self.analyzeQuery(
            "Process.parent matches (Process.name == 'init')")
        self.assertIn("Process.parent", analysis.symbols)
        self.assertIn("Process.name", analysis.symbols)
