import logging
import unittest

from rekall.entities.query import analyzer
from rekall.entities.query import query as entity_query


class AnalyzerTest(unittest.TestCase):
    def analyze(self, query):
        return entity_query.Query(query).execute("QueryAnalyzer")

    def assertDepends(self, query, inclusions, exclusions=(), omissions=()):
        analysis = self.analyze(query)
        include = analysis.include
        exclude = analysis.exclude

        for dep in inclusions:
            dependency = analyzer.SimpleDependency.parse(dep)
            self.assertNotIn(dependency.inverted(), exclude)
            self.assertIn(dependency, include)

        for dep in exclusions:
            dependency = analyzer.SimpleDependency.parse(dep)
            self.assertNotIn(dependency, include)
            self.assertIn(dependency.inverted(), exclude)

        for dep in omissions:
            dependency = analyzer.SimpleDependency.parse(dep)
            self.assertNotIn(dependency, include)
            self.assertNotIn(dependency.inverted(), exclude)

    def testBasicDeps(self):
        query = "Process/command is 'foobar'"
        self.assertDepends(query, ["Process/command=foobar"], [], ["Process"])

    def testExclusions(self):
        query = "MemoryObject/type is not socket"
        self.assertDepends(query, ["MemoryObject"],
                           ["MemoryObject/type=socket"])

    def testMutuallyExclusive(self):
        query = ("MemoryObject/type is socket and "
                 "MemoryObject/type is not socket")
        self.assertDepends(query, ["MemoryObject"], [],
                           ["MemoryObject/type=socket"])

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
