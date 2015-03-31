from rekall import testlib

from rekall.entities.query import analyzer
from rekall.entities.query import query as entity_query


class AnalyzerTest(testlib.RekallBaseUnitTestCase):
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
        query = "Struct/type is not 'socket'"
        self.assertDepends(query, ["Struct"],
                           ["Struct/type=socket"])

    def testMutuallyExclusive(self):
        query = ("Struct/type is 'socket' and "
                 "Struct/type is not 'socket'")
        self.assertDepends(query, ["Struct"], [],
                           ["Struct/type=socket"])
