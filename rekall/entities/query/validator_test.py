from rekall import testlib

from rekall.entities.query import query as entity_query
from rekall.entities.query import validator


class ValidatorTest(testlib.RekallBaseUnitTestCase):
    def assertQueryRaises(self, query):
        q = entity_query.Query(query)
        self.assertRaises(validator.ValidationError,
                          q.execute, "QueryValidator")

    def assertQueryPasses(self, query):
        q = entity_query.Query(query)
        try:
            q.execute("QueryValidator")
        except validator.ValidationError as e:
            self.fail("%s raised exception on validation:\n%s" % (q, e))

    def testBasicTypes(self):
        query = "Process/pid == 'foo'"
        self.assertQueryRaises(query)
        query = "Process/pid == 1"
        self.assertQueryPasses(query)

    def testListTypes(self):
        query = "Process/pid in (1, 2, 3)"
        self.assertQueryPasses(query)
        query = "Process/pid in 'foobar'"
        self.assertQueryRaises(query)

    def testAttributeTrouble(self):
        query = "Process/pid == 1 and Process/command_typo == 'foo'"
        self.assertQueryRaises(query)
        query = "Process/pid == 1 and Process/command == 'foo'"
        self.assertQueryPasses(query)

    def testUnquoted(self):
        query = "Process/command is foo"
        self.assertQueryRaises(query)

        query = "Process/command is Process"
        self.assertQueryRaises(query)

        query = "Process/command is 'Process'"
        self.assertQueryPasses(query)
