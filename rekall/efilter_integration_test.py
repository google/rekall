from rekall import testlib
from rekall import efilter_protocols

from rekall.entities import definitions

from efilter import query


class EfilterIntegrationTest(testlib.RekallBaseUnitTestCase):
    def setUp(self):
        self.session = self.MakeUserSession({})
        self.profile = self.session.LoadProfile("test/fake_os")
        self.appdelegate = efilter_protocols.RekallDelegate(self.session,
                                                            self.profile)

    def typeQuery(self, source):
        q = query.Query(source, application_delegate=self.appdelegate)
        return q.run_engine("infer_types")

    def hintQuery(self, source, selector):
        q = query.Query(source, application_delegate=self.appdelegate,
                        syntax="slashy")
        return q.run_engine("hinter", selector=selector)

    def testReflection(self):
        # Test that the application delegate provides correct types for
        # entity attributes.
        t = self.typeQuery("Process")
        self.assertEqual(definitions.Process, t)
        t = self.typeQuery("Process->pid")
        self.assertEqual(int, t)

    def testHinting(self):
        hint = self.hintQuery("Process/parent->Process/command == 'init'",
                              selector="Process/parent")
        self.assertEqual(hint, query.Query("Process/command == 'init'",
                                           syntax="slashy"))

    def testCrossComponentHints(self):
        hint = self.hintQuery(
            "MemoryDescriptor/process matches (Process/command == 'Adium')"
            " and 'execute' in MemoryDescriptor/permissions"
            " and 'write' in MemoryDescriptor/permissions",
            selector="MemoryDescriptor/process")
        self.assertEqual(hint, query.Query("Process/command == 'Adium'",
                                           syntax="slashy"))
