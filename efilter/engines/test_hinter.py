import unittest

from efilter import query


class HinterTest(unittest.TestCase):
    def parseQuery(self, source, syntax="dotty"):
        return query.Query(source, syntax=syntax)

    def assertHinted(self, source, selector, expected, syntax="dotty"):
        hinted = self.parseQuery(source).run_engine("hinter",
                                                    selector=selector,
                                                    syntax=syntax)
        baseline = self.parseQuery(expected)
        self.assertEqual(hinted, baseline)

    def testNop(self):
        self.assertHinted("Process.name == 'init'", None,
                          "Process.name == 'init'")

    def testBasic(self):
        self.assertHinted("Process.name == 'init'", "Process",
                          "name == 'init'")

    def testMulti(self):
        self.assertHinted("Process.parent.Process.name == 'init'",
                          "Process.parent",
                          "Process.name == 'init'")

    def testNested(self):
        self.assertHinted("Process.parent.Process.name == 'init' "
                          "and Process.pid > 10",
                          "Process.parent",
                          "Process.name == 'init'")

    def testAndNested(self):
        self.assertHinted("Process.parent.Process.name == 'init' "
                          "and Process.parent.Process.pid > 10",
                          "Process.parent",
                          "Process.name == 'init' and Process.pid > 10")

    def testNestedWithComplement(self):
        self.assertHinted("Process.parent.Process.name != 'init' "
                          "and not Process.parent.Process.pid > 10",
                          "Process.parent",
                          "Process.name != 'init' and not Process.pid > 10")

    def testLegacy(self):
        self.assertHinted(
            "MemoryDescriptor.process where (Process.command == 'Adium')"
            " and 'execute' in MemoryDescriptor.permissions"
            " and 'write' in MemoryDescriptor.permissions",
            "MemoryDescriptor.process",
            "Process.command == 'Adium'")
