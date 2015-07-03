from efilter import testlib


class HinterTest(testlib.EngineTestCase):
    def testNop(self):
        self.assertTransform(
            engine="hinter",
            original="Process.name == 'init'",
            expected="Process.name == 'init'",
            selector=None)

    def testBasic(self):
        self.assertTransform(
            engine="hinter",
            original="Process.name == 'init'",
            expected="name == 'init'",
            selector="Process")

    def testMulti(self):
        self.assertTransform(
            engine="hinter",
            original="Process.parent.Process.name == 'init'",
            selector="Process.parent",
            expected="Process.name == 'init'")

    def testNested(self):
        self.assertTransform(
            engine="hinter",
            original=("Process.parent.Process.name == 'init' "
                      "and Process.pid > 10"),
            selector="Process.parent",
            expected="Process.name == 'init'")

    def testAndNested(self):
        self.assertTransform(
            engine="hinter",
            original=("Process.parent.Process.name == 'init' "
                      "and Process.parent.Process.pid > 10"),
            selector="Process.parent",
            expected="Process.name == 'init' and Process.pid > 10")

    def testNestedWithComplement(self):
        self.assertTransform(
            engine="hinter",
            original=("Process.parent.Process.name != 'init' "
                      "and not Process.parent.Process.pid > 10"),
            selector="Process.parent",
            expected="Process.name != 'init' and not Process.pid > 10")

    def testLegacy(self):
        self.assertTransform(
            engine="hinter",
            original=("MemoryDescriptor.process where "
                      "(Process.command == 'Adium') "
                      "and 'execute' in MemoryDescriptor.permissions "
                      "and 'write' in MemoryDescriptor.permissions"),
            selector="MemoryDescriptor.process",
            expected="Process.command == 'Adium'")
