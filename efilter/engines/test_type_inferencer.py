import unittest

from efilter import protocol
from efilter import query

from efilter.protocols import boolean
from efilter.protocols import number
from efilter.protocols import name_delegate


class FakeApplicationDelegate(object):
    NAMES = {
        "ProcessName": basestring,
        "ProcessPid": int}

    def reflect(self, name, scope=None):
        _ = scope
        return self.NAMES.get(name)

    def provide(self, name):
        pass

    def getnames(self):
        return self.NAMES.iterkeys()


name_delegate.INameDelegate.implement(
    for_type=FakeApplicationDelegate,
    implementations={
        name_delegate.reflect: FakeApplicationDelegate.reflect,
        name_delegate.provide: FakeApplicationDelegate.provide,
        name_delegate.getnames: FakeApplicationDelegate.getnames
    }
)


class TypeInferenceTest(unittest.TestCase):
    def analyzeQuery(self, source):
        q = query.Query(source, syntax="dotty",
                        application_delegate=FakeApplicationDelegate())
        return q.run_engine("infer_types")

    def analyzeLegacyQuery(self, source):
        q = query.Query(source, syntax="slashy")
        return q.run_engine("infer_types")

    def assertIsa(self, t, p):
        self.assertTrue(protocol.isa(t, p))

    def testDelegate(self):
        t = self.analyzeQuery("ProcessName")
        self.assertIsa(t, basestring)

    def testBasic(self):
        t = self.analyzeQuery("ProcessName == 'init'")
        self.assertIsa(t, boolean.IBoolean)

        t = self.analyzeLegacyQuery("Process/Name == 'init'")
        self.assertIsa(t, boolean.IBoolean)

    def testBinary(self):
        t = self.analyzeQuery("'foo' in ('bar', 'foo')")
        self.assertIsa(t, boolean.IBoolean)

    def testRecursive(self):
        t = self.analyzeQuery(
            "ProcessParent matches (ProcessName == 'init')")
        self.assertIsa(t, boolean.IBoolean)

        t = self.analyzeQuery(
            "any ProcessChildren matches (ProcessName == 'init')")
        self.assertIsa(t, boolean.IBoolean)

    def testNumbers(self):
        t = self.analyzeQuery("5 + 5")
        self.assertIsa(t, number.INumber)

        t = self.analyzeQuery("10 * (1 - 4) / 5")
        self.assertIsa(t, number.INumber)

    def testDescendExpression(self):
        t = self.analyzeQuery(
            "with ProcessParent evaluate (ProcessPid + 10)")

        self.assertIsa(t, number.INumber)

        # Should be the same using shorthand syntax.
        t = self.analyzeQuery(
            "with ProcessParent.ProcessParent evaluate (ProcessPid - 1)")

        self.assertIsa(t, number.INumber)
