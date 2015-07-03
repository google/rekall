from efilter import testlib

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


class TypeInferenceTest(testlib.EngineTestCase):
    def testDelegate(self):
        self.assertEngineResult(
            engine="infer_types",
            source="ProcessName",
            expected=basestring,
            assertion=self.assertIsa)

    def testBasic(self):
        self.assertEngineResult(
            engine="infer_types",
            source="ProcessName == 'init'",
            expected=boolean.IBoolean,
            assertion=self.assertIsa)

        self.assertEngineResult(
            engine="infer_types",
            source="Process/Name == 'init'",
            source_syntax="slashy",
            expected=boolean.IBoolean,
            assertion=self.assertIsa)

    def testBinary(self):
        self.assertEngineResult(
            engine="infer_types",
            source="'foo' in ('bar', 'foo')",
            expected=boolean.IBoolean,
            assertion=self.assertIsa)

    def testRecursive(self):
        self.assertEngineResult(
            engine="infer_types",
            source="ProcessParent where (ProcessName == 'init')",
            expected=boolean.IBoolean,
            assertion=self.assertIsa)

        self.assertEngineResult(
            engine="infer_types",
            source="any ProcessChildren where (ProcessName == 'init')",
            expected=boolean.IBoolean,
            assertion=self.assertIsa)

    def testNumbers(self):
        self.assertEngineResult(
            engine="infer_types",
            source="5 + 5",
            expected=number.INumber,
            assertion=self.assertIsa)

        self.assertEngineResult(
            engine="infer_types",
            source="10 * (1 - 4) / 5",
            expected=number.INumber,
            assertion=self.assertIsa)

    def testDescendExpression(self):
        self.assertEngineResult(
            engine="infer_types",
            source="ProcessParent where (ProcessPid + 10)",
            expected=number.INumber,
            app_delegate=FakeApplicationDelegate(),
            assertion=self.assertIsa)

        # Should be the same using shorthand syntax.
        self.assertEngineResult(
            engine="infer_types",
            source="ProcessParent.ProcessParent where (ProcessPid - 1)",
            expected=number.INumber,
            app_delegate=FakeApplicationDelegate(),
            assertion=self.assertIsa)
