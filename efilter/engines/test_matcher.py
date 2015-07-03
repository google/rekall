from efilter import testlib


class MatcherTest(testlib.EngineTestCase):
    def assertMatcherResult(self, expected, result):
        self.assertEqual(expected, result.result)

    def testBasic(self):
        self.assertEngineResult(
            engine="filter",
            assertion=self.assertMatcherResult,
            source="Process/pid is 1",
            source_syntax="slashy",
            expected=True,
            bindings={"Process/pid": 1})

    def testRecursion(self):
        # Drilling down into a nested object should succeed.
        self.assertEngineResult(
            engine="filter",
            assertion=self.assertMatcherResult,
            source="Process/parent matches Process/pid is 1",
            bindings={"Process/parent": {"Process/pid": 1}},
            expected=True,
            source_syntax="slashy")

        # Using a let-any form should succeed even if there is only one linked
        # object.
        self.assertEngineResult(
            engine="filter",
            assertion=self.assertMatcherResult,
            source=("any Process/parent matches (Process/pid is 1 or "
                    "Process/command is 'foo')"),
            bindings={"Process/parent": {"Process/pid": 1}},
            expected=True,
            source_syntax="slashy")
