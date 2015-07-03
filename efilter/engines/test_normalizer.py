from efilter import expression
from efilter import testlib


class NormalizerTest(testlib.EngineTestCase):
    def testBasic(self):
        self.assertTransform("normalizer", "ProcessName == 'init'",
                             "ProcessName == 'init'")

    def testEliminateEmpties(self):
        self.assertTransform(
            "normalizer", ("&", True), expression.Literal(True))

    def testLetForms(self):
        """LetAny and LetEach forms are not rotated."""
        original = ("let-any",
                    ("let", ("var", "Process"), ("var", "parent")),
                    ("==", ("var", "name"), "init"))

        self.assertTransform("normalizer", original, original)

    def testRealExample(self):
        original = ("&",
                    ("let",
                     ("let", ("var", "MemoryDescriptor"), ("var", "process")),
                     ("==",
                      ("let", ("var", "Process"), ("var", "command")),
                      "Adium")),
                    ("&",
                     ("in", "execute",
                      ("let",
                       ("var", "MemoryDescriptor"),
                       ("var", "permissions"))),
                     ("in", "write",
                      ("let",
                       ("var", "MemoryDescriptor"),
                       ("var", "permissions")))))

        # Two binary intersections become one variadic intersection and the
        # let-forms now have a Binding as their LHS whenever possible.
        expected = ("&",
                    ("let",
                     ("var", "MemoryDescriptor"),
                     ("let",
                      ("var", "process"),
                      ("==",
                       ("let", ("var", "Process"), ("var", "command")),
                       "Adium"))),
                    ("in", "execute",
                     ("let",
                      ("var", "MemoryDescriptor"),
                      ("var", "permissions"))),
                    ("in", "write",
                     ("let",
                      ("var", "MemoryDescriptor"),
                      ("var", "permissions"))))

        self.assertTransform("normalizer", original, expected)
