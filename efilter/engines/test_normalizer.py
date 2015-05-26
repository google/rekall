import unittest

from efilter import expression
from efilter import query


class RuleAnalyzerTest(unittest.TestCase):
    def assertResult(self, source, expected, syntax="dotty"):
        q = query.Query(source, syntax=syntax)
        normalized = q.run_engine("normalizer")
        baseline = query.Query(expected, syntax=syntax)
        self.assertEqual(normalized, baseline)

    def testBasic(self):
        self.assertResult("ProcessName == 'init'",
                          "ProcessName == 'init'")

    def testEliminateEmpties(self):
        self.assertResult(
            expression.Intersection(
                expression.Literal(True)),
            expression.Literal(True))

    def testRealExample(self):
        original = expression.Intersection(
            expression.Let(
                expression.Let(
                    expression.Binding('MemoryDescriptor'),
                    expression.Binding('process')),
                expression.Equivalence(
                    expression.Let(
                        expression.Binding('Process'),
                        expression.Binding('command')),
                    expression.Literal('Adium'))),
            expression.Intersection(
                expression.Membership(
                    expression.Literal('execute'),
                    expression.Let(
                        expression.Binding('MemoryDescriptor'),
                        expression.Binding('permissions'))),
                expression.Membership(
                    expression.Literal('write'),
                    expression.Let(
                        expression.Binding('MemoryDescriptor'),
                        expression.Binding('permissions')))))

        # Two binary intersections become one variadic intersection and the
        # let-forms now have a Binding as their LHS whenever possible.
        expected = expression.Intersection(
            expression.Let(
                expression.Binding('MemoryDescriptor'),
                expression.Let(
                    expression.Binding('process'),
                    expression.Equivalence(
                        expression.Let(
                            expression.Binding('Process'),
                            expression.Binding('command')),
                        expression.Literal('Adium')))),
            expression.Membership(
                expression.Literal('execute'),
                expression.Let(
                    expression.Binding('MemoryDescriptor'),
                    expression.Binding('permissions'))),
            expression.Membership(
                expression.Literal('write'),
                expression.Let(
                    expression.Binding('MemoryDescriptor'),
                    expression.Binding('permissions'))))

        self.assertResult(original, expected)
