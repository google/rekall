# EFILTER Forensic Query Language
#
# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
EFILTER dotty syntax output.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter import engine
from efilter import expression

from efilter.frontends.experiments import dotty


def build_operator_lookup(*tables):
    lookup = {}
    for table in tables:
        for token, operator in table.iteritems():
            if not (isinstance(operator.handler, type) and
                    issubclass(operator.handler, expression.Expression)):
                continue

            lookup[operator.handler] = token

    return lookup


class DottyOutput(engine.VisitorEngine):
    """Produces equivalent Dotty output to the AST.

    This class follows the visitor pattern. See documentation on VisitorEngine.
    """

    TOKENS = build_operator_lookup(dotty.INFIX, dotty.PREFIX)

    def visit_Let(self, expr):
        lhs = expr.lhs
        rhs = expr.rhs
        left = self.visit(lhs)
        right = self.visit(rhs)
        token = "."

        if not isinstance(expr.lhs, (expression.ValueExpression,
                                     expression.Let)):
            left = "(%s)" % left
            token = " where "

        if not isinstance(expr.rhs, (expression.ValueExpression,
                                     expression.Let)):
            right = "(%s)" % right
            token = " where "

        return token.join((left, right))

    def visit_LetAny(self, expr):
        return "any %s" % self.visit_Let(expr)

    def visit_letEach(self, expr):
        return "each %s" % self.visit_Let(expr)

    def visit_Literal(self, expr):
        return repr(expr.value)

    def visit_Binding(self, expr):
        return expr.value

    def visit_Complement(self, expr):
        return "not (%s)" % self.visit(expr)

    def visit_BinaryExpression(self, expr):
        return self.visit_VariadicExpression(expr)

    def visit_VariadicExpression(self, expr):
        token = self.TOKENS[type(expr)]
        separator = " %s " % token
        return separator.join(self.visit(x) for x in expr.children)


engine.Engine.register_engine(DottyOutput, "dotty_output")
