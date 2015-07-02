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
EFILTER query normalizer.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter import engine
from efilter import expression


class Normalizer(engine.VisitorEngine):
    """Optimizes the AST for better performance and simpler structure.

    The returned query will be logically equivalent to what was provided but
    transformations will be made to flatten and optimize the structure. This
    engine works by recognizing certain patterns and replacing them with nicer
    ones, eliminating pointless expressions, and so on.

    Examples:
        # Logical expressions are made variadic:
        Intersection("foo", Intersection("bar", "baz")) # becomes:
        Intersection("foo", "bar", "baz")

        # Let-forms are rotated so that the LHS is a Binding when possible:
        Let(
            Let(
                Binding("Process"),
                Binding("parent")),
            Equivalence(
                Binding("name"),
                Literal("init")))
        # Becomes:
        Let(
            Binding("Process"),
            Let(
                Binding("parent"),
                Equivalence(
                    Binding("name"),
                    Literal("init"))))
    """

    def run(self, *args, **kwargs):
        expr = super(Normalizer, self).run(*args, **kwargs)
        return self.query.subquery(expr)

    def visit_Let(self, expr, **kwargs):
        lhs = self.visit(expr.lhs, **kwargs)
        rhs = self.visit(expr.rhs)

        if (isinstance(lhs, expression.Let)
                and isinstance(lhs.lhs, expression.Binding)):
            lhs_ = lhs.lhs
            rhs = type(expr)(lhs.rhs, rhs)
            lhs = lhs_

        return type(expr)(lhs, rhs)

    def visit_Expression(self, expr, **_):
        return expr

    def visit_BinaryExpression(self, expr, **kwargs):
        return self.visit_VariadicExpression(expr, **kwargs)

    def visit_VariadicExpression(self, expr, **kwargs):
        children = []
        for child in expr.children:
            branch = self.visit(child, **kwargs)
            if branch is None:
                continue

            if type(branch) is type(expr):
                children.extend(branch.children)
            else:
                children.append(branch)

        if len(children) == 0:
            return None

        if len(children) == 1:
            return children[0]

        return type(expr)(*children)

engine.Engine.register_engine(Normalizer, "normalizer")
