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

    This class follows the visitor pattern. See documentation on VisitorEngine.

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
        """Rotate repeated let-forms so they cascade on the RHS.

        Basic let-forms should be rotated as follows:
        (let (let x y) (...)) => (let x (let y) (...))

        These are functionally equivalent, but the latter is easier to follow.

        Returns rotated Let instance.
        """
        lhs = self.visit(expr.lhs, **kwargs)
        rhs = self.visit(expr.rhs)

        if (isinstance(lhs, expression.Let)
                and isinstance(lhs.lhs, expression.Binding)):
            lhs_ = lhs.lhs
            rhs = type(expr)(lhs.rhs, rhs)
            lhs = lhs_

        return type(expr)(lhs, rhs)

    def visit_LetAny(self, expr, **kwargs):
        """let-any|let-each forms are not cascaded.

        This is basically a pass-through function.
        """
        lhs = self.visit(expr.lhs, **kwargs)
        rhs = self.visit(expr.rhs, **kwargs)
        return type(expr)(lhs, rhs)

    def visit_LetEach(self, expr, **kwargs):
        return self.visit_LetAny(expr, **kwargs)

    def visit_Expression(self, expr, **_):
        return expr

    def visit_BinaryExpression(self, expr, **kwargs):
        return self.visit_VariadicExpression(expr, **kwargs)

    def visit_VariadicExpression(self, expr, **kwargs):
        """Pass through n-ary expressions, and eliminate empty branches.

        Variadic and binary expressions recursively visit all their children.

        If all children are eliminated then the parent expression is also
        eliminated:

        (& [removed] [removed]) => [removed]

        If only one child is left, it is promoted to replace the parent node:

        (& True) => True
        """
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
