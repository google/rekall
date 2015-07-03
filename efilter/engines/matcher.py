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
EFILTER individual object filter and matcher.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


import re

from efilter import expression
from efilter import engine

from efilter.protocols import associative
from efilter.protocols import superposition


class ObjectMatcher(engine.VisitorEngine):
    """Given a query and bindings will evaluate the query.

    This class follows the visitor pattern. See documentation on VisitorEngine.
    """

    # run() sets this to the sort value for the latest object matched.
    latest_sort_order = None

    def run(self, bindings, match_backtrace=False):
        self.match_backtrace = match_backtrace
        self.bindings = bindings

        # The match backtrace works by keeping a list of all the branches that
        # matched and then backtracking from the latest one to be evaluated
        # to the first parent that's a relation.
        if self.match_backtrace:
            self._matched_expressions = []

        self.latest_sort_order = []
        self.node = self.query.root
        self.result = self.visit(self.node)
        self.latest_sort_order = tuple(self.latest_sort_order)

        if self.match_backtrace:
            self.matched_expression = None
            for expr in self._matched_expressions:
                if isinstance(expr, expression.Relation):
                    self.matched_expression = expr
                    break

        if self.result:
            return self

        return False

    def visit(self, expr, **_):
        result = super(ObjectMatcher, self).visit(expr)

        if self.match_backtrace and result:
            self._matched_expressions.append(expr)

        return result

    def visit_Literal(self, expr, **_):
        return expr.value

    def visit_Binding(self, expr, **_):
        return associative.select(self.bindings, expr.value)

    def visit_Let(self, expr, **_):
        saved_bindings = self.bindings
        if isinstance(expr, expression.LetAny):
            union_semantics = True
        elif isinstance(expr, expression.LetEach):
            union_semantics = False
        else:
            union_semantics = None

        if not isinstance(expr.context, expression.Binding):
            raise ValueError(
                "Left operand of Let must be a Binding expression.")

        # Context to rebind to. This is the key that will be selected from
        # current bindings and become the new bindings for ever subexpression.
        context = expr.context.value

        try:
            rebind = associative.resolve(saved_bindings, context)

            if not rebind:  # No value from context.
                return None

            if union_semantics is None:
                # This is a simple let, which does not permit superposition
                # semantics.
                if superposition.insuperposition(rebind):
                    raise TypeError(
                        "A Let expression doesn't permit superposition "
                        "semantics. Use LetEach or LetAny instead.")

                self.bindings = rebind
                return self.visit(expr.expression)

            # If we're using union or intersection semantics, the type of
            # rebind MUST be a Superposition, even if it happens to have
            # only one state. If the below throws a type error then the
            # query is invalid and should fail here.
            result = False
            for state in superposition.getstates(rebind):
                self.bindings = state
                result = self.visit(expr.expression)
                if result and union_semantics:
                    return result

                if not result and not union_semantics:
                    return False

            return result
        finally:
            self.bindings = saved_bindings

    def visit_ComponentLiteral(self, expr, **_):
        return getattr(self.bindings.components, expr.value)

    def visit_Complement(self, expr, **_):
        return not self.visit(expr.value)

    def visit_Intersection(self, expr, **_):
        for child in expr.children:
            if not self.visit(child):
                return False

        return True

    def visit_Union(self, expr, **_):
        for child in expr.children:
            if self.visit(child):
                return True

        return False

    def visit_Sum(self, expr, **_):
        return sum([self.visit(child) for child in expr.children])

    def visit_Difference(self, expr, **_):
        difference = self.visit(expr.children[0])
        for child in expr.children[1:]:
            difference -= self.visit(child)

        return difference

    def visit_Product(self, expr, **_):
        product = 1
        for child in expr.children:
            product *= self.visit(child)

        return product

    def visit_Quotient(self, expr, **_):
        quotient = self.visit(expr.children[0])
        for child in expr.children[1:]:
            quotient /= self.visit(child)

        return quotient

    def visit_Equivalence(self, expr, **_):
        first_val = self.visit(expr.children[0])
        for child in expr.children[1:]:
            if self.visit(child) != first_val:
                return False

        return True

    def visit_Membership(self, expr, **_):
        return self.visit(expr.element) in set(self.visit(expr.set))

    def visit_RegexFilter(self, expr, **_):
        string = self.visit(expr.string)
        pattern = self.visit(expr.regex)

        return re.compile(pattern).match(str(string))

    def visit_StrictOrderedSet(self, expr, **_):
        iterator = iter(expr.children)
        min_ = self.visit(next(iterator))

        if min_ is None:
            return False

        for child in iterator:
            val = self.visit(child)

            if not min_ > val or val is None:
                return False

            min_ = val

        return True

    def visit_PartialOrderedSet(self, expr, **_):
        iterator = iter(expr.children)
        min_ = self.visit(next(iterator))

        if min_ is None:
            return False

        for child in iterator:
            val = self.visit(child)
            if min_ < val or val is None:
                return False

            min_ = val

        return True


engine.Engine.register_engine(ObjectMatcher, "filter")
