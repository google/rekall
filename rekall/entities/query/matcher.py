# Rekall Memory Forensics
#
# Copyright 2014 Google Inc. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""
The Rekall Entity Layer.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

import re

from rekall.entities import superposition

from rekall.entities.query import expression
from rekall.entities.query import visitor


class QueryMatcher(visitor.QueryVisitor):
    """Given a query and bindings will evaluate the query."""

    # match() sets this to the sort value for the latest object matched.
    latest_sort_order = None

    def match(self, bindings, match_backtrace=False):
        """Tried to match bindings, which must respond to calls to [].

        Bindings can be any object that supports the __getitem__ operator, such
        as a dict or an Entity.

        This function will also set self.latest_sort_order if the query calls
        for ordering.

        Arguments:
            bindings: The entity (technically, anything dict-like).
            match_backtrace: Should the matcher keep track of which branch of
                             the expression matched? Recommended usage is to
                             keep this False during the search, and once the
                             result is available, to match again just on the
                             single object with this set to True.

        Returns:
            If no match is made, returns None. If a match is made returns an
            object with the following properties:

                latest_sort_order: A key that the matched object can be sorted
                                   by.
                result: The actual result of the match. This will usually be
                        True, but could be some other scalar, like an int.
                matched_expression: The subexpression that actually resulted in
                                    the match.
        """
        self.match_backtrace = match_backtrace
        self.bindings = bindings

        # The match backtrace works by keeping a list of all the branches that
        # matched and then backtracking from the latest one to be evaluated
        # to the first parent that's a relation.
        if self.match_backtrace:
            self._matched_expressions = []

        self.latest_sort_order = []
        self.result = self.run()
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

    def visit(self, expr):
        result = super(QueryMatcher, self).visit(expr)

        if self.match_backtrace and result:
            self._matched_expressions.append(expr)

        return result

    def visit_Literal(self, expr):
        return expr.value

    def visit_Binding(self, expr):
        getter = getattr(self.bindings, "get_raw", None)

        # Special case in case bindings supports an interface that turns of
        # automagic behavior. (Basically, this means bindings is an entity.)
        if callable(getter):
            return getter(expr.value)

        return self.bindings.get(expr.value)

    def visit_Let(self, expr):
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

        context = expr.context.value

        try:
            rebind = saved_bindings.get(context)

            if not rebind:  # No results.
                return False

            if isinstance(rebind, superposition.BaseSuperposition):
                rebind_variants = list(saved_bindings.get_variants(context))
            else:
                rebind_variants = [rebind]

            if len(rebind_variants) > 1 and union_semantics is None:
                raise ValueError(
                    "More than one result for a Let expression is illegal. "
                    "Use LetEach or LetAny to specify semantics.")

            result = False
            for rebind in rebind_variants:
                self.bindings = rebind
                result = self.visit(expr.expression)
                if result and union_semantics:
                    return result

                if not result and not union_semantics:
                    return False

            return result
        finally:
            self.bindings = saved_bindings

    def visit_ComponentLiteral(self, expr):
        return getattr(self.bindings.components, expr.value)

    def visit_Complement(self, expr):
        return not self.visit(expr.value)

    def visit_Intersection(self, expr):
        for child in expr.children:
            if not self.visit(child):
                return False

        return True

    def visit_Union(self, expr):
        for child in expr.children:
            if self.visit(child):
                return True

        return False

    def visit_Sum(self, expr):
        return sum([self.visit(child) for child in expr.children])

    def visit_Difference(self, expr):
        difference = self.visit(expr.children[0])
        for child in expr.children[1:]:
            difference -= self.visit(child)

        return difference

    def visit_Product(self, expr):
        product = 1
        for child in expr.children:
            product *= self.visit(child)

        return product

    def visit_Quotient(self, expr):
        quotient = self.visit(expr.children[0])
        for child in expr.children[1:]:
            quotient /= self.visit(child)

        return quotient

    def visit_Equivalence(self, expr):
        first_val = self.visit(expr.children[0])
        for child in expr.children[1:]:
            if self.visit(child) != first_val:
                return False

        return True

    def visit_Membership(self, expr):
        return self.visit(expr.element) in set(self.visit(expr.set))

    def visit_RegexFilter(self, expr):
        string = self.visit(expr.string)
        pattern = self.visit(expr.regex)

        return re.compile(pattern).match(str(string))

    def visit_StrictOrderedSet(self, expr):
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

    def visit_PartialOrderedSet(self, expr):
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
