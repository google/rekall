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

from rekall.entities.query import expression
from rekall.entities.query import visitor


class QueryMatcher(visitor.QueryVisitor):
    """Given a query and bindings will evaluate the query."""

    # match() sets this to the sort value for the latest object matched.
    latest_sort_order = None

    def match(self, bindings):
        """Tried to match bindings, which must respond to calls to [].

        Bindings can be any object that supports the __getitem__ operator, such
        as a dict or an Entity.

        This function will also set self.latest_sort_order if the query calls
        for ordering.
        """
        self.latest_sort_order = []
        self.bindings = bindings
        result = self.run()
        self.latest_sort_order = tuple(self.latest_sort_order)
        return result

    def visit_Literal(self, expr):
        return expr.value

    def visit_Binding(self, expr):
        return self.bindings.get_raw(expr.value)

    def visit_Let(self, expr):
        saved_bindings = self.bindings
        if isinstance(expr, expression.LetAny):
            union_semantics = True
        elif isinstance(expr, expression.LetEach):
            union_semantics = False
        else:
            union_semantics = None

        try:
            rebind_variants = list(saved_bindings.get_variants(expr.context))
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

    def visit_Sorted(self, expr):
        self.latest_sort_order.append(self.bindings[expr.binding])
        return self.visit(expr.expression)

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

    def visit_Addition(self, expr):
        return sum([self.visit(child) for child in expr.children])

    def visit_Multiplication(self, expr):
        product = 1
        for child in expr.children:
            product *= self.visit(child)
        return product

    def visit_Equivalence(self, expr):
        first_val = self.visit(expr.children[0])
        for child in expr.children[1:]:
            if self.visit(child) != first_val:
                return False

        return True

    def visit_StrictOrderedSet(self, expr):
        iterator = iter(expr.children)
        x = next(iterator)
        for y in iterator:
            if not x > y:
                return False
            x = y

        return True

    def visit_NonStrictOrderedSet(self, expr):
        iterator = iter(expr.children)
        x = next(iterator)
        for y in iterator:
            if x < y:
                return False

        return True
