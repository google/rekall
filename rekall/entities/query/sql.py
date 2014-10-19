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

from rekall.entities.query import visitor


class SQLGenerator(visitor.QueryVisitor):
    """Proof-of-concept SQL generator from query AST.

    The assumed database schema is such that there is one table per each
    component with one column per each attribute. And additional column per
    component-table contains the unique entity ID which serves both as a shared
    foreign key and the surrogate primary key of the component-table.

    The Entities table is a relation of string representations of indices,
    serving as the natural primary key, and the entity IDs.

    This is currently a non-complete implementation of the query AST and will
    develop as an SQL layer is added.
    """

    components = set()

    def run(self):
        where = self.visit(self.query)
        joins = ["NATURAL INNER JOIN %s" % x for x in self.components]
        return "SELECT * FROM Entities %s WHERE %s" % (
            " ".join(joins), where)

    def visit_ValueExpression(self, expr):
        return expr.value

    def visit_Literal(self, expr):
        val = expr.value

        if isinstance(val, str):
            return "\"%s\"" % val

        if isinstance(val, (int, long, float)):
            return str(val)

    def visit_ComponentLiteral(self, expr):
        self.components.add(expr.value)
        return "1"

    def visit_Intersection(self, expr):
        vals = [self.visit(x) for x in expr.children]
        return "(%s)" % ") AND (".join(vals)

    def visit_Union(self, expr):
        vals = [self.visit(x) for x in expr.children]
        return "(%s)" % ") OR (".join(vals)

    def visit_Equivalence(self, expr):
        first = self.visit(expr.children[0])
        comparisons = []
        for expr in expr.children[1:]:
            comparisons.append("%s = %s" % (first, self.visit(expr)))
        return "(%s)" % " AND ".join(comparisons)

    def visit_Complement(self, expr):
        return "NOT(%s)" % self.visit(expr.value)

    def visit_Addition(self, expr):
        pairs = [self.visit(x) for x in expr.children]
        return "(%s)" % " + ".join(pairs)

    def visit_Multiplication(self, expr):
        pairs = [self.visit(x) for x in expr.children]
        return "(%s)" % " * ".join(pairs)
