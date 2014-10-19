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
from rekall.entities.query import matcher
from rekall.entities.query import visitor


class EntityQuerySearch(visitor.QueryVisitor):
    """Tries to solve the query using available indexing."""

    def search(self, entities, lookup_tables):
        self.entities = entities
        self.lookup_tables = lookup_tables
        return self.run()

    def visit_Sorted(self, expr):
        results = self.visit(expr.expression)

        return sorted(results, key=lambda result: result[expr.binding])

    def visit_ComponentLiteral(self, expr):
        return self.__as_entities(
            self.lookup_tables["components"].table.get(expr.value, []))

    def visit_Intersection(self, expr):
        results = set(self.visit(expr.children[0]))
        for child in expr.children[1:]:
            results.intersection_update(self.visit(child))

        return results

    def visit_Union(self, expr):
        results = set()
        for child in expr.children:
            results.update(self.visit(child))

        return results

    def __slow_solve(self, expr):
        slow_matcher = matcher.QueryMatcher(expr)
        entities = set()
        for entity in self.entities.itervalues():
            if slow_matcher.match(entity):
                entities.add(entity)

        return entities

    def __as_entities(self, identities):
        entities = set()
        for identity in identities:
            # identity.indices is a set, hence the loop.
            for index in identity.indices:
                entities.add(self.entities[index])
                break

        return entities

    def _solve_equivalence(self, expr, binding, literal):
        table = self.lookup_tables.get(binding.value, None)
        if table:
            # Sweet, we have exact index for this.
            return self.__as_entities(table.table.get(literal.value, set()))

        # Don't have an exact index, but can prefilter by component index.
        component, _ = binding.value.split("/", 1)
        slow_matcher = matcher.QueryMatcher(expr)
        entities = set()
        candidates = self.lookup_tables["components"].table.get(component, [])
        for identity in candidates:
            for index in identity.indices:
                # identity.indices is a set, hence the loop.
                entity = self.entities[index]
                if slow_matcher.match(entity):
                    entities.add(entity)

                break

        return entities

    def visit_Equivalence(self, expr):
        if len(expr.children) != 2:
            return self.__slow_solve(expr)

        x, y = expr.children
        if (isinstance(x, expression.Binding) and
                isinstance(y, expression.Literal)):
            return self._solve_equivalence(expr, x, y)
        elif (isinstance(x, expression.Literal) and
              isinstance(y, expression.Binding)):
            return self._solve_equivalence(expr, y, x)

        return self.__slow_solve(expr)

    def visit_Expression(self, expr):
        return self.__slow_solve(expr)


class EntityLookupTable(object):
    """Lookup table for entities."""

    def __init__(self, key_name, key_func, entity_manager):
        self.key_name = key_name
        self.key_func = key_func
        self.manager = entity_manager
        self.table = {}

    def update_index(self, entities):
        for entity in entities:
            for key in self.key_func(entity):
                if key:
                    self.table.setdefault(key, set()).add(entity.identity)

    def lookup(self, *keys):
        unique_results = set()

        for key in keys:
            for identity in self.table.get(key, []):
                for entity in self.manager.find_by_identity(identity):
                    unique_results.add(entity)

        return unique_results
