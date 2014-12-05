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

import logging

from rekall.entities import entity as entity_module
from rekall.entities import identity as entity_id

from rekall.entities.query import expression
from rekall.entities.query import matcher
from rekall.entities.query import query as entity_query
from rekall.entities.query import visitor


class EntityQuerySearch(visitor.QueryVisitor):
    """Tries to solve the query using available indexing."""

    def search(self, entities, lookup_tables):
        self.entities = entities
        self.lookup_tables = lookup_tables
        return list(self.run())

    def visit_ComponentLiteral(self, expr):
        return self._as_entities(
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

    def _subquery(self, expr):
        return entity_query.Query(expression=expr,
                                  source=self.query.source)

    def _slow_solve(self, expr, seed):
        slow_matcher = matcher.QueryMatcher(self._subquery(expr))
        entities = set()
        for entity in seed:
            if slow_matcher.match(entity):
                entities.add(entity)

        return entities

    def _as_entities(self, identities):
        entities = set()
        for identity in identities:
            # identity.indices is a set, hence the loop.
            for index in identity.indices:
                entities.add(self.entities[index])
                break

        return entities

    def _solve_equivalence(self, expr, binding, literal):
        literal_value = literal.value
        if isinstance(literal_value, entity_id.Identity):
            results = set()
            for index in literal_value.indices:
                results |= self._solve_equivalence(
                    expr, binding, expression.Literal(index))

            return results

        table = self.lookup_tables.get(binding.value, None)
        if table:
            # Sweet, we have exact index for this.
            return self._as_entities(table.table.get(literal_value, set()))

        # Don't have an exact index, but can prefilter by component index.
        component, _ = binding.value.split("/", 1)
        slow_matcher = matcher.QueryMatcher(self._subquery(expr))
        entities = set()
        candidates = self.lookup_tables["components"].table.get(component, [])
        for identity in candidates:
            entity = self.entities[identity.first_index]
            if slow_matcher.match(entity):
                entities.add(entity)

        return entities

    def visit_Equivalence(self, expr):
        if len(expr.children) != 2:
            return self._slow_solve(expr, self.entities.itervalues())

        x, y = expr.children
        if (isinstance(x, expression.Binding) and
                isinstance(y, expression.Literal)):
            return self._solve_equivalence(expr, x, y)
        elif (isinstance(x, expression.Literal) and
              isinstance(y, expression.Binding)):
            return self._solve_equivalence(expr, y, x)

        return self._slow_solve(expr, self.entities.itervalues())

    def visit_Expression(self, expr):
        logging.debug("Fallthrough to filter-based search (%s).", expr)
        return self._slow_solve(expr, self.entities.itervalues())

    def _slow_Let(self, expr):
        logging.debug("Fallthrough to filter-based search (%s).", expr)
        # Prefiltering the slow solve to just entities that actually have the
        # relevant attribute usually shaves off about 200 ms.
        seed = self.visit(expr.context)
        return self._slow_solve(expr, seed)

    def visit_LetEach(self, expr):
        return self._slow_Let(expr)

    def visit_LetAny(self, expr):
        return self._slow_Let(expr)

    def visit_Let(self, expr):
        # Do we have an index for the context attribute?
        table = self.lookup_tables.get(expr.context.value)

        if not table:
            return self._slow_Let(expr)

        # We have an index - this means we can run the subquery, get the
        # identities that match and then get their intersection with the
        # index we just found.
        results = set()
        subquery_hits = self.visit(expr.expression)
        for subquery_result in subquery_hits:
            for index in subquery_result.indices:
                # Need to check every index in case the lookup table is
                # stale.
                matching_entities = table.table.get(index)
                if not matching_entities:
                    continue

                for matching_entity in matching_entities:
                    results.add(matching_entity)

        return self._as_entities(results)


class EntityLookupTable(object):
    """Lookup table for entities."""

    @property
    def cost_per_search(self):
        return self.updates / self.searches

    def __init__(self, key_name, key_func, entity_manager):
        self.searches = 0.0
        self.updates = 0.0
        self.key_name = key_name
        self.key_func = key_func
        self.manager = entity_manager
        self.table = {}

    def update_index(self, entities):
        for entity in entities:
            for key in self.key_func(entity):
                self.updates += 1

                # Identities need to be stored at each of their indices instead
                # of by just one hash.
                if isinstance(key, entity_id.Identity):
                    for index in key.indices:
                        self.table.setdefault(
                            index, set()).add(entity.identity)
                else:
                    self.table.setdefault(key, set()).add(entity.identity)

    def lookup(self, *keys):
        unique_results = set()
        self.searches += 1

        for key in keys:
            for identity in self.table.get(key, []):
                for entity in self.manager.find_by_identity(identity):
                    unique_results.add(entity)

        return unique_results


class AttributeLookupTable(EntityLookupTable):
    """Lookup table by attribute value."""

    def __init__(self, attribute, entity_manager):
        field = entity_module.Entity.reflect_attribute(attribute)
        coerce_fn = field.typedesc.coerce

        def key_func(entity):
            return (coerce_fn(entity.get_raw(attribute)), )

        super(AttributeLookupTable, self).__init__(attribute, key_func,
                                                   entity_manager)
