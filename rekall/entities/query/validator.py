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

from rekall.entities import entity

from rekall.entities.query import expression
from rekall.entities.query import visitor


class ValidationError(expression.QueryError):
    pass


class QueryValidator(visitor.QueryVisitor):
    """Checks the query for semantic errors.

    This checks for the following:

    - Attribute/literal type mismatch.
    - Non-existent components or attributes.
    """

    COLLECTION_TYPES = frozenset(["tuple", "list"])

    def error(self, message, exp):
        raise ValidationError(error=message, start=exp.start, end=exp.end,
                              query=self.query.source)

    def visit_Expression(self, exp):
        for child in exp.children:
            if isinstance(child, expression.Expression):
                self.visit(child)

        return exp.return_types

    def visit_Literal(self, exp):
        type_name = type(exp.value).__name__
        if type_name in ["str", "unicode"]:
            return frozenset(["str", "unicode"])

        return frozenset([type(exp.value).__name__])

    def visit_Binding(self, exp):
        if exp.value.startswith("&"):
            field = entity.Entity.reflect_attribute(exp.value[1:])
            if field and field.typedesc.type_name != "Entity":
                return self.error(
                    "%s is type %s. Reverse lookups require type Entity." %
                    (field.name, field.typedesc.type_name),
                    exp)
        else:
            field = entity.Entity.reflect_attribute(exp.value)

        if field is None:
            return self.error("Attribute %s doesn't exist." % exp.value, exp)

        return frozenset([field.typedesc.type_name])

    def visit_ComponentLiteral(self, exp):
        component = entity.Entity.reflect_component(exp.value)
        if component is None:
            return self.error("Component %s doesn't exist." % exp.value, exp)

        return ("expression", )

    def visit_RegexFilter(self, exp):
        if "str" not in self.visit(exp.regex):
            return self.error("Regex pattern must be string.", exp.regex)

        string_types = self.visit(exp.string)
        if not set(["str", "unicode"]) & string_types:
            return self.error(
                "Cannot match regex with %s" % ",".join(string_types),
                exp.string)

    def visit_Membership(self, exp):
        if not self.COLLECTION_TYPES & self.visit(exp.set):
            return self.error("Left hand side of 'in' must be a collection.",
                              exp.set)

    def visit_Relation(self, exp):
        first_type = self.visit(exp.children[0])
        for child in exp.children[1:]:
            child_type = self.visit(child)
            if child_type & first_type:
                continue

            self.error("Comparing type %s to type %s." % (
                ", ".join(first_type),
                ", ".join(child_type)), child)

        return "bool"
