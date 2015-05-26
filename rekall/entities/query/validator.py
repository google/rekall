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

from efilter import errors
from efilter import engine


class ValidationError(errors.EfilterError):
    pass


class QueryValidator(engine.VisitorEngine):
    """Checks the query for semantic errors.

    This checks for the following:

    - Attribute/literal type mismatch.
    - Non-existent components or attributes.
    """

    def error(self, message, exp):
        raise ValidationError(error=message, start=exp.start, end=exp.end,
                              query=self.query.source)

    def visit_Expression(self, exp):
        _ = exp
        return True

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

        return True

    def visit_ComponentLiteral(self, exp):
        component = entity.Entity.reflect_component(exp.value)
        if component is None:
            return self.error("Component %s doesn't exist." % exp.value, exp)

        return True

engine.Engine.register_engine(QueryValidator, "validator")
