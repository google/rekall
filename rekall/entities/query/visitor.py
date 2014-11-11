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

from rekall import registry


class QueryVisitor(object):
    __abstract = True
    __metaclass__ = registry.MetaclassRegistry

    def __init__(self, query):
        self.query = query
        self.expression = query.expression

    def __hash__(self):
        return hash((type(self), self.query))

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.query == other.query

    def __ne__(self, other):
        return not self.__eq__(other)

    def run(self):
        return self.visit(self.expression)

    def visit(self, expression):
        # Walk the MRO and try to find a closest match for handler.
        for cls in type(expression).mro():
            handler_name = "visit_%s" % cls.__name__
            handler = getattr(self, handler_name, None)

            if callable(handler):
                return handler(expression)

        # No appropriate handler for this class. Explode.
        raise ValueError(
            "%s has no handler for %s" % (
                type(self).__name__, type(expression).__name__))
