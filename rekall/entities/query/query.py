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

from rekall.entities.query import efilter
from rekall.entities.query import expression as expr
from rekall.entities.query import visitor


class Query(object):
    source = None
    expression = None

    def __init__(self, source, expression=None, params=None):
        if isinstance(source, Query):
            self.source = source.source
            self.expression = source.expression
            return

        if expression:
            self.source = source
            self.expression = expression
            return

        if isinstance(source, str):
            self.source = source
            self.expression = efilter.Parser(source, params=params).parse()
        elif isinstance(source, expr.Expression):
            self.expression = source

    def locate_expression(self, expression):
        """Returns the original source of the expression with context.

        Returns tuple of:
            - query up to the start of expression
            - source of the expression
            - the rest of the query
        """
        return expression.start, expression.end

    def execute(self, visitor_name, method="run", **kwargs):
        visitor_ = visitor.QueryVisitor.classes[visitor_name](self)
        func = getattr(visitor_, method)
        return func(**kwargs)

    def __str__(self):
        return unicode(self)

    def __unicode__(self):
        if self.source:
            return unicode(self.source)

        return unicode(self.expression)

    def __repr__(self):
        if self.source:
            return "Query('%s')" % self.source

        return "Query(%s)" % repr(self.expression)

    def __hash__(self):
        return hash(self.expression)

    def __eq__(self, other):
        if not isinstance(other, Query):
            return False

        return self.expression == other.expression

    def __ne__(self, other):
        return not self.__eq__(other)
