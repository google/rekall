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
EFILTER query wrapper.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


from efilter import frontend
from efilter import engine
from efilter import expression


class Query(object):
    source = None
    root = None

    def __init__(self, source, root=None, params=None):
        # Copy constructor.
        if isinstance(source, Query):
            self.source = source.source
            self.root = source.root
            return

        # No need to parse anything.
        if root:
            self.source = source
            self.root = root
            return

        # Need to parse. We assume the default frontend/syntax (dotty).
        if isinstance(source, basestring):
            parser = frontend.Frontend.get_frontend("dotty")(original=source,
                                                             params=params)
            self.root = parser.root
            self.source = parser.original
        elif isinstance(source, expression.Expression):
            self.root = source
        else:
            raise TypeError("%r is not an expression.", source)

    def locate_expression(self, node):
        """Returns the original source of the expression with context.

        Returns tuple of:
            - query up to the start of expression
            - source of the expression
            - the rest of the query
        """
        return node.start, node.end

    def run_engine(self, shorthand, **kwargs):
        engine_cls = engine.Engine.get_engine(shorthand)
        if engine_cls is None:
            raise ValueError("No such engine %r." % shorthand)

        return engine_cls(query=self).run(**kwargs)

    def __str__(self):
        return unicode(self)

    def __unicode__(self):
        if self.source:
            return unicode(self.source)

        return unicode(self.root)

    def __repr__(self):
        if self.source:
            return "Query(%r)" % self.source

        return "Query(%r)" % repr(self.root)

    def __hash__(self):
        return hash(self.root)

    def __eq__(self, other):
        if not isinstance(other, Query):
            return False

        return self.root == other.root

    def __ne__(self, other):
        return not self.__eq__(other)
