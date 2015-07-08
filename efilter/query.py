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
    syntax = None

    def __init__(self, source, root=None, params=None, syntax="slashy",
                 application_delegate=None):
        super(Query, self).__init__()
        self.application_delegate = application_delegate
        self.syntax = syntax

        # Run as a copy constructor.
        if isinstance(source, Query):
            self.source = source.source
            self.root = root or source.root
            self.application_delegate = (application_delegate
                                         or source.application_delegate)
            return

        # No need to parse anything.
        if root:
            self.source = source
            self.root = root
            return

        # This is here to support calling Query with a positional argument
        # that's the root of the AST.
        if isinstance(source, expression.Expression):
            self.root = source
            return

        # If we got here then source is actually a query and it's not been
        # parsed, so we need to find the appropriate frontend parser and run it.
        if self.syntax and self.syntax != "expression":
            # We need to parse the query.
            parser_cls = frontend.Frontend.get_frontend(syntax)
            parser = parser_cls(original=source, params=params)
            self.source = parser.original
            self.root = parser.root

            # Query is normalized by default because parsers are allowed to
            # produce crazy AST and rely on the visitor engines to understand
            # it.
            self.root = self.run_engine("normalizer").root
        else:
            raise TypeError("%r is not an expression.", source)

    def subquery(self, node):
        return type(self)(self, root=node)

    def locate_expression(self, node):
        """Returns the original source of the expression with context.

        Returns tuple of:
            - query up to the start of expression
            - source of the expression
            - the rest of the query
        """
        return node.start, node.end

    def source_expression(self, node):
        if isinstance(self.source, basestring):
            return self.source[node.start:node.end]

        return None

    def run_engine(self, shorthand, **kwargs):
        engine_cls = engine.Engine.get_engine(shorthand)
        if engine_cls is None:
            raise ValueError("No such engine %r." % shorthand)

        return engine_cls(
            query=self,
            application_delegate=self.application_delegate).run(**kwargs)

    def __str__(self):
        return unicode(self)

    def __unicode__(self):
        if self.source:
            return unicode(self.source)

        return unicode(self.root)

    def __repr__(self):
        source = self.source_expression(self.root)
        if not source:
            source = self.root

        return "Query(%r)" % source

    def __hash__(self):
        return hash(self.root)

    def __eq__(self, other):
        if not isinstance(other, Query):
            return False

        return self.root == other.root

    def __ne__(self, other):
        return not self.__eq__(other)
