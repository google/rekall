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
EFILTER engine base class.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


import abc

from efilter.protocols import name_delegate


class NopAppDelegate(object):
    """This application delegate doesn't do anything."""


name_delegate.INameDelegate.implement(
    for_type=NopAppDelegate,
    implementations={
        name_delegate.reflect: lambda d, n, s: None,
        name_delegate.provide: lambda d, n: None,
        name_delegate.getnames: lambda d: ()
    }
)


class Engine(object):
    """Base class representing the various behaviors of the EFILTER AST.

    Attributes:
        query: The query object this is running on.
        application_delegate: The application delegate - should be the same as
            the one on the query.
    """
    __metaclass__ = abc.ABCMeta

    ENGINES = {}

    def __init__(self, query, application_delegate=None):
        super(Engine, self).__init__()
        self.query = query
        if application_delegate:
            self.application_delegate = application_delegate
        else:
            self.application_delegate = NopAppDelegate()

    @abc.abstractmethod
    def run(self, *_, **__):
        """Execute this engine and return its result."""

    @classmethod
    def register_engine(cls, subcls, shorthand=None):
        if shorthand is None:
            shorthand = repr(subcls)

        cls.ENGINES[shorthand] = subcls

    @classmethod
    def get_engine(cls, shorthand):
        if isinstance(shorthand, type) and issubclass(shorthand, Engine):
            return shorthand

        return cls.ENGINES.get(shorthand)


class VisitorEngine(Engine):
    """Engine that implements the visitor pattern.

    Visitor engines start by calling self.visit(self.root). The default
    implementation of self.visit will walk the MRO of the expression it got
    and find the best available handler in the form of visit_<classname>.

    (This ends up trying visit_Expression as last resort and then throwing a
    TypeError if no handlers are available.)

    The actual handlers themselves are implemented by subclasses providing
    different behaviors (e.g. matcher, analyzer, etc.). Each handler is
    responsible for evaluating the branch it's passed, usually by recursively
    calling self.visit on any children and then combining the results of those
    sub-branches according to its own logic.

    For example, to implement expression.Sum (add up numbers), one would do:

        def visit_Sum(self, expr):
            result = 0
            for branch in expr.children:
                result += self.visit(branch)

            return result
    """

    def __hash__(self):
        return hash((type(self), self.query))

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.query == other.query

    def __ne__(self, other):
        return not self.__eq__(other)

    def run(self, *_, **kwargs):
        """Visitors by default visit the root of the query."""
        super(VisitorEngine, self).run()
        self.node = self.query.root
        return self.visit(self.node, **kwargs)

    def fall_through(self, node, engine_shorthand, **kwargs):
        """A visitor only implementing part of the AST can delegate with this.

        If a visitor engine only implemenets a subset of the AST language, it
        becomes useful to delegate to other visitor classes for subbranches the
        original visitor cannot handle.

        Arguments:
            node: The subbranch to be handled by the other visitor.
            engine_shorthand: The shorthand name of the other visitor.
            kwargs: Are passed on verbatim.

        Returns:
            Whatever the other visitor engine returns.
        """
        engine_cls = type(self).get_engine(engine_shorthand)
        if not issubclass(engine_cls, VisitorEngine):
            raise TypeError(
                "VisitorEngine can only fall through to other VisitorEngines.")

        engine = engine_cls(query=self.query,
                            application_delegate=self.application_delegate)
        return engine.visit(node, **kwargs)

    def visit(self, node, **kwargs):
        """Visit the AST node by calling as specific a handler as we have."""
        # Walk the MRO and try to find a closest match for handler.
        for cls in type(node).mro():
            handler_name = "visit_%s" % cls.__name__
            handler = getattr(self, handler_name, None)

            if callable(handler):
                return handler(node, **kwargs)

        # No appropriate handler for this class. Explode.
        raise ValueError(
            "Visitor engine %s has no handler for node %r of %r." %
            (type(self).__name__, node, self.query))
