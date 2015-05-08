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


class Engine(object):
    """Base class representing the various behaviors of the EFILTER AST."""
    __metaclass__ = abc.ABCMeta

    ENGINES = {}

    def __init__(self, query):
        self.query = query

    @abc.abstractmethod
    def run(self, *_, **__):
        pass

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
    """Engine that implements the visitor pattern."""

    def __hash__(self):
        return hash((type(self), self.query))

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.query == other.query

    def __ne__(self, other):
        return not self.__eq__(other)

    def run(self, *_, **__):
        self.node = self.query.root
        return self.visit(self.node)

    def visit(self, node):
        # Walk the MRO and try to find a closest match for handler.
        for cls in type(node).mro():
            handler_name = "visit_%s" % cls.__name__
            handler = getattr(self, handler_name, None)

            if callable(handler):
                return handler(node)

        # No appropriate handler for this class. Explode.
        raise ValueError(
            "Visitor engine %s has no handler for node %r of %r." %
            (type(self).__name__, node, self.query))
