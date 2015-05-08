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
EFILTER abstract syntax.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import numbers

from efilter.types import associative
from efilter.types import boolean
from efilter.types import eq
from efilter.types import iset
from efilter.types import ordered


class QueryError(Exception):
    start = None
    end = None
    token = None
    query = None

    def __init__(self, query, error, start=None, end=None, token=None):
        super(QueryError, self).__init__(error)
        self.query = query
        self.token = token
        if token:
            self.start = token.start
            self.end = token.end

        # Allow caller to override start and end:
        if start:
            self.start = start

        if end:
            self.end = end

        if self.end is None and self.start is not None:
            self.end = self.start + 1

        self.error = error

    def __str__(self):
        if self.start is not None:
            return "%s\nEncountered at:\n%s >>> %s <<< %s" % (
                self.error, self.query[0:self.start],
                self.query[self.start:self.end], self.query[self.end:])

        return "%s\nQuery:\n%s" % (self.error, self.query)


class Expression(object):
    """Base class of the query AST.

    Behavior of the query language is encoded in the various QueryVisitor
    subclasses. Expressions themselves only contain children and an arity hint.
    """

    __abstract = True
    children = ()
    arity = 0
    start = None
    end = None

    def __hash__(self):
        return hash((type(self), self.children))

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.children == other.children

    def __ne__(self, other):
        return not self.__eq__(other)

    def __init__(self, *children, **kwargs):
        self.start = kwargs.pop("start", None)
        self.end = kwargs.pop("end", None)

        if kwargs:
            raise ValueError("Unexpected argument(s) %s" % kwargs.keys())

        if self.arity and len(children) != self.arity:
            raise ValueError("%d-ary expression %s passed %d children." % (
                self.arity, type(self).__name__, len(children)))

        self.children = children

    def __repr__(self):
        return "%s(%s)" % (
            type(self).__name__,
            ", ".join([repr(child) for child in self.children]))


class ValueExpression(Expression):
    """Unary expression."""
    arity = 1

    @property
    def value(self):
        return self.children[0]


class Literal(ValueExpression):
    """Represents a literal, which is to say not-an-expression."""

    type_signature = ()


class Binding(ValueExpression):
    """Represents a member of the evaluated object - attributes of entity."""

    arity = 1
    type_signature = (associative.IAssociative,)


class ComponentLiteral(ValueExpression):
    """Evaluates to True if the component exists."""


class Complement(ValueExpression):
    """Logical NOT."""

    arity = 1
    type_signature = (boolean.IBoolean,)


class Let(Expression):
    """Let(BINDING, SUBQUERY) evaluates SUBQUERY with the result of BINDING.

    Example:
    # True if the parent of this process has a Timestamps component.
    Let("Process/parent", ComponentLiteral("Timestamps"))
    """

    arity = 2
    type_signature = (associative.IAssociative, Expression)

    @property
    def context(self):
        return self.children[0]

    @property
    def expression(self):
        return self.children[1]


class LetAny(Let):
    """Like Let, but handles multiple BINDINGS using intersection semantics."""


class LetEach(Let):
    """Like Let, but handles multiple BINDINGS using union semantics."""


class VariadicExpression(Expression):
    """Represents an expression with variable arity."""

    arity = None


class Union(VariadicExpression):
    """Logical OR (variadic)."""

    type_signature = iset.ISet


class Intersection(VariadicExpression):
    """Logical AND (variadic)."""

    type_signature = iset.ISet


class Relation(VariadicExpression):
    pass


class Equivalence(Relation):
    """Logical == (variadic)."""

    type_signature = eq.IEq


class Sum(VariadicExpression):
    """Arithmetic + (variadic)."""

    type_signature = numbers.Number


class Difference(VariadicExpression):
    """Arithmetic - (variadic)."""

    type_signature = numbers.Number


class Product(VariadicExpression):
    """Arithmetic * (variadic)."""

    type_signature = numbers.Number


class Quotient(VariadicExpression):
    """Arithmetic / (variadic)."""

    type_signature = numbers.Number


class OrderedSet(Relation):
    """Abstract class to represent strict and non-strict ordering."""

    type_signature = ordered.IOrdered


class StrictOrderedSet(OrderedSet):
    """Greater than relation."""


class PartialOrderedSet(OrderedSet):
    """Great-or-equal than relation."""


class ContainmentOrder(Relation):
    """Inclusion of set 1 by set 2 and so on."""

    type_signature = iset.ISet


class Membership(Relation):
    """Membership of element in set."""

    arity = 2
    type_signature = (iset.ISet, eq.IEq)

    @property
    def element(self):
        return self.children[0]

    @property
    def set(self):
        return self.children[1]


class RegexFilter(Relation):
    @property
    def string(self):
        return self.children[0]

    @property
    def regex(self):
        return self.children[1]
