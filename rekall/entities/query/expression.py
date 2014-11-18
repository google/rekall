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
    return_types = frozenset(["expression"])

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
    __abstract = True
    arity = 1

    @property
    def value(self):
        return self.children[0]


class Literal(ValueExpression):
    """Represents a literal, which is to say not-an-expression."""

    return_types = frozenset([None])


class Binding(ValueExpression):
    """Represents a member of the evaluated object - attributes of entity."""

    return_types = frozenset([None])


class ComponentLiteral(ValueExpression):
    """Evaluates to True if the component exists."""
    pass


class Complement(ValueExpression):
    """Logical NOT."""
    return_types = frozenset(["bool"])


class Let(Expression):
    """Let(BINDING, SUBQUERY) evaluates SUBQUERY with the result of BINDING.

    Example:
    # True if the parent of this process has a Timestamps component.
    Let("Process/parent", ComponentLiteral("Timestamps"))
    """

    return_types = frozenset(["bool"])
    arity = 2

    @property
    def context(self):
        return self.children[0]

    @property
    def expression(self):
        return self.children[1]


class LetAny(Let):
    """Like Let, but handles multiple BINDINGS using intersection semantics."""
    pass


class LetEach(Let):
    """Like Let, but handles multiple BINDINGS using union semantics."""
    pass


class VariadicExpression(Expression):
    """Represents an expression with variable arity."""

    __abstract = True
    arity = None


class Union(VariadicExpression):
    """Logical OR (variadic)."""

    return_types = frozenset(["bool"])


class Intersection(VariadicExpression):
    """Logical AND (variadic)."""

    return_types = frozenset(["bool"])


class Relation(VariadicExpression):
    __abstract = True

    return_types = frozenset(["bool"])


class Equivalence(Relation):
    """Logical == (variadic)."""
    pass


class Sum(VariadicExpression):
    """Arithmetic + (variadic)."""
    return_types = frozenset(["int", "long", "float", "complex"])


class Difference(VariadicExpression):
    """Arithmetic - (variadic)."""
    return_types = frozenset(["int", "long", "float", "complex"])


class Product(VariadicExpression):
    """Arithmetic * (variadic)."""
    return_types = frozenset(["int", "long", "float", "complex"])


class Quotient(VariadicExpression):
    """Arithmetic / (variadic)."""
    return_types = frozenset(["int", "long", "float", "complex"])


class OrderedSet(Relation):
    """Abstract class to represent strict and non-strict ordering."""
    __abstract = True


class StrictOrderedSet(OrderedSet):
    """Greater than relation."""
    pass


class PartialOrderedSet(OrderedSet):
    """Great-or-equal than relation."""
    pass


class ContainmentOrder(Relation):
    """Inclusion of set 1 by set 2 and so on."""
    pass


class Membership(Relation):
    """Membership of element in set."""
    return_types = frozenset(["bool"])

    @property
    def element(self):
        return self.children[0]

    @property
    def set(self):
        return self.children[1]


class RegexFilter(Relation):
    return_types = frozenset(["bool"])

    @property
    def string(self):
        return self.children[0]

    @property
    def regex(self):
        return self.children[1]
