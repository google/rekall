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


class Expression(object):
    """Base class of the query AST.

    Behavior of the query language is encoded in the various QueryVisitor
    subclasses. Expressions themselves only contain children and an arity hint.
    """

    __abstract = True
    children = ()
    arity = 0

    def __hash__(self):
        return hash((type(self), self.children))

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.children == other.children

    def __ne__(self, other):
        return not self.__eq__(other)

    def __init__(self, *children):
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
    pass


class Binding(ValueExpression):
    """Represents a member of the evaluated object - attributes of entity."""
    pass


class ComponentLiteral(ValueExpression):
    """Evaluates to True if the component exists."""
    pass


class Complement(ValueExpression):
    """Logical NOT."""
    pass


class Let(Expression):
    """Let(BINDING, SUBQUERY) evaluates SUBQUERY with the result of BINDING.

    Example:
    # True if the parent of this process has a Timestamps component.
    Let("Process/parent", ComponentLiteral("Timestamps"))
    """

    arity = 2

    @property
    def context(self):
        return self.children[0]

    @property
    def expression(self):
        return self.children[1]


class Sorted(Expression):
    """Sorted(BINDING, SUBQUERY) sorts results of SUBQUERY by value of BINDING.

    Example:
    # Returns processes ordered by PID:
    Sorted("Process/pid", ComponentLiteral("Process"))
    """

    arity = 2

    @property
    def binding(self):
        return self.children[0]

    @property
    def expression(self):
        return self.children[1]


class VariadicExpression(Expression):
    """Represents an expression with variable arity."""

    __abstract = True
    arity = None


class Union(VariadicExpression):
    """Logical OR (variadic)."""
    pass


class Intersection(VariadicExpression):
    """Logical AND (variadic)."""
    pass


class Equivalence(VariadicExpression):
    """Logical == (variadic)."""
    pass


class Addition(VariadicExpression):
    """Arithmetic + (variadic)."""
    pass


class Multiplication(VariadicExpression):
    """Arithmetic * (variadic)."""
    pass


class OrderedSet(VariadicExpression):
    """Abstract class to represent strict and non-strict ordering."""
    __abstract = True


class StrictOrderedSet(OrderedSet):
    """Greater than relation."""
    pass


class NonStrictOrderedSet(OrderedSet):
    """Great-or-equal than relation."""
    pass
