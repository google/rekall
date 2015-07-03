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

from efilter import protocol

from efilter.protocols import associative
from efilter.protocols import boolean
from efilter.protocols import eq
from efilter.protocols import iset
from efilter.protocols import ordered
from efilter.protocols import number


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

    type_signature = (protocol.AnyType,)
    return_signature = protocol.AnyType

    def __hash__(self):
        return hash((type(self), self.children))

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.children == other.children

    def __ne__(self, other):
        return not self.__eq__(other)

    def __init__(self, *children, **kwargs):
        super(Expression, self).__init__()

        self.start = kwargs.pop("start", None)
        self.end = kwargs.pop("end", None)

        if kwargs:
            raise ValueError("Unexpected argument(s) %s" % kwargs.keys())

        if self.arity and len(children) != self.arity:
            raise ValueError("%d-ary expression %s passed %d children." % (
                self.arity, type(self).__name__, len(children)))

        self.children = children

    def __repr__(self):
        if len(self.children) == 1:
            return "%s(%r)" % (type(self).__name__, self.children[0])

        lines = []
        for child in self.children:
            if isinstance(child, Expression):
                clines = [" %s" % line for line in repr(child).split("\n")]
            else:
                clines = repr(child).split("\n")
            lines.extend(clines)

        return "%s(\n%s)" % (type(self).__name__, "\n".join(lines))


class ValueExpression(Expression):
    """Unary expression."""
    arity = 1

    @property
    def value(self):
        return self.children[0]


class BinaryExpression(Expression):
    arity = 2

    @property
    def lhs(self):
        return self.children[0]

    @property
    def rhs(self):
        return self.children[1]


class VariadicExpression(Expression):
    """Represents an expression with variable arity."""

    arity = None


### Value (unary) expressions ###

class Literal(ValueExpression):
    """Represents a literal, which is to say not-an-expression."""

    type_signature = None  # Depends on literal.


class Binding(ValueExpression):
    """Represents a member of the evaluated object - attributes of entity."""

    type_signature = (associative.IAssociative,)


class ComponentLiteral(ValueExpression):
    """Evaluates to True if the component exists."""


class Complement(ValueExpression):
    """Logical NOT."""

    type_signature = (boolean.IBoolean,)
    return_signature = boolean.IBoolean


### Binary expressions ###


class Let(BinaryExpression):
    """Let(BINDING, SUBQUERY) evaluates SUBQUERY with the result of BINDING.

    Example:
    # True if the parent of this process has a Timestamps component.
    Let("Process/parent", ComponentLiteral("Timestamps"))
    """

    type_signature = (associative.IAssociative, Expression)
    return_signature = None  # Depends on rhs.

    @property
    def context(self):
        return self.lhs

    @property
    def expression(self):
        return self.rhs


class LetAny(Let):
    """Like Let, but handles multiple BINDINGS using intersection semantics."""

    return_signature = boolean.IBoolean


class LetEach(Let):
    """Like Let, but handles multiple BINDINGS using union semantics."""

    return_signature = boolean.IBoolean


class Membership(BinaryExpression):
    """Membership of element in set."""
    type_signature = (eq.IEq, iset.ISet)
    return_signature = boolean.IBoolean

    @property
    def element(self):
        return self.lhs

    @property
    def set(self):
        return self.rhs


class RegexFilter(BinaryExpression):
    type_signature = (basestring, basestring)
    return_signature = boolean.IBoolean

    @property
    def string(self):
        return self.lhs

    @property
    def regex(self):
        return self.rhs


### Variadic Expressions ###

### Logical Variadic ###

class LogicalOperation(VariadicExpression):
    type_signature = boolean.IBoolean
    return_signature = boolean.IBoolean


class Union(LogicalOperation):
    """Logical OR (variadic)."""


class Intersection(LogicalOperation):
    """Logical AND (variadic)."""


### Variadic Relations ###

class Relation(VariadicExpression):
    return_signature = boolean.IBoolean


class OrderedSet(Relation):
    """Abstract class to represent strict and non-strict ordering."""

    type_signature = ordered.IOrdered


class StrictOrderedSet(OrderedSet):
    """Greater than relation."""

    type_signature = ordered.IOrdered


class PartialOrderedSet(OrderedSet):
    """Great-or-equal than relation."""

    type_signature = ordered.IOrdered


class ContainmentOrder(Relation):
    """Inclusion of set 1 by set 2 and so on."""

    type_signature = iset.ISet


class Equivalence(Relation):
    """Logical == (variadic)."""

    type_signature = eq.IEq


### Variadic Arithmetic ###

class NumericExpression(VariadicExpression):
    """Arithmetic expressions."""

    return_signature = number.INumber


class Sum(NumericExpression):
    """Arithmetic + (variadic)."""

    type_signature = number.INumber


class Difference(NumericExpression):
    """Arithmetic - (variadic)."""

    type_signature = number.INumber


class Product(NumericExpression):
    """Arithmetic * (variadic)."""

    type_signature = number.INumber


class Quotient(NumericExpression):
    """Arithmetic / (variadic)."""

    type_signature = number.INumber
