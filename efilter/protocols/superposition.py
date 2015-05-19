# -*- coding: utf-8 -*-

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

"""EFILTER abstract type system.

The superposition protocol concerns itself with variables that may have several
possible values, and it is unclear which value is the correct one, or whether
there even is a correct value.

Real-world examples of when this happens include merge conflicts, roots of
quadratic equations, and programmers suffering from pathological inability to
make decisions.
"""

from efilter import dispatch
from efilter import protocol

from efilter.protocols import eq

# Declarations:
# pylint: disable=unused-argument


@dispatch.polymorphic
def superposition(first_state, *states):
    """Build a superposition of states, all of which must be the same type."""
    raise NotImplementedError()


def meld(*states):
    """Returns a superposition of states, or the state if all args are equal.

    This is a convenience function, equivalent to calling
    getstate(superposition(x)) to get x.

    This function skips over instances of None in states (None is not allowed)
    in superpositions.

    Examples:
        meld("foo", "bar") # => HashedSuperposition("foo", "bar")
        meld("foo", "foo") # => "foo"
        meld("foo", None) # => "foo"
        meld(None) # => None
    """
    states = [x for x in states if x is not None]
    if not states:
        return None

    s = superposition(*states)
    if insuperposition(s):
        return s

    return getstate(s)


@dispatch.polymorphic
def getstates(x):
    """Return a collection of the possible states of x."""
    raise NotImplementedError()


def getstate(x):
    """Return the state of x, or raise exception if x is in superposition."""
    if insuperposition(x):
        raise TypeError(
            "Ambiguous call to getstate for %r which has more than one state."
            % x)

    for state in getstates(x):
        return state


@dispatch.polymorphic
def state_type(x):
    """Return the type (class) of the states of x."""
    raise NotImplementedError()


@dispatch.polymorphic
def state_union(x, y):
    """Return a new superposition with the union of states."""
    raise NotImplementedError()


@dispatch.polymorphic
def state_intersection(x, y):
    """Return a new superposition with the intersection of states."""
    raise NotImplementedError()


@dispatch.polymorphic
def state_difference(x, y):
    """Return a new superposition with the difference of states of x and y."""
    raise NotImplementedError()


@dispatch.polymorphic
def hasstate(sp, state):
    """Does superposition have the (scalar) state?

    Calling this with a state that is, itself, a superposition must return
    False. (Use state_superset for comparing two superpositions in a similar
    fashion.)
    """
    raise NotImplementedError()


@dispatch.polymorphic
def state_eq(x, y):
    """Are the states of x and y exactly the same?"""
    raise NotImplementedError()


@dispatch.polymorphic
def state_superset(x, y):
    """Are the states of x a superset of the states of y?"""
    raise NotImplementedError()


@dispatch.polymorphic
def state_subset(x, y):
    """Optional: are the states of x a subset of the states of y?"""
    return state_superset(y, x)


@dispatch.polymorphic
def state_strictsuperset(x, y):
    """Optional: Are the states of x a strict superset of the states of y?"""
    return state_superset(x, y) and not state_eq(x, y)


@dispatch.polymorphic
def state_strictsubset(x, y):
    """Optional: Are the states of x a strict subset of the states of y?"""
    return state_strictsuperset(y, x)


@dispatch.polymorphic
def state_apply(x, f):
    """Apply f to each state of x and return a new superposition of results."""
    raise NotImplementedError()


@dispatch.polymorphic
def insuperposition(x):
    """Optional: Is x a superposition AND does it have more than one state?"""
    return isinstance(x, ISuperposition) and len(getstates(x)) > 1


class ISuperposition(protocol.Protocol):
    _protocol_functions = (getstates, state_type, state_union,
                           state_intersection, state_difference, hasstate,
                           state_eq, state_superset, state_apply)


def _scalar_hasstate(sp, state):
    if insuperposition(state):
        raise TypeError(
            "2nd argument to hasstate must not be in superposition. Got %r."
            % state)

    return state_eq(sp, state)


def _scalar_state_eq(x, y):
    if insuperposition(y):
        return False

    return eq.eq(x, getstate(y))


# Implementation for scalars:
# pylint: disable=unnecessary-lambda
ISuperposition.implement(
    for_type=protocol.AnyType,
    implementations={
        getstates: lambda x: (x,),
        state_type: lambda x: type(x),
        state_union: lambda x, y: superposition(x, y),
        state_intersection: lambda x, y: x if hasstate(y, x) else None,
        state_difference: lambda x, y: None if hasstate(y, x) else x,
        hasstate: _scalar_hasstate,
        state_eq: _scalar_state_eq,
        state_superset: lambda x, y: state_eq(x, y),
        state_apply: lambda x, f: f(x)
    }
)
