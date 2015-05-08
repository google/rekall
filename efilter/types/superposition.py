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

"""EFILTER abstract type system."""

from efilter import dispatch
from efilter import protocol

# Declarations:
# pylint: disable=unused-argument


@dispatch.polymorphic
def superposition(first_state, *states):
    """Build a superposition of arguments."""
    raise NotImplementedError()


@dispatch.polymorphic
def getstates(x):
    """Return a collection of the possible states of x."""
    raise NotImplementedError()


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
def state_apply(x, f):
    """Apply f to each state of x and return a new superposition of results."""
    raise NotImplementedError()


@dispatch.polymorphic
def insuperposition(x):
    """Is x a superposition AND does it have more than one state?"""
    return isinstance(x, ISuperposition) and len(getstates(x)) > 1


class ISuperposition(protocol.Protocol):
    _protocol_functions = (getstates, state_type, state_union,
                           state_intersection, state_apply)

# Implementation for scalars:
# pylint: disable=unnecessary-lambda
ISuperposition.implement(
    for_type=protocol.AnyType,
    implementations={
        getstates: lambda x: (x,),
        state_type: lambda x: type(x),
        state_union: lambda x, y: superposition(x, y),
        state_intersection: lambda x, y: x if x == y else None,
        state_apply: lambda x, f: f(x)
    }
)
