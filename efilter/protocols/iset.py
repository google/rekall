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

from efilter.protocols import eq

# Declarations:
# pylint: disable=unused-argument


@dispatch.polymorphic
def union(x, y):
    raise NotImplementedError()


@dispatch.polymorphic
def intersection(x, y):
    raise NotImplementedError()


@dispatch.polymorphic
def difference(x, y):
    raise NotImplementedError()


@dispatch.polymorphic
def issuperset(x, y):
    raise NotImplementedError()


@dispatch.polymorphic
def issubset(x, y):
    return issuperset(y, x)


@dispatch.polymorphic
def isstrictsuperset(x, y):
    return issuperset(x, y) and eq.ne(x, y)


@dispatch.polymorphic
def isstrictsubset(x, y):
    return isstrictsuperset(y, x)


@dispatch.polymorphic
def contains(s, e):
    raise NotImplementedError()


class ISet(protocol.Protocol):
    _protocol_functions = (union, intersection, difference, issuperset,
                           contains)


# Default implementations:

ISet.implement(
    for_types=(set, frozenset),
    implementations={
        union: lambda x, y: x | frozenset(y),
        intersection: lambda x, y: x & frozenset(y),
        difference: lambda x, y: x - frozenset(y),
        issuperset: lambda x, y: x >= frozenset(y),
        contains: lambda s, e: e in s
    }
)


ISet.implement(
    for_types=(list, tuple),
    implementations={
        union: lambda x, y: frozenset(x) | frozenset(y),
        intersection: lambda x, y: frozenset(x) & frozenset(y),
        difference: lambda x, y: frozenset(x) - frozenset(y),
        issuperset: lambda x, y: frozenset(x) >= frozenset(y),
        contains: lambda s, e: e in s
    }
)
