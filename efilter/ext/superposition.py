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
EFILTER type system.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter.types import indexable
from efilter.types import hashable
from efilter.types import superposition

from efilter.ext import indexset


# pylint: disable=protected-access
class DelegatingSuperposition(object):
    """Superposition implementation using a container type (set or similar.)"""
    _state_type = None
    _delegate = None

    def __init__(self, first_state=None, *states):
        self._initialize_delegate()

        if first_state is None:
            return

        self._state_type = superposition.state_type(first_state)
        self.add_state(first_state)

        for state in states:
            if type(state) != self.state_type():
                raise TypeError(
                    "All states of a superposition must be of the same type."
                    " First argument was of type %r, but argument %r is of "
                    " type %r." %
                    (self.state_type, state, type(state)))
            self.add_state(state)

    def _initialize_delegate(self):
        """Override in subclasses."""
        raise NotImplementedError()

    def add_state(self, state):
        for state_ in superposition.getstates(state):
            self._add_state(state_)

    def _add_state(self, state):
        """Override in subclasses."""
        raise NotImplementedError()

    def getstates(self):
        return self._delegate

    def state_type(self):
        return self._state_type

    def union(self, other):
        other_type = superposition.state_type(other)
        if other_type != self._state_type:
            raise TypeError(
                "Can't join %r of state type %r with %r of state type %r."
                % (other, other_type, self, self._state_type))

        other_states = superposition.getstates(other)

        result = type(self)()
        result._delegate = self._delegate.union(set(other_states))
        result._state_type = self._state_type
        return result

    def intersection(self, other):
        other_type = superposition.state_type(other)
        if other_type != self._state_type:
            raise TypeError(
                "Can't intersect %r of state type %r with %r of state "
                "type %r." % (other, other_type, self, self._state_type))

        other_states = superposition.getstates(other)

        result = type(self)()
        result._delegate = self._delegate.intersection(set(other_states))
        result._state_type = self._state_type
        return result

    def apply(self, f):
        return superposition.superposition(*[f(x) for x in self.getstates()])

    def __repr__(self):
        return "%s(%s)" % (type(self).__name__,
                           ", ".join([repr(s) for s in self.getstates()]))


superposition.ISuperposition.implement(
    for_type=DelegatingSuperposition,
    implementations={
        superposition.getstates: DelegatingSuperposition.getstates,
        superposition.state_union: DelegatingSuperposition.union,
        superposition.state_intersection: DelegatingSuperposition.intersection,
        superposition.state_apply: DelegatingSuperposition.apply,
        superposition.state_type: DelegatingSuperposition.state_type
    }
)


class HashedSuperposition(DelegatingSuperposition):
    def _initialize_delegate(self):
        self._delegate = set()

    def _add_state(self, state):
        self._delegate.add(state)

    def indices(self):
        result = set()
        for state in self._delegate:
            result.add(state)

        return result

superposition.superposition.implement(
    for_type=hashable.IHashable,
    implementation=HashedSuperposition)


class IndexedSuperposition(DelegatingSuperposition):
    def _initialize_delegate(self):
        self._delegate = indexset.IndexSet()

    def _add_state(self, state):
        self._delegate.add(state)

    def indices(self):
        result = set()
        for state in self._delegate:
            result |= frozenset(indexable.indices(state))

        return result

superposition.superposition.implement(
    for_type=indexable.IIndexable,
    implementation=IndexedSuperposition)


# Make sure we're hashing anything we can hash, because it's faster.
superposition.superposition.prefer_type(
    hashable.IHashable,
    over=indexable.IIndexable)
