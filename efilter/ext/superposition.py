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

from efilter.protocols import indexable
from efilter.protocols import hashable
from efilter.protocols import superposition

from efilter.ext import indexset


# pylint: disable=protected-access
class DelegatingSuperposition(object):
    """Superposition implementation using a container type (set or similar.)"""

    _state_type = None
    _delegate = None

    def __init__(self, first_state=None, *states):
        self._delegate = self._make_delegate()

        if first_state is None:
            return

        self._state_type = superposition.state_type(first_state)
        self.add_state(first_state)

        for state in states:
            if superposition.state_type(state) != self.state_type():
                raise TypeError(
                    "All states of a superposition must be of the same type."
                    " First argument was of type %r, but argument %r is of "
                    " type %r." %
                    (self.state_type(), state,
                     superposition.state_type(state)))
            self.add_state(state)

    def _make_delegate(self):
        """Instantiate the container we store states in and return it.

        Currently, the container must behave like a Python set, in that it
        supports all the standard Python set opetations.
        """
        raise NotImplementedError("Subclasses must override.")

    def add_state(self, state):
        """Add state to this superposition.

        WARNING: this mutates the object (it's NOT copy on write). Unless
        you're absolutely certain of what you're doing, you most likely want
        to call superposition.state_union(sp, state) instead.
        """
        for state_ in superposition.getstates(state):
            self._add_state(state_)

    def _add_state(self, state):
        """Add state to self._delegate."""
        raise NotImplementedError("Subclasses must override.")

    def getstates(self):
        return self._delegate

    def hasstate(self, state):
        return state in self._delegate

    def state_type(self):
        return self._state_type

    def state_eq(self, other):
        if isinstance(other, type(self)):
            return self._delegate == other._delegate

        return sorted(self._delegate) == sorted(superposition.getstates(other))

    def __eq__(self, other):
        if not isinstance(other, superposition.ISuperposition):
            return False

        return self.state_eq(other)

    def __ne__(self, other):
        return not self == other

    def indices(self):
        raise NotImplementedError("Subclasses must override.")

    def _typecheck(self, other, operation="compare"):
        other_type = superposition.state_type(other)
        if other_type != self._state_type:
            raise TypeError(
                "Can't %s %r of state type %r with %r of state type %r."
                % (operation, other, other_type, self, self._state_type))

    def union(self, other):
        self._typecheck(other, "join")

        other_states = self._make_delegate()
        other_states.update(superposition.getstates(other))
        other_states.update(self._delegate)

        return type(self)(*other_states)

    def intersection(self, other):
        self._typecheck(other, "intersect")

        other_states = self._make_delegate()
        other_states.update(superposition.getstates(other))

        return type(self)(*(self._delegate & other_states))

    def difference(self, other):
        self._typecheck(other, "subtract")

        other_states = self._make_delegate()
        new_states = self._delegate - other_states

        return type(self)(*new_states)

    def issuperset(self, other):
        if isinstance(other, type(self)):
            return self._delegate >= other._delegate

        if not superposition.insuperposition(other):
            return self.hasstate(superposition.getstate(other))

        other_states = self._make_delegate()
        other_states.update(superposition.getstates(other))

        return self._delegate >= other_states

    def apply(self, f):
        return superposition.superposition(*[f(x) for x in self.getstates()])

    def __repr__(self):
        return "%s(%s)" % (type(self).__name__,
                           ", ".join([repr(s) for s in self.getstates()]))


superposition.ISuperposition.implement(
    for_type=DelegatingSuperposition,
    implementations={
        superposition.getstates: DelegatingSuperposition.getstates,
        superposition.state_type: DelegatingSuperposition.state_type,
        superposition.state_union: DelegatingSuperposition.union,
        superposition.state_intersection: DelegatingSuperposition.intersection,
        superposition.state_difference: DelegatingSuperposition.difference,
        superposition.hasstate: DelegatingSuperposition.hasstate,
        superposition.state_eq: DelegatingSuperposition.state_eq,
        superposition.state_superset: DelegatingSuperposition.issuperset,
        superposition.state_apply: DelegatingSuperposition.apply
    }
)


indexable.IIndexable.implement(
    for_type=DelegatingSuperposition,
    implementations={
        indexable.indices: DelegatingSuperposition.indices
    }
)


class HashedSuperposition(DelegatingSuperposition):
    def _make_delegate(self):
        return set()

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
    def _make_delegate(self):
        return indexset.IndexSet()

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
