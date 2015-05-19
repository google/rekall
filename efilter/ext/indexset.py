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
Primitive types not found in Python.

This module implements a set-like container that supports multiple hashable
elems per entry.
"""


__author__ = "Adam Sindelar <adamsh@google.com>"


from efilter.protocols import indexable


class IndexSet(object):
    _backing_dict = None
    _elem_count = None

    def __init__(self, elems=()):
        self._backing_dict = dict()
        self._elem_count = 0
        for elem in elems:
            self.add(elem)

    def add(self, elem):
        duplicate_entry = False
        for index in indexable.indices(elem):
            if index in self._backing_dict:
                duplicate_entry = True

            self._backing_dict[index] = elem

        if not duplicate_entry:
            self._elem_count += 1

    def get(self, elem):
        indices = getattr(elem, "indices", None)
        if not indices:
            return None

        for index in indices:
            result = self._backing_dict.get(index)
            if result:
                return result

        return None

    def remove(self, elem):
        indices = getattr(elem, "indices", None)
        if not indices:
            raise KeyError("%s elem is not in %s.", repr(elem), repr(self))

        for index in elem.indices:
            del self._backing_dict[index]

        self._elem_count -= 1

    def discard(self, elem):
        try:
            self.remove(elem)
        except KeyError:
            return

    def pop(self):
        popped_elem = None
        for elem in self._backing_dict.itervalues():
            popped_elem = elem
            break

        self.remove(popped_elem)
        return popped_elem

    def clear(self):
        self._backing_dict = dict()
        self._elem_count = 0

    def get_index(self, index):
        return self._backing_dict.get(index)

    @property
    def indices(self):
        return self._backing_dict.keys()

    @property
    def values(self):
        return list(self)

    def isdisjoint(self, other):
        return not self.intersection(other)

    def issubset(self, other):
        for elem in self:
            if not elem in other:
                return False

        return True

    def issuperset(self, other):
        return other.issubset(self)

    def update(self, other):
        for elem in other:
            if elem in self:
                continue

            self.add(elem)

        return self

    def union(self, other):
        result = type(self)(self._backing_dict.itervalues())
        for elem in other:
            if elem in result:
                continue

            result.add(elem)

        return result

    def intersection(self, other):
        result = type(self)()
        for elem in self:
            if elem in other:
                result.add(elem)

        return result

    def intersection_update(self, other):
        for elem in list(self):
            if not elem in other:
                self.remove(elem)

        return self

    def difference(self, other):
        result = type(self)()
        for elem in self:
            if not elem in other:
                result.add(elem)

        return result

    def difference_update(self, other):
        for elem in other:
            self.remove(elem)

        return self

    def __contains__(self, elem):
        if self.get(elem) is not None:
            return True

        return False

    def __repr__(self):
        return "FrozenSet(%s)" % ", ".join([repr(elem) for elem in self])

    def __len__(self):
        return self._elem_count

    def __iter__(self):
        seen = set()

        for elem in self._backing_dict.itervalues():
            indices = set(indexable.indices(elem))
            if seen & indices:
                continue

            yield elem
            seen |= indices

    def __eq__(self, other):
        return sorted(self.indices) == sorted(other.indices)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __nonzero__(self):
        return self._elem_count > 0

    def __lt__(self, other):
        return self != other and self.issubset(other)

    def __gt__(self, other):
        return self != other and self.issuperset(other)

    def __le__(self, other):
        return self.issubset(other)

    def __ge__(self, other):
        return self.issuperset(other)

    def __or__(self, other):
        return self.union(other)

    def __sub__(self, other):
        return self.difference(other)

    def __and__(self, other):
        return self.intersection(other)

    def __ior__(self, other):
        return self.update(other)

    def __iand__(self, other):
        return self.intersection_update(other)

    def __isub__(self, other):
        return self.difference_update(other)

indexable.IIndexable.implemented(for_type=IndexSet)
