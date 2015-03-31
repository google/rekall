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

# pylint: disable=protected-access

"""
The Rekall Entity Layer.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"


from rekall.entities import types

from rekall.entities.ext import indexset


def FastSuperpositionCompare(x, y):
    if isinstance(x, BaseSuperposition):
        return x.issuperset(y)
    elif isinstance(y, BaseSuperposition):
        return y.issubset(x)
    else:
        return x == y


class BaseSuperposition(object):
    _backing_container = None
    typedesc = None

    def __init__(self, typedesc, variants):
        self.typedesc = types.TypeFactory(typedesc)
        self._backing_container = self._make_container(variants)

    def _make_container(self, variants):
        raise NotImplementedError("Subclasses must override.")

    def _typecheck(self, other):
        if not isinstance(other, BaseSuperposition):
            raise TypeError(
                "%s cannot compare with %s.", type(self), type(other))

        if self.typedesc != other.typedesc:
            raise TypeError(
                "Cannot compare %s to %s." % (self.type_name, other.type_name))

    def union(self, other):
        self._typecheck(other)

        return type(self)(self.typedesc, self.variants.union(other.variants))

    def add(self, value):
        self._backing_container.add(self.typedesc.coerce(value))

    @property
    def type_name(self):
        return self.typedesc.type_name

    def coerce(self, value):
        if isinstance(value, BaseSuperposition):
            self._typecheck(value)
            return value, False

        return self.typedesc.coerce(value), True

    def __contains__(self, value):
        return self.typedesc.coerce(value) in self._backing_container

    def __iter__(self):
        return iter(self._backing_container)

    def __nonzero__(self):
        return len(self) > 0

    def __len__(self):
        return len(self._backing_container)

    def __unicode__(self):
        if len(self) == 1:
            for variant in self:
                return unicode(variant)

        results = [unicode(variant) for variant in self]
        return "%s (%d values)" % (", ".join(results), len(results))

    def __repr__(self):
        return "%s(typedesc=%s, variants=%s)" % (
            type(self).__name__,
            repr(self.typedesc),
            repr(list(iter(self))))

    def issuperset(self, other):
        other, isscalar = self.coerce(other)
        if isscalar:
            return other in self

        return self._backing_container.issuperset(other._backing_container)

    def issubset(self, other):
        other, isscalar = self.coerce(other)
        if isscalar:
            # Subset should still return true if we're equal to the other value
            # (it's a <= comparison, not a <).
            if len(self._backing_container) != 1:
                return False

            for variant in self:
                return variant == other

        return self._backing_container.issubset(other._backing_container)

    def __eq__(self, other):
        other, isscalar = self.coerce(other)
        if isscalar:
            for variant in self:
                if variant == other:
                    return True

            return False

        return (sorted(self._backing_container) ==
                sorted(other._backing_container))

    def __ne__(self, other):
        return not self.__eq__(other)

    @classmethod
    def impl_for_type(cls, typedesc):
        if typedesc.type_name == "Entity":
            return EntitySuperposition
        if typedesc.type_name == "Identity":
            return IndexedSuperposition
        elif hasattr(getattr(typedesc, "type_cls", None), "__hash__"):
            return HashableSuperposition
        else:
            return ListSuperposition

    @classmethod
    def merge_values(cls, variants, typedesc):
        instance = cls(typedesc, ())
        for variant in variants:
            if variant is None:
                continue
            elif isinstance(variant, cls):
                instance = instance.union(variant)
            else:
                instance.add(variant)

        if len(instance) == 0:
            return None

        if len(instance) == 1:
            for variant in iter(instance):
                return variant

        return instance


class HashableSuperposition(BaseSuperposition):
    def _make_container(self, variants):
        return set([self.typedesc.coerce(x) for x in variants])


class IndexedSuperposition(BaseSuperposition):
    def _make_container(self, variants):
        return indexset.IndexSet([self.typedesc.coerce(x) for x in variants])

    @property
    def indices(self):
        result = set()
        for variant in self:
            result |= set(variant.indices)

        return result


class ListSuperposition(BaseSuperposition):
    def _make_container(self, variants):
        return [self.typedesc.coerce(variant) for variant in variants]

    @classmethod
    def merge_values(cls, variants, typedesc):
        if not variants:
            return []

        ordered = [typedesc.coerce(x) for x in variants]
        ordered.sort()

        uniq = [ordered[0]]
        for i in xrange(1, len(ordered)):
            variant = ordered[i]
            if uniq[-1] != variant:
                uniq.append(variant)

        return cls(variants=uniq, typedesc=typedesc)

    def add(self, value):
        if value in self._backing_container:
            return

        self._backing_container.append(value)

    def union(self, other):
        self._typecheck(other)

        variants = self.variants[:]
        for variant in other.variants:
            if variant in variants:
                continue

            variants.append(variant)

        return type(self)(self.typedesc, variants)


class EntitySuperposition(IndexedSuperposition):
    def __init__(self, typedesc=None, variants=()):
        if not typedesc:
            typedesc = "EntityDescriptor"
        super(EntitySuperposition, self).__init__(
            typedesc=typedesc, variants=variants)

    def issuperset(self, other):
        if not super(EntitySuperposition, self).issuperset(other):
            return False

        for other_entity in iter(other):
            my_entity = self._backing_container.get(other_entity)
            if not my_entity.issuperset(other_entity):
                return False

        return True

    def get(self, key, **kwargs):
        typedesc = self.typedesc.type_cls.reflect_type(key)
        superposition_cls = self.impl_for_type(typedesc)

        vals = []
        for entity in iter(self):
            value = entity.get(key, **kwargs)
            if isinstance(value, BaseSuperposition):
                vals.extend(iter(value))
            else:
                vals.append(value)

        return superposition_cls(variants=vals, typedesc=typedesc)

    def __getitem__(self, key):
        return self.get(key)
