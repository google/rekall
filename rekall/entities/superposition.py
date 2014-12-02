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


import itertools

from rekall import obj


class Superposition(object):
    """Represents multiple possible values of a single variable.

    Superpositions are used to represent merge conflicts and inconsistencies in
    a memory image. Due to a variety of factors, such as smear in acquisition,
    and differences in representation of certain objects, such inconsistencies
    are fairly common and not considered errors in Rekall.

    Superposition objects are used in two ways: they can either be created
    explicitly out of any iterable object (using the constructor), or they can
    be created implicitly as needed by one of the several merge_* class methods
    on this class.

    For example:

    Superposition.merge_scalars("foo", "bar") # returns superposition
    Superposition.merge_scalars("foo", "foo") # returns "foo"

    Once created, superpositions can be further merged, returning unions. They
    can also be used in place of the original objects in most situations - the
    __unicode__ and __repr__ functions represent the inconsistency in a
    human-readable way, and calls to __getitem__ are proxied to each of the
    variants of the superposition, returning a new superposition of the results.
    """

    def __init__(self, variants):
        self.variants = variants

    @classmethod
    def merge_scalars(cls, *scalars):
        # TODO (adam): This method should be using sets, but it currently can't,
        # because there is a requirement for implementing __hash__ expressed
        # as, in essence, A == B -> hash(A) == hash(B), and some types in
        # rekall (entities, enums, etc.) currently violate this rule.
        #
        # A robust solution to this problem is to implement a hashing protocol
        # for these types instead of trying to stick them in primitive sets
        # and dicts. Once we've done that, this method should be optimized by
        # using containers that support that hashing protocol.
        #
        # I think the following is currently O(n^2), which kind of sucks, but
        # luckily, N is almost always 2 or 3.
        variants = []
        for scalar in scalars:
            if isinstance(scalar, Superposition):
                for var in scalar.variants:
                    if var not in variants:
                        variants.append(var)
            elif scalar != None and scalar not in variants:
                variants.append(scalar)

        if len(variants) == 1:
            return variants.pop()
        elif not variants:
            return None

        return cls(set(variants))

    @classmethod
    def coerce(cls, value):
        if isinstance(value, cls):
            return value

        return cls(set([value]))

    def __unicode__(self):
        results = []
        for variant in self.variants:
            if isinstance(variant, obj.BaseObject):
                # Base object __str__ returns massive output.
                results.append(repr(variant))
            else:
                results.append(str(variant))

        return "%s (%d values)" % (", ".join(results), len(results))

    def __str__(self):
        return self.__unicode__()

    def __repr__(self):
        return self.__unicode__()

    def union(self, other):
        return Superposition(
            set(self.variants) | set(other.variants))

    def __or__(self, other):
        return self.union(other)

    def __getitem__(self, key):
        values = [variant[key] for variant in self.variants]
        return self.merge_scalars(*values)

    def __iter__(self):
        return self.variants.__iter__()

    def strict_superset(self, other):
        if not isinstance(other, Superposition):
            return other in self.variants

        return self.variants.issuperset(other.variants)


def SuperpositionMergeNamedTuples(x, y):
    """Merges namedtuples x and y using superpositions.

    Both arguments must be of the same type.
    """
    if None in (x, y):
        return x or y or None

    tuple_cls = type(x)
    if not isinstance(y, tuple_cls):
        raise ValueError("Cannot merge namedtuples of different types.")

    return tuple_cls(*[Superposition.merge_scalars(mx, my)
                       for mx, my in itertools.izip(x, y)])
