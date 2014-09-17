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
Provides facilities for non-destructive merging of collections.
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
        variants = set()
        for scalar in scalars:
            if isinstance(scalar, Superposition):
                variants.update(scalar.variants)
            elif scalar:
                variants.add(scalar)

        if len(variants) == 1:
            return variants.pop()
        elif not variants:
            return obj.NoneObject(
                "No non-null scalars in merge.")

        return cls(variants)

    def __unicode__(self):
        results = [str(x) for x in self.variants]
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
        return Superposition(variants=values)

    def __iter__(self):
        return self.variants.__iter__()


def SuperpositionMergeNamedTuples(x, y):
    """Merges namedtuples x and y using superpositions.

    Both arguments must be of the same type.
    """
    if None in (x, y):
        return x or y or None

    tuple_cls = type(x)
    if tuple_cls != type(y):
        raise ValueError("Cannot merge namedtuples of different types.")

    return tuple_cls(
        *[Superposition.merge_scalars(mx, my)
            for mx, my in itertools.izip(x, y)])
