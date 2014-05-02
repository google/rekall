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


class Superposition(object):
    """Represents multiple possible values of a single variable."""
    def __init__(self, old, new):
        self.variants = set()

        if isinstance(old, Superposition):
            self.variants.update(old.variants)
        else:
            self.variants.add(old)

        if isinstance(new, Superposition):
            self.variants.update(new.variants)
        else:
            self.variants.add(new)

    def __unicode__(self):
        return "superposition(%s)" % ", ".join([str(x) for x in self.variants])
    
    def __str__(self):
        return self.__unicode__()

    def __repr__(self):
        return self.__unicode__()


def ScalarSuperposition(x, y):
    """Takes two scalars and returns a superposition of them."""
    if None in (x, y) or x == y:
        return x or y or None

    return Superposition(x, y)


def SuperpositionMerge(x, y):
    """Merges x and y (dicts). Keeps all values of top-level conflicts.

    In case x and y both contain a top level key that maps to different values
    the new dictionary will contain, at that key, an instance of Superposition
    that holds values from both x and y.

    Apart from that distinction, this is the same as running:
      dict(x.items() + y.items())
    """
    result = dict()

    for key, val in itertools.chain(x.iteritems(), y.iteritems()):
        if result.get(key, val) != val:
            result[key] = Superposition(result[key], val)
        else:
            result[key] = val

    return result


def SuperpositionMergeNamedTuples(x, y):
    """Merges namedtuples x and y using superpositions.

    Both arguments must be of the same type.
    """
    if None in (x, y):
        return x or y or None

    tuple_cls = type(x)
    if tuple_cls != type(y):
        raise AttributeError("Cannot merge namedtuples of different types.")

    return tuple_cls(
        *[ScalarSuperposition(mx, my) for mx, my in itertools.izip(x, y)]
    )


