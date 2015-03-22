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


from rekall.entities.query import expression


class IdentityError(RuntimeError):
    pass


class Identity(object):
    """Uniquely identifies something like a process or a user.

    Instantiate with:
    - global_prefix: The universe this identity belongs to.
    - indices: Iterable of tuples of (prefix, attribute_name, value) that
        identify some entity.
    """

    global_prefix = None
    key_canary = None  # Set of attributes references in indices.
    indices = None  # Set of tuples of (global_prefix, attribute, value).
    first_index = None  # Used for hashing.

    @classmethod
    def from_dict(cls, global_prefix, identity_dict):
        indices = []
        for key, val in identity_dict.iteritems():
            if val == None:
                raise IdentityError(
                    "Identity index value for %s cannot be None." % key)

            indices.append((global_prefix, key, val))

        return cls(indices, global_prefix)

    def as_query(self):
        """A query that'll match entities with this identity."""
        union = []
        for _, keys, vals in self.indices:
            if isinstance(keys, tuple):
                intersection = []
                for idx, key in enumerate(keys):
                    intersection.append(
                        expression.Equivalence(
                            expression.Binding(key),
                            expression.Literal(vals[idx])))

                union.append(expression.Intersection(*intersection))
            else:
                union.append(expression.Equivalence(
                    expression.Binding(keys),
                    expression.Literal(vals)))

        if len(union) == 1:
            return union[0]

        return expression.Union(*union)

    def __init__(self, indices=None, global_prefix=None):
        self.key_canary = frozenset([attribute for _, attribute, _ in indices])
        self.indices = frozenset(indices)
        self.global_prefix = global_prefix

        for index in indices:
            self.first_index = index
            break

    def __hash__(self):
        """Hashing an identity has a big caveat.

        Because an identity is hashed on all of its indices, and comparisons
        between identities are done by intersection of indices, it is possible
        for two identities to have different hashes and still be equal if
        compared. This is fine in certain cases, such as with identities
        retrieved from the EntityManager (because they're already merged and
        therefore unique) but may result in unexpected behavior with identities
        made up outside of the normal collection mechanism.
        """
        return hash(self.first_index)

    def __eq__(self, other):
        if ((not isinstance(other, Identity)) or
                (self.global_prefix != other.global_prefix)):
            return False

        matching_keys = self.key_canary & other.key_canary
        if not matching_keys:
            return None  # No overlap - undecidable.

        matching_indices = self.indices & other.indices
        if not matching_indices:
            return False

        # If some keys matched but not others then that's a consistency error
        # most likely caused by faulty collector logic. By blowing up here
        # we preserve the integrity of the database, but this is a programmer
        # error and likely means that the data isn't reliable anyway.
        if len(matching_keys) != len(matching_indices):
            raise IdentityError(
                "Identity logic error! Identity %s matches %s on %d keys, "
                "but on %d values." % (
                    self, other, len(matching_keys), len(matching_indices)))

        return True

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is None:
            return None

        return not result

    def __unicode__(self):
        return "Identity(%s)" % ", ".join([repr(x) for x in self.indices])

    def __str__(self):
        return self.__unicode__()

    def __repr__(self):
        return self.__unicode__()

    def __or__(self, other):
        return self.union(other)

    def union(self, other):
        if self != other:
            raise IdentityError(
                "Attempting to merge identities %s and %s which are unequal.",
                self, other)

        return Identity(indices=self.indices | other.indices,
                        global_prefix=self.global_prefix)
