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


class Identity(object):
    """Uniquely identifies something like a process or a user.

    When collecting information about a system, data that relates to the same
    conceptual entity, such as a user or a network connection, can come from
    multiple sources. In such cases, this class provides a way of uniquelly
    identifying the conceptual entities (such as users, processes, connections,
    etc.) to make it easier to view information about them in one place, even
    when it was collected using different algorithms.

    Identities can be either scalar or vector. Scalar identities wrap around a
    single piece of information, typically a numeric ID or a memory offset and
    use that for comparisons and hashing. Vector identities have more than one
    way of identifying the object. For example, a user may be identified by
    either their UID or their username, with each being equally valid and
    unique (within the scope of one system).
    """

    def __init__(self):
        pass

    def __eq__(self, other):
        """Is this identity equivalent to the other identity?

        Returns:
            Scalar identities should return True or False (never None).

            Vector identities may return None when the question is
            undecidable right now, but may be decidable at a later time.

            Example - let x be a user identified by the UID 37 and y be a user
            identified by the username "Alice". X and y both posses valid
            identifiers of a user, but they are not comparable until we set
            username on x or UID on y.
        """
        pass

    def __ne__(self, other):
        """Three-valued not equal predicate."""
        eq = self.__eq__(other)

        if eq is None:
            return None  # Three-valued logic sentinel for unknown.

        return not eq

    def union(self, other):
        """Return a new identity that's a union of self and other.

        Self and other should be equivalent (self.__eq__(other) returns True).

        Returns:
            Scalar identities should return self.

            Vector identities should return a new identity instance,
            combining the known keys from self and other in a union of both.

        Note on immutability:
            Identities are immmutable. If you override this method you MUST
            return a new identity and you MUST NOT modify self or other.
        """
        _ = other
        return self

    @property
    def indices(self):
        """Set of hashable keys that can be used to index this identity.

        Returns:
            Scalar identities should implement this same as __hash__, with one
            difference: instead of the value itself, return the value wrapped
            in a tuple like so: (value,)

            Vector identities should return a set (or other iterable) of
            valid key values. Usually, this is one per non-null member of the
            identity vector/tuple.
        """
        return set([self.__unicode__()])

    def __hash__(self):
        """Hashes the identity with a caveat. Don't use, unless you know how.

        WARNING: This has an unexpected property, which is that alternate
        identities may be equal to each other and yet have different hashes.
        This probably breaks whatever scheme you had in mind that used entities
        as keys. My advice to you is to just use EntityManager and not worry
        about it. The only reason __hash__ is implemented on identity is
        because it allows for some optimizations with sets in
        EntityLookupTable. """
        return hash(self.__unicode__())

    def __unicode__(self):
        pass

    def __str__(self):
        return self.__unicode__()

    def __repr__(self):
        return self.__unicode__()

    def __or__(self, other):
        return self.union(other)


class UniqueObject(object):
    def __eq__(self, other):
        return self is other

    def __hash__(self):
        return id(self)


class UniqueIdentity(Identity):
    def __init__(self, global_prefix=None):
        super(UniqueIdentity, self).__init__()
        self.global_prefix = global_prefix
        self.index = UniqueObject()

    def __unicode__(self):
        return "<unique %d>" % id(self.index)

    def __hash__(self):
        return id(self.index)

    @property
    def indices(self):
        return (self.index,)

    def __eq__(self, other):
        return False


class AlternateIdentity(Identity):
    """Identifies an entity using any one of the keys in identity dict.

    Note that alterante identities are used where an entity can be identified
    by any of multiple *unique* candidate keys, such as a user being identified
    by either a username or their UID. If you create two alternate identities
    that match on one key but mismatch on another key then undefined behavior
    will result. (In the above example, this would be equivalent to two users
    with the same UID but different usernames.)

    If you need to express an AND-like relationship use a tuple attribute
    (For example, two memory addresses are equivalent if their offsets are the
    same *and* their DTB value is the same.)
    """

    def __init__(self, identity_dict=None, global_prefix=None):
        super(AlternateIdentity, self).__init__()
        self.global_prefix = global_prefix
        self.identity_dict = identity_dict
        self._indices = set(self.indices_from_dict(global_prefix=global_prefix,
                                                   identity_dict=identity_dict))

        # Used to quickly rule out equality checks.
        self.key_canary = set(identity_dict)

    @staticmethod
    def indices_from_dict(global_prefix, identity_dict):
        for attribute, value in identity_dict.iteritems():
            if value == None:
                raise ValueError(
                    "None (%s) cannot be used as index." % value)

            indices = getattr(value, "indices", None)
            if indices:
                # This means the value supports indexing, like an identity or
                # a base object.
                for index in indices:
                    yield (global_prefix, attribute, index)
            else:
                # The value itself is an index.
                yield (global_prefix, attribute, value)

    def __eq__(self, other):
        if ((not isinstance(other, AlternateIdentity)) or
                (self.global_prefix != other.global_prefix)):
            return False

        matching_keys = self.key_canary & other.key_canary
        if not matching_keys:
            return None  # Undecidable - no key overlap.

        matching_indices = self.indices & other.indices
        if not matching_indices:
            return False

        # If some keys matched but not others then that's a consistency error
        # most likely caused by faulty collector logic. By blowing up here
        # we preserve the integrity of the database, but this is a programmer
        # error and likely means that the data isn't reliable anyway.
        if len(matching_keys) != len(matching_indices):
            raise RuntimeError(
                "Identity logic error! Identity %s matches %s on %d keys, "
                "but only %d values." % (
                    self, other, len(matching_keys), len(matching_indices)))

        return True

    @property
    def indices(self):
        return self._indices

    def __unicode__(self):
        return "(%s)" % ";".join(["%s/%s=%s" % x for x in self.indices])

    def union(self, other):
        if self != other:
            raise RuntimeError(
                "Attempting to merge identities %s and %s which are unequal.",
                self, other)

        return AlternateIdentity(
            identity_dict=dict(
                self.identity_dict.items() + other.identity_dict.items()),
            global_prefix=self.global_prefix)
