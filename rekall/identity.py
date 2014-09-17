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
The Rekall Memory Forensics entity layer.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall import obj


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


class SimpleIdentity(Identity):
    def __init__(self, attribute, value, global_prefix=None):
        super(SimpleIdentity, self).__init__()
        self.id_path = "%s/%s=%s" % (
            global_prefix,
            attribute,
            value)

        self.attribute = attribute
        self.value = value
        self.global_prefix = global_prefix

    def __eq__(self, other):
        if not isinstance(other, SimpleIdentity):
            return False

        return self.id_path == other.id_path

    def __unicode__(self):
        return self.id_path


class AlternateIdentity(Identity):
    """Identifies an entity using any one of the keys in identity dict.

    Note that alterante identities are used where an entity can be identified
    by any of multiple *unique* candidate keys, such as a user being identified
    by either a username or their UID. If you create two alternate identities
    that match on one key but mismatch on another key then undefined behavior
    will result. (In the above example, this would be equivalent to two users
    with the same UID but different usernames.)

    If you need to express an AND-like relationship use a SimpleIdentity with
    a tuple attribute. (For example, two memory addresses are equivalent if
    their offsets are the same *and* their DTB value is the same.)
    """
    def __init__(self, identity_dict, global_prefix=None):
        super(AlternateIdentity, self).__init__()
        self.global_prefix = global_prefix

        # Save the identity dict because it'll be useful when we merge.
        self.identity_dict = identity_dict

        # All attributes should be from the same components, so just grab the
        # component name from the first attribute. It'll be validated below.
        self.component_prefix = identity_dict.keys()[0].split("/")[0]

        self.attributes = []
        self.values = []
        self._indices = []

        for attribute, value in sorted(identity_dict.iteritems()):
            component, key = attribute.split("/")
            if self.component_prefix != component:
                raise ValueError((
                    "identity_dict can only contain attributes from one "
                    "component, but %s was given.") % identity_dict)

            self.attributes.append(key)
            self.values.append(value)

            # Build up indices now, so we don't have to do it every time.
            if value is not None:
                self._indices.append((global_prefix, attribute, value))

    def __eq__(self, other):
        if not isinstance(other, AlternateIdentity):
            return False

        # Make sure we're comparing the comparable.
        if ((self.component_prefix != other.component_prefix) or
            (self.global_prefix != other.component_prefix) or
            (self.attributes != other.attributes)):
            return False

        for idx, value in enumerate(self.values):
            # If either side is None then we can't compare them.
            if value is None or other.attributes[idx] is None:
                continue

            # We got here, so we have two values we can actually compare.
            # Note that we don't need to compare every value - it would be
            # a violation of the entity system's integrity if one value matched
            # and another one didn't in an alternate identity.
            return value == other.attributes[idx]

        # At this point we know that we're comparing two identities of the same
        # kind, but none of the values match or mismatch, so the result is
        # undecidable.
        return None

    def union(self, other):
        return AlternateIdentity(
            identity_dict=self.identity_dict,
            global_prefix=self.global_prefix)

    @property
    def indices(self):
        return self._indices

    def __unicode__(self):
        keyvals = []
        for idx, value in enumerate(self.values):
            if value is None:
                continue
            keyvals.append("%s=%s" % (self.attributes[idx], value))

        return "%s/%s/(%s)" % (
            self.global_prefix,
            self.component_prefix,
            ",".join(keyvals))


class BaseObjectIdentity(Identity):
    """Implements Identity using BaseObject memory locations.

    This container will store:
      obj_offset
      obj_type
      obj_vm, actually an AttributeDict with:
        dtb (or 0 for physical address space)

    The interface above is the same as what BaseObject would provide which
    is useful when using the two interchangeably.

    This class also supports pickling and, once unpickled, can rebuild the
    original BaseObject instance using an active session.

    TODO: This class is going to be drastically simplified.
    """
    def __init__(self, base_obj, follow_pointers=True):
        super(BaseObjectIdentity, self).__init__()

        # Dereference pointers by default so we don't have the same thing
        # appear more than one time. One exception is void pointers.
        if (follow_pointers and
            isinstance(base_obj, obj.Pointer) and
            base_obj.target != "void"):
            base_obj = base_obj.dereference()

        self.obj_offset = base_obj.obj_offset
        self.obj_type = base_obj.obj_type
        self.dtb = getattr(base_obj.obj_vm, "dtb", 0)

        if isinstance(base_obj, obj.Pointer) and follow_pointers:
            _base_obj = base_obj.dereference()
            if _base_obj:
                base_obj = base_obj

    def restore_base_obj(self, session):
        """Rebuild the original BaseObject instance."""
        if self.dtb == 0:
            vm = session.physical_address_space
        elif self.dtb == session.kernel_address_space.dtb:
            vm = session.kernel_address_space
        else:
            raise AttributeError(
                "DTB does't match the kernel virtual address space.")

        if session == None:
            raise AttributeError(
                "Cannot restore a base object without a valid session.")

        return session.profile.Object(
            type_name=self.obj_type,
            offset=self.obj_offset,
            vm=vm)

    def __eq__(self, other):
        if not isinstance(other, BaseObjectIdentity):
            return False

        return ((self.obj_type, self.obj_offset, self.dtb)
                == (other.obj_type, other.obj_offset, other.dtb))

    def __unicode__(self):
        return "<%s 0x%x; dtb:0x%x>" % (
            self.obj_type,
            self.obj_offset,
            self.dtb)

    @property
    def indices(self):
        return set([(self.obj_type, self.obj_offset, self.dtb)])
