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

import logging

from rekall import obj

from rekall.entities import component as entity_component
from rekall.entities import identity
from rekall.entities import superposition
from rekall.entities import types

from rekall.entities.query import query


class Entity(object):
    """Entity is an abstraction of things like Process, User or Connection.

    Each entity consists of a an identity object, like PID, username or a memory
    address, and a list of components, which are data about the entity.

    Immutability:
    =============

    Entities and components are copy-on-write. Components enforce immutability
    while Entity and Identity are less strict for practical reasons.
    Nevertheless, changing an instance of entity or identity after they've been
    added to an entity manager will result in undefined behavior.

    Relational Model:
    =================

    Entites support associations with other entities. For example, a resource
    has a handle, a handle is owned by a process, and so on. These associations
    are implemented using Identity and lookups through an entity manager. See
    documentation of 'find_referenced_entities' and 'find_referencing_entities'
    for a discussion of associations.

    Merging:
    ========

    If more than one entity is added to an entity manager for the same thing,
    they will be merged into a single entity with all the properties, as long as
    the identity is decidable. For example, if we have a user with UID 15 and
    another user with username "Alice" they will remain separate entities until
    an entity is added with an identity that has the UID 15 and username
    "Alice", at which point the identity becomes decidable and all three
    entities will be merged into one.

    If, during merging, a conflict arises then both versions are kept
    encapsulated in an instance of superposition.Superposition. As long as you
    use 'get_' family of accessors on Entity this will be handled for you (as
    those functions always return generators).

    Superpositions:
    ===============

    Superpositions are technically merge conflicts, but they are not errors.
    They occur in cases where there are legitimately multiple valid values of a
    single attribute. Some examples:

    Resource/handle can have multiple values, because a single file/socket can
    be opened by multiple handles owned by multiple processes.

    Struct/type can be a superposition in case of unions, or things that
    are stored as a void pointer and cast depending on contextual state.

    User/real_name can often be a superposition because of variable formatting
    rules applied by the OS.

    Public state members:
    =====================

    components: An instance of ComponentContainer, which is a fast container
        object that actually stores the components of the entity.

    manager: The manager this entity belongs to.

    Special Attributes:
    ===================

    entity["Entity/identity"] (shorthand entity.identity, entity.indices)
    entity["Entity/collectors"] (shorthand entity.collectors)

    ### References:

    http://en.wikipedia.org/wiki/Composition_over_inheritance
    http://en.wikipedia.org/wiki/Entity_component_system
    """

    typedesc = None

    def __init__(self, components, entity_manager=None):
        self.components = components
        self.manager = entity_manager
        self.typedesc = EntityDescriptor()

    @property
    def identity(self):
        return self.components.Entity.identity

    @property
    def collectors(self):
        return self.components.Entity.collectors

    @property
    def indices(self):
        """Returns all the keys that the entity will be accessible at."""
        return self.identity.indices

    def __hash__(self):
        return hash(self.identity)

    def __eq__(self, other):
        if not isinstance(other, Entity):
            return False

        return self.identity == other.identity

    def __ne__(self, other):
        return not self.__eq__(other)

    def issuperset(self, other):
        """Is this entity a strict superset of other?"""
        # Compare both component containers, but skip the Entity component.
        other_components = other.components[1:]
        for cidx, component in enumerate(self.components[1:]):
            other_comp = other_components[cidx]
            if other_comp is None:
                continue

            if component is None or not component.issuperset(other_comp):
                return False

        return True

    @property
    def name(self):
        """Name of the entity, if set (Named/name). If not, takes a guess."""
        name = self.get_raw("Named/name")

        if name:
            try:
                return unicode(name)
            except UnicodeDecodeError:
                logging.warning(
                    "Could not decode Named/name '%s' as unicode.",
                    name.encode("string-escape"))
                name = None

        if not name:
            key = unicode(self.identity.first_index[1])
            val = self.identity.first_index[2]

            if isinstance(val, obj.Struct):
                # Rekall uses the opposite meaning of repr and str from
                # the entity layer. This is a temporary workaround until
                # everything just uses renderers all the time.
                val = repr(val)
            else:
                val = unicode(val)

            return "%s: %s" % (key, val)

        return unicode(name)

    @property
    def kind(self):
        kind = self.get_raw("Named/kind")
        if kind == None:
            kind = "Entity"

        return unicode(kind)

    def __repr__(self):
        parts = []
        for component in self.components:
            if not component:
                continue

            parts.append(repr(component))

        return "Entity(\n%s)" % ",\n\n".join(parts)

    def __str__(self):
        return self.__unicode__()

    def __unicode__(self):
        return u"%s: %s" % (self.kind, self.name)

    # pylint: disable=protected-access
    def asdict(self):
        """Returns a dict of all attributes and their values."""
        result = {}
        for component_name in entity_component.Component.classes.keys():
            component = getattr(self.components, component_name)

            if component is None:
                continue

            for idx, field in enumerate(component.component_fields):
                val = component[idx]
                if val:
                    key = "%s/%s" % (component_name, field.name)
                    result[key] = val

        return result

    @classmethod
    def fromdict(cls, attributes, manager=None):
        """Rebuilds the entity from a dict of attributes.

        Values will be coerced into their proper types automatically.
        """
        component_dicts = {}

        for attribute, value in attributes.iteritems():
            component_name, field_name = attribute.split("/", 1)
            component_dicts.setdefault(component_name, {})
            component_dicts[component_name][field_name] = value

        components = {}
        for component_name, kwargs in component_dicts.iteritems():
            component_cls = cls.reflect_component(component_name)
            components[component_name] = component_cls(**kwargs)

        return cls(entity_component.CONTAINER_PROTOTYPE._replace(**components),
                   manager)

    def get_referencing_entities(self, key, complete=True):
        """Finds entities that reference this entity by its identity.

        If other entities have an attribute that stores the identity of this
        entity then this function will find those entities.

        For example, calling this on a process, one can find all the handles
        owned by the process by calling
        process.get_referencing_entities("Handle/process").

        Arguments:
            key: The property path to the attribute on the other entities.
                As usual, form is Component/attribute.
        """
        # Automatically ask the entity manager to add indexing for
        # identity-based attributes. This is a good heuristic for optimal
        # performance.
        self.manager.add_attribute_lookup(key)

        return self.manager.find(
            query.Query("%s is {}" % key, params=[self.identity]),
            complete=complete)

    def get_raw(self, key):
        """Get raw value of the key, no funny bussiness.

        Does not attempt to resolve superposition or identities, just returns
        the raw value of the key.

        Arguments:
            key: Property path in form of Component/attribute.
        """
        try:
            component_name, attribute = key.split("/", 1)
        except ValueError:
            # Maybe the key is just a component name?
            component = getattr(self.components, key, None)
            if component:
                return component

            raise ValueError("%s is not a valid key." % key)

        component = getattr(self.components, component_name, None)
        if component is None:
            return None

        try:
            return getattr(component, attribute)
        except AttributeError:
            return component.reflect_attribute(attribute)

    def get(self, key, complete=False):
        """Returns value of the key, or a superposition thereof.

        Out of the get_ functions, this is almost always the one you want.

        Getting a basic value:
        ======================

        Use key in form of Component.attribute. For example, "Process/pid" or
        "User/username". Same as calling entity[key]:

        entity["Process/pid"]  # PID of the process.

        What if the value is an entity:
        ===============================

        This method automatically recognizes attributes that reference other
        entities, looks them up and returns them. For example:

        entity["Process/parent"]  # Returns the parent process entity.
        entity["Process/parent"]["Process/pid"]  # PID of the parent.

        What if I want all the child processes (Inverse Lookup):
        ========================================================

        You can call entity.get_referencing_entities if you want to be explicit.

        Alternatively, prepend the key with a '&' for inverse lookup of a N:1
        assocation.

        For example:

        entity["&Process/parent"]  # Returns processes of which this process is
                                   # (Child processes).

        entity["&Handle/process"]  # Returns all handles this process has open.

        In most cases, this is unnecessary and aliases can be used instead.

        For example:

        entity["&Handle/process"]  # Is already aliased in definitions as:
        entity["Process/handles"]

        entity["&Process/parent"]  # Is already aliased in definitions as:
        entity["Process/children"]

        When does this return more than one value:
        ==========================================

        1) When doing an inverse lookup.
        2) When the value we find is a superposition.

        In both cases, a superposition is returned. Remember that superpositions
        proxy the [] operator, returning more superpositions. For example:

        # To return the pids of all child processes:
        entity["&Process/parent"]["Process/pid"]

        You can request more than one key in a single call:
        ===================================================

        This is identical to the behavior of [] on python dictionaries:

        entity["Process/pid", "Process/command"]  # is the same as calling:
        (entity["Process/pid"], entity["Process/command"])

        You can also request a multi-level path into the object:
        ========================================================

        The path separator is '->' and is used as follows:

        entity["Process/handles"]["Handle/resource"]  # Is the same as:
        entity["Process/handles->Handle/resource]

        This is merely syntax sugar to make specifying rendering output easier.
        """
        # If we get called with [x, y] python will pass us the keys as a tuple
        # of (x, y). The following behaves identically to dict.
        if isinstance(key, tuple):
            return [self.get(_key, complete) for _key in key]

        # If we get called with a Component/attribute->Component/attribute
        # we treat -> as path separator and the whole key as path into the
        # object.
        if "->" in key:
            # This works recursively.
            key, rest = key.split("->", 1)
            subresult = self.get(key=key, complete=complete)
            if not subresult:
                return None

            return subresult.get(key=rest, complete=complete)

        # The & sigil denotes reverse lookup.
        if key.startswith("&"):
            return superposition.EntitySuperposition.merge_values(
                variants=self.get_referencing_entities(key[1:],
                                                       complete=complete),
                typedesc=self.typedesc)

        # The raw result could be None, a superposition or just a scalar.
        value = self.get_raw(key)
        if value is None:
            return obj.NoneObject(
                "Entity '%s' has no results for key '%s'." % (self, key))

        # Redirection.
        if isinstance(value, entity_component.Alias):
            return self.get(value.alias, complete=complete)

        typedesc = self.reflect_type(key)
        if typedesc.type_name == "Entity":
            return superposition.EntitySuperposition.merge_values(
                variants=self.manager.find_by_identity(value,
                                                       complete=complete),
                typedesc=self.typedesc)

        return value

    def get_variants(self, key, complete=False):
        value = self.get(key, complete=complete)
        if isinstance(value, superposition.BaseSuperposition):
            return iter(value)

        return (value,)

    def __getitem__(self, key):
        return self.get(key)

    @classmethod
    def reflect_attribute(cls, path):
        """Return an instance of Attribute describing the attribute."""
        # For longer keypaths, the relevant attribute (for types, etc) is
        # the last one.
        attribute_name = path.split("->")[-1]

        try:
            component, key = attribute_name.split("/", 1)
        except ValueError:
            # Doesn't include a slash - it's a component maybe?
            return cls.reflect_component(path)

        component_cls = cls.reflect_component(component)
        if not component_cls:
            return

        attribute = component_cls.reflect_attribute(key)

        if "->" in path:
            # Need to modify the attribute so that attribute.path matches the
            # one the callers was looking for.
            return entity_component.AttributePath(attribute, path)

        return attribute

    @classmethod
    def reflect_type(cls, path):
        typedesc = cls.reflect_attribute(path).typedesc
        if typedesc.type_name == "Identity":
            # Return a typedesc that says "Entity" on it when asked. Even
            # though the attribute contains an Identity, and that's what will
            # be set by any writers, Entity is what we actually return from
            # self.get.
            return EntityDescriptor()

        return typedesc

    @classmethod
    def reflect_component(cls, component):
        return entity_component.Component.classes.get(component, None)

    def _merge_containers(self, other):
        """Merge component containers from self and other into new container."""
        new_components = []
        x = self.components
        y = other.components

        # Skipping component idx 0 (Entity)
        try:
            for idx in xrange(1, len(x)):
                cx = x[idx]
                cy = y[idx]
                if not cx:
                    if cy:
                        new_components.append(cy)
                    else:
                        new_components.append(None)
                else:
                    if cy:
                        new_components.append(cx.union(cy))
                    else:
                        new_components.append(cx)
        except TypeError as e:
            # Merging may encounter type enforcement errors. Such errors mean
            # either that a collector is using faulty assumptions (canonical
            # example is assuming handles on Windows are unique to a process,
            # and using the process identity in the Handle component) or that
            # the image is inconsistent.
            # The best we can do is reject the faulty data and hope for the
            # best.
            logging.error("Entity rejected because of a type error %s", e)
            return self.components

        # Entity component is merged using slightly simpler rules.
        component_cls = entity_component.Component.classes["Entity"]
        try:
            new_entity_component = component_cls(
                identity=x.Entity.identity | y.Entity.identity,
                collectors=x.Entity.collectors | y.Entity.collectors)
        except identity.IdentityError as e:
            # Consistency errors can mean the data is corrupt. There are no
            # good solutions. Lets log the reject and get on with our lives.
            logging.error("Entity rejected because of consistency error %s", e)
            return self.components

        return type(x)(new_entity_component, *new_components)

    def update(self, other):
        """Changes this entity to include information from other.

        This is not a part of the API - only EntityManager should use this.
        """
        self.components = self._merge_containers(other)

    def union(self, other):
        """Returns a new entity that is a union of x and y.

        Original entities remain immutable. If x and y have some of the same
        components and those components report conflicting values in some fields
        then those fields will be replaced with a superposition (see
        superposition.Superposition) of all reported values.
        """
        if not self == other:  # self != other can return None.
            raise AttributeError("Can't do union unless both are equal.")

        return Entity(
            components=self._merge_containers(other),
            entity_manager=self.manager)

    def __ior__(self, other):
        return self.update(other)

    def __or__(self, other):
        return self.union(other)


class IdentityDescriptor(types.TypeDescriptor):
    """Entity type, actually contains the Identity key."""

    # Actually, it's Identity, but the user doesn't care about the difference.
    type_name = "Identity"

    def coerce(self, value):
        if value is None:
            return None

        if isinstance(value, Entity):
            return value.identity

        if isinstance(value, identity.Identity):
            return value

        value_repr = None
        try:
            value_repr = repr(value)
        except Exception as e:
            raise TypeError(
                ("Object passed to coerce is not an identity. Additionally, "
                 "calling repr(object) raised %s.") % e)

        if isinstance(value, superposition.BaseSuperposition):
            raise TypeError(
                ("Object being coerced as identity is a superposition: %s. "
                 "Identity superpositions in attributes are not allowed.") %
                value_repr)

        raise TypeError("%s is not an identity." % value_repr)

    def __repr__(self):
        return "Entity (Identity) type"


class EntityDescriptor(types.TypeDescriptor):
    """Actually contains an Entity. Used by superpositions."""

    type_name = "Entity"
    type_cls = Entity

    def coerce(self, value):
        if value is None:
            return None

        if isinstance(value, Entity):
            return value

        value_repr = None
        try:
            value_repr = repr(value)
        except Exception as e:
            raise TypeError(
                ("Object passed to coerce is not an entity. Additionally, "
                 "calling repr(object) raised %s.") % e)

        raise TypeError("%s is not an entity." % value_repr)

    def __repr__(self):
        return "Entity type"
