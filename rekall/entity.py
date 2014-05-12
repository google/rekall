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

from rekall import components as comp
from rekall import identity as id
from rekall import obj
from rekall import superposition


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

    Resource.handle can have multiple values, because a single file/socket can
    be opened by multiple handles owned by multiple processes.

    MemoryObject.type can be a superposition in case of unions, or things that
    are stored as a void pointer and cast depending on contextual state.

    User.real_name can often be a superposition because of variable formatting
    rules applied by the OS.

    Public state members:
    =====================

    identity: An instance of Identity, or subclass.

    components: An instance of components.ComponentTuple - see that class for
        details.

    copies_count: The number of times this entity was discovered by different
        collectors. Incremented with each merge.

    collectors: A set of collector names that discovered this entity.

    entity_manager: The manager this entity belongs to.

    ### References:

    http://en.wikipedia.org/wiki/Composition_over_inheritance
    http://en.wikipedia.org/wiki/Entity_component_system
    """

    def __init__(self, components, copies_count=1, entity_manager=None):
        self.components = components
        self.copies_count = copies_count
        self.entity_manager = entity_manager

    @property
    def identity(self):
        return self.components.Entity.identity

    @property
    def collectors(self):
        return self.components.Entity.collectors

    @property
    def indices(self):
        """Returns all the keys that the entity will be accessible at."""
        return set(self.identity.indices)

    def __hash__(self):
        return hash(self.identity)

    def __eq__(self, other):
        if not isinstance(other, Entity):
            return False

        return self.identity == other.identity

    def __ne__(self, other):
        return not self.__eq__(other)

    def __unicode__(self):
        return "Entity(ID: %s; components: %s)" % (
            str(self.identity),
            ", ".join([
                x
                for x in comp.COMPONENTS
                if getattr(self.components, x)
            ])
        )

    def __str__(self):
        return self.__unicode__()

    def __repr__(self):
        return self.__unicode__()

    def asdict(self):
        result = {}
        for component_name in comp.COMPONENTS:
            component = getattr(self.components, component_name)

            if component is None:
                continue

            for field in component._fields:
                val = getattr(component, field)
                if val:
                    key = "%s.%s" % (component_name, field)
                    result[key] = val

        return result

    def get_referencing_entities(self, key):
        """Finds entities that reference this entity by its identity.

        If other entities have an attribute that stores the identity of this
        entity then this function will find those entities.

        For example, calling this on a process, one can find all the handles
        owned by the process by calling
        process.get_referencing_entities("Handle.process").

        Arguments:
            key: The property path to the attribute on the other entities.
                As usual, form is Component.attribute.
        """
        # Automatically ask the entity manager to add indexing for
        # identity-based attributes. This is a good heuristic for optimal
        # performance.
        self.entity_manager.add_attribute_lookup(key)

        for entity in self.entity_manager.find_by_attribute(
            key, self.identity):
            yield entity

    def get_raw(self, key):
        """Get raw value of the key, no funny bussiness.

        Does not attempt to resolve superposition or identities, just returns
        the raw value of the key.

        Arguments:
            key: Property path in form of Component.attribute.
        """
        try:
            component_name, attribute = key.split(".")
        except ValueError:
            raise ValueError("%s is not a valid key." % key)

        component = getattr(self.components, component_name, None)
        return getattr(component, attribute, None)

    def get_variants(self, key):
        """Yields all known values of key.

        Arguments:
            key: The path to the attribute we want. For example: "Process.pid".

        Yields:
            All known values of the key. This is usually exactly one value, but
            can be more, if the key is a superposition.
        """
        # The & sigil denotes reverse lookup.
        if key.startswith("&"):
            for entity in self.get_referencing_entities(key[1:]):
                yield entity

            return

        # The raw result could be None, a superposition or just a scalar.
        values = self.get_raw(key)

        if values is None:
            return

        if isinstance(values, superposition.Superposition):
            values = values.variants
        else:
            values = (values,)

        for value in values:
            if isinstance(value, id.Identity):
                for entity in self.entity_manager.find_by_identity(value):
                    yield entity
            else:
                yield value

    def get(self, key):
        """Returns value of the key, or a superposition thereof.

        Out of the get_ functions, this is almost always the one you want.

        Getting a basic value:
        ======================

        Use key in form of Component.attribute. For example, "Process.pid" or
        "User.username". Same as calling entity[key]:

        entity["Process.pid"]  # PID of the process.

        What if the value is an entity:
        ===============================

        This method automatically recognizes attributes that reference other
        entities and automatically looks them up and returns them. For example:

        entity["Process.parent"]  # Returns the parent process entity.
        entity["Process.parent"]["Process.pid"]  # PID of the parent.

        What if I want all the child processes (Inverse Lookup):
        ========================================================

        You can call entity.get_referencing_entities if you want to be explicit.

        Alternatively, prepend the key with a '&' for inverse lookup of a N:1
        assocation.

        For example:

        entity["&Process.parent"]  # Returns processes of which this process is
                                   # (Child processes).

        entity["&Handle.process"]  # Returns all handles this process has open.

        When does this return more than one value:
        ==========================================

        1) When doing an inverse lookup.
        2) When the value we find is a superposition.

        In both cases, a superposition is returned. Remember that superpositions
        proxy the [] operator, returning more superpositions. For example:

        # To return the pids of all child processes:
        entity["&Process.parent"]["Process.pid"]

        You can request more than one key in a single call:
        ===================================================

        This is identical to the behavior of [] on python dictionaries:

        entity["Process.pid", "Process.command"]  # is the same as calling:
        (entity["Process.pid"], entity["Process.command"])
        """
        # If we get called with [x, y] python will pass us the keys as a tuple
        # of (x, y). The following behaves identically to dict.
        if isinstance(key, tuple):
            return [self.get(_key) for _key in key]

        results = list(self.get_variants(key))
        if not results:
            return obj.NoneObject(
                "Entity '%s' has no results for key '%s'" % (self, key))

        return superposition.Superposition.merge_scalars(*results)

    def __getitem__(self, key):
        return self.get(key)

    def update(self, other):
        """Changes this entity to include information from other.

        This is not a part of the API - only EntityManager should use this.
        """
        self.components = self.components | other.components
        self.copies_count = self.copies_count + other.copies_count

        return self

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
            components=self.components | other.components,
            copies_count=self.copies_count + other.copies_count,
            entity_manager=self.entity_manager,
        )

    def __ior__(self, other):
        return self.update(other)

    def __or__(self, other):
        return self.union(other)


class EntityLookupTable(object):
    """Lookup table for entities."""

    def __init__(self, key_name, key_func, entity_manager):
        self.key_name = key_name
        self.key_func = key_func
        self.entity_manager = entity_manager
        self.table = {}

    def update_index(self, entities):
        for entity in entities:
            for key in self.key_func(entity):
                if key:
                    self.table.setdefault(key, set()).add(entity.identity)

    def lookup(self, *keys):
        unique_results = set()

        for key in keys:
            for identity in self.table.get(key, []):
                for entity in self.entity_manager.find_by_identity(identity):
                    unique_results.add(entity)

        return unique_results


class EntityManager(object):
    """Database of entities."""

    def __init__(self, session):
        self.entities = {}
        self.finished_collectors = set()
        self.session = session

        # Lookup table on component name is such a common use case that we
        # always have it on. This actually speeds up searches by attribute that
        # don't have a specific lookup table too.
        def _component_indexer(entity):
            for component_name in comp.COMPONENTS:
                if getattr(entity.components, component_name):
                    yield component_name

        self.lookup_tables = {
            "components": EntityLookupTable(
                key_name="components",
                key_func=_component_indexer,
                entity_manager=self,
            )
        }

    def register_components(self, identity, components, source_collector):
        """Find or create an entity for identity and add components to it.

        Arguments:
            identity: What the components are about. Should be a subclass of
                Identity. As a special case, we also accept BaseObjects.

            components: An iterable of components about the identity.

            source_collector: Anything that responds to __unicode__ or __name__
                and describes the source of this information (usually the
                string name of the collector function).
        """
        if isinstance(identity, obj.BaseObject):
            # Be nice and accept base objects.
            identity = id.BaseObjectIdentity(identity)

        entity = Entity(
            entity_manager=self,
            components=comp.MakeComponentTuple(
                comp.Entity(
                    identity=identity,
                    collectors=frozenset((source_collector,)),
                ),
                *components
            ),
        )

        indices = entity.indices

        for existing_entity in self.find_by_identity(identity):
            # One or more entities represent the same thing. Lets merge all of
            # them into the new entity and then replace all the resulting
            # indices with a reference to the new entity.
            entity |= existing_entity
            indices |= existing_entity.indices

        for index in indices:
            self.entities[index] = entity

        for lookup_table in self.lookup_tables.itervalues():
            lookup_table.update_index((entity,))

    def add_attribute_lookup(self, key):
        """Adds a fast-lookup index for the component/attribute key path.

        This also causes the newly-created lookup table to rebuild its index.
        Depending on how many entities already exist, this could possibly even
        take a few hundred miliseconds.
        """
        # Don't add the same one twice.
        if self.lookup_tables.get(key, None):
            return

        component, _ = key.split(".")

        lookup_table = EntityLookupTable(
            key_name=key,
            key_func=lambda e: (e.get_raw(key),),
            entity_manager=self,
        )

        # Only use the entities that actually have the component to build the
        # index.
        lookup_table.update_index(
            self.find_by_component(component, complete_results=False)
        )

        self.lookup_tables[key] = lookup_table

    def find_by_identity(self, identity):
        """Yield the entities that matches the identity.

        The number of entities yielded is almost always one or zero. The single
        exception to that rule is when the identity parameter is both: (a) a
        composite identity and (b) not yet present in this entity manager. In
        that case, multiple entities may match.
        """
        for index in identity.indices:
            entity = self.entities.get(index, None)
            if entity:
                yield entity

    def find_by_component(self, component, complete_results=True):
        """Yields all entities that have the component.

        Arguments:
            complete_results: If True, will run collect_component(component).
        """
        if complete_results:
            self.collect_component(component)

        return self.lookup_tables["components"].lookup(component)

    def find_by_attribute(self, key, value, complete_results=True):
        """Yields all entities where component.attribute == value.

        Arguments:
            key: Path to the value formed of <component>.<attribute>. E.g:
                Process.pid, or User.username.
            value: Value, compared against using the == operator
            complete_results: If False, will only hit cache. If True, will also
                collect_component(component).

        Yields:
            Instances of entity that match the search criteria.
        """
        component, _ = key.split(".")
        lookup_table = self.lookup_tables.get(key, None)

        if lookup_table:
            # Sweet, we have an index for this.
            if complete_results:
                self.collect_component(component)

            for entity in lookup_table.lookup(value):
                yield entity
        else:
            # No specific index. Let's hit the components index and then
            # iterate.
            for entity in self.find_by_component(
                component=component, complete_results=complete_results):
                if entity.get_raw(key) == value:
                    yield entity

    def run_collector(self, collector):
        """Will run the collector, which must be callable.

        All entities yielded by the collector will be registered and collector
        will be added to the list of collectors that have been executed.
        """
        if collector.__name__ in self.finished_collectors:
            return

        for identity, components in collector(self.session.profile):
            self.register_components(
                identity=identity,
                components=components,
                source_collector=collector.__name__,
            )

        self.finished_collectors.add(collector.__name__)

    def collect_component(self, component_name):
        """Will run all collectors that yield entities with this component."""
        for collector in self.session.profile.get_collectors(component_name):
            self.run_collector(collector)

