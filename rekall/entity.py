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

    Entites support relationships with other entities. For example, a resource
    has a handle, a handle is owned by a process, and so on. These relationships
    are implemented using Identity and lookups through an entity manager. See
    documentation of 'get_related_entities' for details.

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
    encapsulated in an instance of superposition.Superposition. As long as you use
    'get_' family of accessors on Entity this will be handled for you (as those
    functions always return generators).

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

    def __init__(self, identity, components, collectors=frozenset(),
                 copies_count=1, entity_manager=None):
        self.identity = identity
        self.components = components
        self.collectors = frozenset(collectors)
        self.copies_count = copies_count
        self.entity_manager = entity_manager

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

    def get_related_entities(self, key):
        """Retrieve entities this entity is related to.

        If one of the components on this entity has an attribute that contains
        an identity (such as process_identity on a Handle) then this convenience
        function will find the entity(ies) represented by that identity.

        Arguments:
            key: The path to the attribute with identity, without the _identity
                part (inferred). For example: "Handle.process"

        Yields:
            Instances of Entity. Note that more than one can be found if the
                attribute is found to be a superposition (common with handles,
                for example, as they can be owned by more than one process.)
        """
        if not key.endswith("_identity"):
            key = "%s_identity" % key

        for entity in self.get_attribute_variants(
            key=key,
            follow_identities=True):
            yield entity

    def get_attribute_variants(self, key, follow_identities=True):
        """Yields all known values of key.

        Arguments:
            key: The path to the attribute we want. For example: "Process.pid".
            follow_identities: If True, instances of Identity will automatically
                be converted into the entities they represent.

        Yields:
            All known values of the key. This is usually exactly one value, but
            can be more, if the key is a superposition.
        """
        values = self[key]
        if not values:
            return  # We don't yield None, we just return an empty generator.

        if isinstance(values, superposition.Superposition):
            values = values.variants
        else:
            values = (values,)

        for value in values:
            if follow_identities and isinstance(value, id.Identity):
                for entity in self.entity_manager.find_by_identity(value):
                    yield entity
            else:
                yield value

    def __getitem__(self, key):
        component_name, attribute = key.split(".")
        component = getattr(self.components, component_name)
        if not component:
            return None

        return getattr(component, attribute, None)

    def update(self, other):
        """Changes this entity to include information from other.

        This is not a part of the API - only EntityManager should use this.
        """
        self.collectors = self.collectors | other.collectors
        self.components = self.components | other.components
        self.copies_count = self.copies_count + other.copies_count
        self.identity = self.identity | other.identity

        return self

    @property
    def indices(self):
        """Returns all the keys that the entity will be accessible at."""
        return set(self.identity.indices)

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
            identity=self.identity | other.identity,
            components=self.components | other.components,
            copies_count=self.copies_count + other.copies_count,
            collectors=self.collectors | other.collectors,
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
            identity=identity,
            components=comp.MakeComponentTuple(components),
            collectors=(source_collector,),
            entity_manager=self,
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

    def add_attribute_lookup(self, component, attribute):
        """Adds a fast-lookup index for the component/attribute key path.

        This also causes the newly-created lookup table to rebuild its index.
        Depending on how many entities already exist, this could possibly even
        take a few hundred miliseconds.
        """
        key_name = "%s.%s" % (component, attribute)

        lookup_table = EntityLookupTable(
            key_name=key_name,
            key_func=lambda e: (e[key_name],),
            entity_manager=self,
        )

        # Only use the entities that actually have the component to build the
        # index.
        lookup_table.update_index(
            self.find_by_component(component, complete_results=False)
        )

        self.lookup_tables[key_name] = lookup_table

    def find_by_identity(self, identity):
        """Yields all entities that match the identity."""
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

    def find_by_attribute(self, component, attribute, value,
                          complete_results=True):
        """Yields all entities where component.attribute == value.

        Arguments:
            component: Name of the component, such as "Process" or "User".
            attribute: Name of the attribute, such as "pid" or "username".
            value: Value, compared against using the == operator
            complete_results: If False, will only hit cache. If True, will also
                collect_component(component).

        Yields:
            Instances of entity that match the search criteria.
        """

        key_name = "%s.%s" % (component, attribute)
        lookup_table = self.lookup_tables.get(key_name, None)

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
                if entity[key_name] == value:
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

