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
from rekall import utils


class EntityCache(object):
    """Per-session register of entities."""

    def __init__(self, session):
        # Entity instances indexed by BaseObjIdentity.
        self.entities_by_identity = {}

        # BaseObjIdentity instances indexed by generator name, so we know which
        # generators have run and what they returned.
        self.identities_by_generator = {}
        self.session = session

    def register_entity(self, entity, generator):
        """Associate entity with this register."""
        entity.session = self.session
        entity.generators = set([generator])

        identity = entity.identity
        if identity in self.entities_by_identity:
            entity = Entity.merge(
                entity,
                self.entities_by_identity[identity]
            )

        self.entities_by_identity[identity] = entity
        self.identities_by_generator.setdefault(
            generator,
            set()).add(identity)

    def _generate_entities(self, entity_cls, include_subclasses=True,
                           cache_only=False):
        """Find distinct entities of a particular type.

        Arguments:
          include_subclasses (default: True): Also look for subclasses.

          entity_cls: The desired class of entities.

          cache_only: Only search the cache, don't run generators.

        Yields:
          Entities of class entity_cls (or subclass. Entities are merged
          using Entity.merge if two or more are found to represent the
          same key object.
        """
        generators = self.session.profile.entity_generators(
            entity_cls=entity_cls,
            subclasses=include_subclasses,
        )

        results = set()

        for generator in generators:
            # If we've already run this generator just get the cached output.
            if generator.__name__ in self.identities_by_generator:
                results.update(
                    self.identities_by_generator[generator.__name__]
                )
                continue

            # Skip ahead if we're only hitting cache.
            if cache_only:
                continue

            # Otherwise register the entities from the generator.
            for entity in generator(self.session.profile):
                self.register_entity(entity, generator.__name__)
                results.add(entity.identity)

        # Generators can return more than one type of entity, which is why the
        # filtering by isinstance is necessary to ensure we return correct
        # results.
        for identity in results:
            entity = self.entities_by_identity[identity]
            if isinstance(entity, entity_cls):
                yield entity

    def _retrieve_entities(self, entity_cls, key_obj, cache_only=False):
        """Given a key object, find entities that represent it.

        If the entity already exists in cache it will be retrieved. Otherwise,
        it'll be creared using entity_cls as class and "Session" as generator
        name.

        If key_obj is a superposition (from merge) then more than one entity
        will be yielded.

        Yields:
          An instance of Entity, most likely entity_cls. If the key object
          is a superposition, more than one result will be yielded.

        Arguments:
          entity_cls: The expected class of the entity. Not guaranteed.

          key_obj: The key object to look up. Can be any object that implements
            obj_offset, obj_vm and obj_type, such as BaseObjectIdentity. Can
            also be a superposition of more values.
        """
        if isinstance(key_obj, utils.Superposition):
            key_objs = key_obj.variants
        elif key_obj == None:
            key_objs = []  # Handle None gracefully.
        else:
            key_objs = [key_obj]

        for key_obj in key_objs:
            # We coerce the key object into a type suitable for use as a
            # dict key.
            idx = obj.BaseObjectIdentity(base_obj=key_obj)

            if idx in self.entities_by_identity:
                yield self.entities_by_identity[idx]
            elif not cache_only:
                entity = entity_cls(key_obj=key_obj, session=self)
                self.register_entity(entity, generator="Session")
                yield entity

    def find(self, entity_cls=None, key_obj=None,
             include_subclasses=True, cache_only=False):
        """Find and yield entities based on class or key object.

        If key_obj is given, will yield entity to represent that object. If
        one doesn't exist it will be created with "Session" as generator and
        entity_cls as class.

        If key_obj is a superposition all matches will be yielded as outlined
        above.

        If only entity_cls is given will yield all objects of that class,
        running generators as appropriate.

        Arguments:
          key_obj: Key object to search for. Can also be any object that
            implements obj_vm, obj_offset and obj_type, such as
            BaseObjectIdentity. Superposition is supported (see
            utils.Superposition).

          entity_cls: Entity class to search for.

          include_subclasses (default: True): If searching for all entities
            of class, also include subclasses.

          cache_only (default: False): Only search the cache, do not create
            new entities or run generators.

        Returns:
          Iterable of instances of Entity, possibly of entity_cls.
        """
        if key_obj:
            return self._retrieve_entities(
                key_obj=key_obj,
                entity_cls=entity_cls,
                cache_only=cache_only,
            )

        if entity_cls:
            return self._generate_entities(
                entity_cls=entity_cls,
                cache_only=cache_only,
                include_subclasses=include_subclasses,
            )

        return []


class Entity(object):
    """Abstraction over high-level concepts like processes and connections.

    An entity is a wrapper around two pieces of information:
        Key Object (key_obj) - a subclass of BaseObject (usually a Struct)
        that provides the entity with its notion of identity (i.e. /what/ the
        entity is about) and some basic data. Key objects are so named because
        they serve as the primary key by which entities are indexed and looked
        up.

        Metadata (meta) - a dictionary of arbitrary data that provides
        contextual information about the key object, such as other objects
        it's related to (remember, we can look up other entities using those
        objects as keys) and any other data that was deemed important at
        time of discovery.

    Subclasses combine information from both sources of information and present
    a clean interface, but they should not attach more state information.

    ### Behavior - Merging

    Entities that are equal (their key objects are equal) can me merged into
    a single entity that has both their data. See merge bellow.

    ### IMPORTANT note on relationships between entities and storing entities:

    Some entities have logical relationships of either the 1:1 (e.g. socket
    and open file) or N:1 sort (e.g. process and open files).

    These relationships should, without exception, be expressed through the key
    objects. For example, a Process entity should store (or lookup) a list
    of key objects used by OpenFile entity, instead of a list of OpenFile
    entities.

    The key object is so named because it serves as the indexing key by which
    entities are identified, hashed, compared and merged. The per-session
    profile object will provide an API to lookup/create entity objects from
    key objects, so there is no reason to ever store entity objects.
    """

    def __init__(self, key_obj, meta=None, generators=frozenset(),
                 session=None, copies_count=1):
        if isinstance(key_obj, obj.BaseObjectIdentity):
            key_obj = key_obj.restore(session=session)

        # Always deref pointers so we can test for equivalency.
        if isinstance(key_obj, obj.Pointer):
            key_obj = key_obj.dereference()

        # Store identity for comparisons and quick lookups.
        self.identity = obj.BaseObjectIdentity(base_obj=key_obj)

        if meta is None:
            meta = dict()

        self.key_obj = key_obj
        self.meta = meta
        self.generators = generators
        self.session = session
        self.copies_count = copies_count

    def __hash__(self):
        return hash(self.identity)

    def __eq__(self, other):
        return self.identity == other.identity

    def __ne__(self, other):
        return not self.__eq__(other)

    @classmethod
    def merge(cls, x, y):
        """Make a new entity with all the attributes of x and y.

        Arguments:
          x, y: Two entities with the same key object. x and y don't have
          to be the exact same class as long as one is a subclass of the other.

        Returns:
          A new entity of the same class as x and y, with all the attributes
          of both. If one entity is a subclass of the other then priority is
          given to the subclass in both the type and the attributes of the
          returned entity.
        """
        if x != y:
            raise AttributeError(
                "Cannot merge entities with different key objects.")

        if isinstance(x, type(y)):
            # Either x is more specific or they're the same.
            e1 = x
            e2 = y
        elif isinstance(y, type(x)):
            e1 = y
            e2 = x
        else:
            raise AttributeError(
                "Cannot merge entities of different types.")

        cls = type(e1)
        return cls(
            key_obj=e1.key_obj,
            generators=e1.generators | e2.generators,
            meta=utils.SuperpositionMerge(e2.meta, e1.meta),
            session=e1.session,
            copies_count=e1.copies_count + e2.copies_count,
        )

    @property
    def entity_name(self):
        pass

    @property
    def entity_type(self):
        pass


class Process(Entity):
    @property
    def pid(self):
        pass

    @property
    def ppid(self):
        pass

    @property
    def command(self):
        pass


class NetworkInterface(Entity):
    @property
    def addresses(self):
        """Tuples of (protocol, address)."""
        pass

    @property
    def interface_name(self):
        pass

    @property
    def entity_name(self):
        return self.interface_name


class OpenResource(Entity):
    @property
    def handles(self):
        pass


class OpenFile(OpenResource):
    @property
    def full_path(self):
        pass


class Connection(OpenResource):
    @property
    def addressing_family(self):
        pass

    @property
    def protocol(self):
        pass

    @property
    def source(self):
        pass

    @property
    def destination(self):
        pass

    @property
    def state(self):
        pass


class OpenHandle(Entity):
    @property
    def resource(self):
        pass

    @property
    def process(self):
        pass

    @property
    def descriptor(self):
        pass

    @property
    def flags(self):
        pass


