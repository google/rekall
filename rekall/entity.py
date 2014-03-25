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
        # Always deref because we need to be able to test for equivalency.
        if isinstance(key_obj, obj.Pointer):
            key_obj = key_obj.dereference()

        if meta is None:
            meta = dict()

        self.key_obj = key_obj
        self.meta = meta
        self.generators = generators
        self.session = session
        self.copies_count = copies_count

    def __hash__(self):
        return self.key_obj.__hash__()

    def __eq__(self, other):
        return self.key_obj == other.key_obj

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
            meta=dict(e2.meta.items() + e1.meta.items()),
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


class OpenResource(Entity):
    @property
    def handle(self):
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


