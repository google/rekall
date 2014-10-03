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

from rekall.entities import collector as entity_collector
from rekall.entities import component as entity_component
from rekall.entities import entity as entity_module
from rekall.entities import definitions
from rekall.entities import identity as entity_id
from rekall.entities import lookup_table as entity_lookup


class EntityManager(object):
    """Database of entities."""

    collectors = []
    collector_stack = []

    def __init__(self, session):
        self.entities = {}
        self.finished_collectors = set()
        self.session = session

        # Lookup table on component name is such a common use case that we
        # always have it on. This actually speeds up searches by attribute that
        # don't have a specific lookup table too.
        def _component_indexer(entity):
            for component in entity_component.Component.classes.keys():
                if getattr(entity.components, component):
                    yield component

        def _collector_indexer(entity):
            for collector_name in entity.components.Entity.collectors:
                yield collector_name

        self.lookup_tables = {
            "components": entity_lookup.EntityLookupTable(
                key_name="components",
                key_func=_component_indexer,
                entity_manager=self),
            "collectors": entity_lookup.EntityLookupTable(
                key_name="collectors",
                key_func=_collector_indexer,
                entity_manager=self)}

    def update_collectors(self):
        """Generate a list of available collectors."""
        self.collectors = []
        for cls in entity_collector.EntityCollector.classes.values():
            if cls.is_active(self.session):
                collector = cls(entity_manager=self)
                self.collectors.append(collector)

    @property
    def identity_prefix(self):
        """Returns the prefix for all identities on this machine.

        Currently this just returns "LOCALHOST", but in the future this will
        be a way of semi-uniquelly identifying the image/machine of origin.
        """
        # TODO: implement proper machine identification.
        return "LOCALHOST"

    def identify(self, identity_dict):
        """Generate the appropriate type of identity based on identity dict.

        Arguments:
        identity_dict: a dictionary of attribute names (format being the
        usual "Component/member") and expected values.

        Returns:
        AlternateIdenity initialized with the identity dict and this manager's
        global prefix.
        """
        return entity_id.AlternateIdentity(global_prefix=self.identity_prefix,
                                           identity_dict=identity_dict)

    # pylint: disable=protected-access
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
        kwargs = {}
        for component in components:
            kwargs[component.component_name] = component

        kwargs["Entity"] = definitions.Entity(
            identity=identity,
            collectors=frozenset((source_collector,)))

        entity = entity_module.Entity(
            entity_manager=self,
            components=entity_component.CONTAINER_PROTOTYPE._replace(**kwargs))

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

        logging.debug("Creating a lookup table for %s", key)
        component, _ = key.split("/")

        lookup_table = entity_lookup.EntityLookupTable(
            key_name=key,
            key_func=lambda e: (e.get_raw(key),),
            entity_manager=self)

        # Only use the entities that actually have the component to build the
        # index.
        lookup_table.update_index(
            self.find_by_component(component, complete_results=False))

        self.lookup_tables[key] = lookup_table

    def find_by_identity(self, identity):
        """Yield the entities that matches the identity.

        The number of entities yielded is almost always one or zero. The single
        exception to that rule is when the identity parameter is both: (a) a
        alternate identity and (b) not yet present in this entity manager. In
        that case, multiple entities may match.
        """
        for index in identity.indices:
            entity = self.entities.get(index, None)
            if entity:
                yield entity

    def find_by_component(self, component, complete_results=True):
        """Yields all entities that have the component.

        Arguments:
            complete_results: If True, will attempt to collect the component.
        """
        if complete_results:
            self.collect_for(component)

        return self.lookup_tables["components"].lookup(component)

    def find_by_collector(self, collector):
        return self.lookup_tables["collectors"].lookup(str(collector))

    def find_by_attribute(self, key, value, complete_results=True):
        """Yields all entities where component.attribute == value.

        Arguments:
            key: Path to the value formed of <component>.<attribute>. E.g:
                Process.pid, or User.username.
            value: Value, compared against using the == operator
            complete_results: If False, will only hit cache. If True, will also
                collect the component.

        Yields:
            Instances of entity that match the search criteria.
        """
        component, _ = key.split("/")
        lookup_table = self.lookup_tables.get(key, None)

        if lookup_table:
            # Sweet, we have an index for this.
            if complete_results:
                self.collect_for((key, value))

            for entity in lookup_table.lookup(value):
                yield entity
        else:
            # No index to support the query. We can use the component index
            # to only search entities for which this makes sense. However,
            # we must take care to only trigger the collectors we need, as
            # opposed to all collectors that touch the component.
            if complete_results:
                self.collect_for((key, value))
            for entity in self.find_by_component(component=component,
                                                 complete_results=False):
                if entity.get_raw(key) == value:
                    yield entity

    def find_first_by_attribute(self, *args, **kwargs):
        """Convenience method - returns first result of find_by_attribute."""
        for entity in self.find_by_attribute(*args, **kwargs):
            return entity

    def collectors_for(self, wanted):
        """Finds the active collectors that can satisfy the query.

        For format of the wanted query, see EntityCollector.can_collect.
        """
        self.update_collectors()
        for collector in self.collectors:
            if collector.can_collect(wanted):
                yield collector

    # pylint: disable=protected-access
    def collect_for(self, wanted, use_hint=False):
        """Will find the appropriate collectors to satisfy the query.

        For format of the wanted query, see EntityCollector.can_collect.

        If use_hint is set to True, 'wanted' will be passed on as hint to
        the collectors. This may result in faster collection, but may result
        in collectors having to run repeatedly.
        """
        if use_hint:
            hint = wanted
        else:
            hint = None

        for collector in self.collectors_for(wanted):
            # Dependency loops are disallowed. Some special cases could be made
            # to work, but the complexity tradeoff is not worth it.
            if collector in self.collector_stack:
                previous = self.collector_stack[-1]
                raise RuntimeError(
                    ("Collector dependency loop: %s is being called to "
                     "collect %s for %s. However, %s is already on the stack:"
                     "\n %s") % (collector.name, wanted, previous.name,
                                 collector.name, self.collector_stack))

            if collector.name in self.finished_collectors:
                continue

            self.collector_stack.append(collector)
            logging.debug("%sCollector %s will now run (hint=%s)",
                          "." * (len(self.collector_stack) - 1),
                          collector.name,
                          hint)

            for results in collector.collect(hint=hint):
                if not isinstance(results, list):
                    # Just one component yielded.
                    results = [results]

                # First result is either the first component or an identity.
                first_result = results[0]
                if isinstance(first_result, entity_id.Identity):
                    # If the collector gave as an identity then use that.
                    identity = first_result
                    results.pop(0)
                else:
                    # If collector didn't give us an identity then we build
                    # one from the first component's first field. This is
                    # a good heuristic for about 90% of the time.
                    first_field = first_result.component_fields[0].name
                    attribute = "%s/%s" % (type(first_result).__name__,
                                           first_field)
                    identity = self.identify({attribute: first_result[0]})

                self.register_components(identity=identity,
                                         components=results,
                                         source_collector=collector.name)

            if hint is None:
                self.finished_collectors.add(collector.name)
            self.collector_stack.pop()
