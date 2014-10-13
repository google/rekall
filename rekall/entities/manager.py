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


class IngestionPipeline(object):
    """Keeps track of new and updated entities during collection."""

    empty = True

    def __init__(self, queries):
        self.queues = {}
        for query in queries:
            self.queues[query] = []

    def seed(self, query, entities):
        """Set up the queue for query with entities."""
        self.queues[query] = [(e, None) for e in entities]
        if self.queues[query]:
            self.empty = False

    def find(self, query, trigger):
        """Return entities available for the query and the trigger.

        Arguments:
            trigger: Can be either 'new' or 'change'. If 'change' entities
            marked as 'new' will be returned as well, but not vice-versa.
        """
        for entity, effect in self.queues[query]:
            if trigger == "new" and effect == "change":
                # Collector only wants new entities and this is a change.
                continue

            yield entity

    def fill(self, ingest, collector):
        """Fills appropriate queues with entities from ingest.

        Arguments:
            ingest: An iterable containing entities and effects of adding them.
                The effects are a dict of:
                    None: How many entities were duplicates, including contents.
                    "change": How many entities changed by merging.
                    "new": How many new entities created.
                    "fill": How many entities were enqueued for ingestion by
                        other collectors.
            collector: The collector object from which ingest was collected.
        """
        counts = {None: 0, "change": 0, "new": 0, "fill": 0}
        outputs = set(collector.outputs)
        for entity, effect in ingest:
            counts[effect] += 1

            if effect is None:
                continue

            for query in self.queries & outputs:
                if entity.matches_query(query):
                    self.queues[query].append((entity, effect))
                    counts["fill"] += 1
                    self.empty = False

        logging.debug(
            "%s results: %d new, %d updated, %d sent to ingest. "
            "pipeline, %d duplicates.",
            collector.name, counts["new"], counts["change"],
            counts["fill"], counts[None])

        return counts

    def flush(self):
        queries = self.queues.keys()
        for query in queries:
            self.queues[query] = []
        self.empty = True

    def __getitem__(self, key):
        return self.queues[key]

    @property
    def queries(self):
        return set(self.queues.keys())


class EntityManager(object):
    """Database of entities."""

    __is_initialized = False

    __active_collector_names = None
    finished_collectors = None

    # Dict of entities keyed by their identity.
    entities = None

    def __init__(self, session):
        self.entities = {}
        self.session = session
        self.finished_collectors = set()
        self._collectors = {}

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

    @property
    def collectors(self):
        self.update_collectors()
        return self._collectors.values()

    def update_collectors(self):
        """Get all active collectors and index them by what they ingest."""
        for key, cls in entity_collector.EntityCollector.classes.iteritems():
            if key in self._collectors:
                if cls.is_active(self.session):
                    continue
                else:
                    del self._collectors[key]
            else:
                if cls.is_active(self.session):
                    self._collectors[key] = cls(entity_manager=self)

    @property
    def identity_prefix(self):
        """Returns the prefix for all identities on this machine.

        Currently this just returns "LOCALHOST", but in the future this will
        be a way of semi-uniquelly identifying the image/machine of origin.
        """
        # TODO: Implement proper machine identification.
        return "LOCALHOST"

    def identify(self, identity_dict):
        """Generate the appropriate type of identity based on identity dict.

        Arguments:
            identity_dict: a dictionary of attribute names (format being the
            usual "Component/member") and expected values.

        Returns:
            AlternateIdenity initialized with the identity dict and this
            manager's global prefix.
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

        Returns:
            Tuple of entity and the effect of the new information.

            The effect can be one of:
            None: No new information learned.
            "change": As result of this call, data in one or more entities was
                updated and entities may have merged.
            "new": A new entity was added.
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

        existing_entities = list(self.find_by_identity(identity))
        effect = "new"
        if existing_entities:
            if (len(existing_entities) == 1 and
                    existing_entities[0].strict_superset(entity)):
                # There is no new data to be gained by merging.
                return existing_entities[0], None

            for existing_entity in existing_entities:
                # Entities exist for this already, but are not equivalent to
                # the entity we found. Merge everything.
                effect = "change"
                entity.update(existing_entity)
                indices.update(existing_entity.indices)

        # Overwrite all old indices with reference to the new entity.
        for index in indices:
            self.entities[index] = entity

        for lookup_table in self.lookup_tables.itervalues():
            lookup_table.update_index((entity,))

        return entity, effect

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
        for collector in self.collectors:
            if collector.can_collect(wanted):
                yield collector

    def find(self, query, complete=True):
        """Runs the query and yields entities that match.

        This is a temporary implementation and currently only intended
        for use with simple 'Component/attribute=value' queries.

        Arguments:
            complete: If True, will trigger collectors as necessary, to ensure
            completness of results.
        """
        # TODO: Implement a query language.
        attribute, value = query.split("=", 1)
        return self.find_by_attribute(attribute, value,
                                      complete_results=complete)

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

        # Firstly, we find all the collectors that satisfy wanted, plus their
        # dependencies, minus the collectors we have already run. During this
        # step we also make a list of all the ingestion queries we'll have
        # to satisfy later.
        self.update_collectors()
        to_process = list(self.collectors_for(wanted))
        collectors = set()
        ingestion_queries = set()

        while to_process:
            collector = to_process.pop()

            if collector.name in self.finished_collectors:
                continue

            collectors.add(collector)

            if collector.ingests:
                ingestion_queries.add(collector.ingests)
                # Also add any collectors that satisfy the ingestion query.
                for dependency in self.collectors_for(collector.ingests):
                    if dependency not in collectors:
                        logging.debug(
                            "Ingestion query '%s' of collector %s depends on "
                            "collector %s.", collector.ingests, collector.name,
                            dependency.name)
                        to_process.append(dependency)

        if not collectors:
            # Don't need to run anything - we're already populated.
            return

        ingestion_pipeline = IngestionPipeline(queries=ingestion_queries)

        logging.debug("%d collectors scheduled for query %s",
                      len(collectors), wanted)

        # Seed the pipeline by running ingestion queries on our current state.
        for query in ingestion_queries:
            logging.debug("Seeding the ingestion pipeline for '%s'.", query)
            results = list(self.find(query, complete=False))
            ingestion_pipeline.seed(query=query, entities=results)

        # Secondly, run collectors which don't ingest anything and build a list
        # of collectors which do ingest.
        ingesting_collectors = []
        for collector in collectors:
            if collector.ingests:
                logging.debug("Ingesting collector %s deferred.",
                              collector.name)
                ingesting_collectors.append(collector)
                continue

            logging.debug("Non-ingesting collector %s will now run.",
                          collector.name)

            ingestion_pipeline.fill(
                ingest=self.collect(collector, hint=hint),
                collector=collector)

        # Now spin on the remaining collectors until they empty the ingestion
        # pipeline (stop producing new results).
        filling_pipeline = IngestionPipeline(ingestion_queries)
        while not ingestion_pipeline.empty:
            logging.debug("Ingestion pipeline is not empty.")

            # Collectors will read from ingestion pipeline and fill the
            # filling pipeline. At the end of each spin the ingestion pipeline
            # is refilled from the filling pipeline and the filling pipeline
            # is emptied.
            for collector in ingesting_collectors:
                collector_input = list(
                    ingestion_pipeline.find(query=collector.ingests,
                                            trigger=collector.trigger))

                if not collector_input:
                    continue  # Pipeline isn't empty, but has nothing for this.

                logging.debug(
                    "Ingestion pipeline found %d entities for %s.",
                    len(collector_input), collector.name)

                # Feed output back into the pipeline.
                filling_pipeline.fill(
                    collector=collector,
                    ingest=self.collect(
                        collector=collector,
                        ingest=collector_input,
                        hint=hint))

            ingestion_pipeline, filling_pipeline = (filling_pipeline,
                                                    ingestion_pipeline)
            filling_pipeline.flush()

        # And we're done. We can't mark collectors as finished if a hint was
        # used because it may have prevented them from producing all results.
        # Subsequent collection without a hint will produce duplicates but
        # they will be deduplicated and not cause any problems.
        if not hint:
            for collector in collectors:
                self.finished_collectors.add(collector.name)

    def collect(self, collector, hint=None, ingest=None):
        """Runs the collector, registers output and yields any new entities."""
        for results in collector.collect(hint=hint, ingest=ingest):
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

            entity, effect = self.register_components(
                identity=identity,
                components=results,
                source_collector=collector.name)

            yield entity, effect
