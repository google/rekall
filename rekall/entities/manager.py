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

import copy
import itertools
import logging

from rekall.entities import collector as entity_collector
from rekall.entities import component as entity_component
from rekall.entities import entity as entity_module
from rekall.entities import definitions
from rekall.entities import identity as entity_id
from rekall.entities import lookup_table as entity_lookup

from rekall.entities.query import analyzer as query_analyzer
from rekall.entities.query import expression
from rekall.entities.query import matcher as query_matcher


class IngestionPipeline(object):
    """Keeps track of new and updated entities during collection."""

    empty = True

    def __init__(self, queries):
        self.queues = {}
        self.matchers = {}
        for query in queries:
            self.queues[query] = []
            self.matchers[query] = query_matcher.QueryMatcher(query)

    def seed(self, query, entities):
        """Set up the queue for query with entities."""
        self.queues[query] = list(entities)
        if self.queues[query]:
            self.empty = False

    def find(self, query):
        """Return entities available to satisfy the query."""
        if isinstance(query, dict):
            results = {}
            for key, value in query.iteritems():
                results[key] = self.find(value)
            return results

        return self.queues[query]

    def fill(self, ingest, collector):
        """Fills appropriate queues with entities from ingest.

        Arguments:
            ingest: An iterable containing entities and effects of adding them.
                The effects are a dict of:
                    None: How many entities were duplicates, including contents.
                    entity_collector.EffectEnum.Merged: How many entities
                        changed by merging.
                    entity_collector.EffectEnum.Added: How many new entities
                        created.
                    "fill": How many entities were enqueued for ingestion by
                        other collectors.
            collector: The collector object from which ingest was collected.
        """

        counts = {entity_collector.EffectEnum.Duplicate: 0,
                  entity_collector.EffectEnum.Merged: 0,
                  entity_collector.EffectEnum.Added: 0,
                  entity_collector.EffectEnum.Enqueued: 0}

        for entity, effect in ingest:
            counts[effect] += 1

            if effect == entity_collector.EffectEnum.Duplicate:
                continue

            for query in self.queries:
                if self.matchers[query].match(entity):
                    self.queues[query].append(entity)
                    counts[entity_collector.EffectEnum.Enqueued] += 1
                    self.empty = False

        logging.debug(
            "%s results: %d new, %d updated, %d sent to ingest. "
            "pipeline, %d duplicates.",
            collector.name,
            counts[entity_collector.EffectEnum.Added],
            counts[entity_collector.EffectEnum.Merged],
            counts[entity_collector.EffectEnum.Enqueued],
            counts[entity_collector.EffectEnum.Duplicate])

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

    # Names of collectors that have produced all they're going to produce.
    finished_collectors = None

    # Dict of entities keyed by their identity.
    entities = None

    def __init__(self, session):
        self.entities = {}
        self.session = session
        self.finished_collectors = set()
        self._collectors = {}
        self._cached_query_analyses = {}
        self._cached_matchers = {}

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
        """Refresh the list of active collectors. Do a diff if possible."""
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
            An instance of Identity initialized with the identity dict and this
            manager's global prefix.
        """
        return entity_id.Identity.from_dict(global_prefix=self.identity_prefix,
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
            EffectEnum.Duplicate: No new information learned.
            EffectEnum.Merged: As result of this call, data in one or more
                entities was updated and entities may have merged.
            EffectEnum.Added: A new entity was added.
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
        effect = entity_collector.EffectEnum.Added
        if existing_entities:
            if (len(existing_entities) == 1 and
                    existing_entities[0].strict_superset(entity)):
                # No new data, but let's give the collector credit for finding
                # what we already knew.
                entity_comp = existing_entities[0].components.Entity
                entity_comp._mutate(
                    member="collectors",
                    value=entity_comp.collectors.union([source_collector]))

                return (existing_entities[0],
                        entity_collector.EffectEnum.Duplicate)

            for existing_entity in existing_entities:
                # Entities exist for this already, but are not equivalent to
                # the entity we found. Merge everything.
                effect = entity_collector.EffectEnum.Merged
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

        lookup_table = entity_lookup.AttributeLookupTable(
            attribute=key,
            entity_manager=self)

        # Only use the entities that actually have the component to build the
        # index.
        lookup_table.update_index(
            self.find(expression.ComponentLiteral(component), complete=False))

        self.lookup_tables[key] = lookup_table

    def find_by_identity(self, identity, complete=False):
        """Yield the entities that matches the identity.

        The number of entities yielded is almost always one or zero. The single
        exception to that rule is when the identity parameter is both: (a) a
        alternate identity and (b) not yet present in this entity manager. In
        that case, multiple entities may match.

        Arguments:
            identity: The identity to search for.
            complete: Should collectors be run to ensure complete results?
        """
        if complete:
            for _, attribute, value in identity.indices:
                self.collect_for(
                    expression.Equivalence(
                        expression.Binding(attribute),
                        expression.Literal(value)))

        results = set()
        for index in identity.indices:
            entity = self.entities.get(index, None)
            if entity:
                results.add(entity)

        if complete:
            results = [self.parse(entity) for entity in results]

        return list(results)

    def find_by_component(self, component, complete=True):
        """Yields all entities that have the component.

        Arguments:
            complete: If True, will attempt to collect the component.
        """
        query = expression.ComponentLiteral(component)
        if complete:
            self.collect_for(query)

        return list(self.lookup_tables["components"].lookup(component))

    def find_by_collector(self, collector):
        return list(self.lookup_tables["collectors"].lookup(str(collector)))

    def matcher_for(self, query):
        matcher = self._cached_matchers.setdefault(
            query, query_matcher.QueryMatcher(query))

        return matcher

    def parsers_for(self, entity):
        """Finds collectors that can parse this entity."""
        for collector in self.collectors:
            if not collector.collect_args:
                continue
            for query_name, query in collector.collect_args.iteritems():
                matcher = self.matcher_for(query)
                if matcher.match(entity):
                    yield collector, query_name

    def parse(self, entity):
        """Parses the entity using available higher-order collectors."""
        result = entity
        for collector, collect_kwarg in self.parsers_for(entity):
            collector_input = {collect_kwarg: [result]}
            for parsed, effect in self.collect(collector=collector,
                                               collector_input=collector_input,
                                               hint=None):
                if effect != entity_collector.EffectEnum.Duplicate:
                    logging.debug(
                        "Collector %s produced a hit in parser mode.",
                        collector.name)
                    result = parsed

        return result

    def analyze(self, wanted):
        """Finds collectors and indexing suggestions for the query.

        Returns a dict of:
            - collectors: list of collectors to run
            - lookups: list of attributes to consider indexing for
            - dependencies: list of SimpleDependency instances to include
            - exclusions: list of SimpleDependency instances to exclude
        """
        analysis = self._cached_query_analyses.get(wanted, None)
        if analysis:
            # We want to make a copy exactly one level deep.
            analysis_copy = {}
            for key, value in analysis.iteritems():
                analysis_copy[key] = copy.copy(value)
            return analysis_copy

        analyzer = query_analyzer.QueryAnalyzer(wanted)
        include, exclude, suggested_indices = analyzer.run()

        # A collector is a match if any of its promises match any of the
        # dependencies of the query.
        matched_collectors = []
        for collector in self.collectors:
            for promise, dependency in itertools.product(
                    collector.promises, include):
                if dependency.match(promise):
                    matched_collectors.append(collector)
                    break

        # A collector is yielded unless each one of its promises matches
        # an exclusion from dependencies.
        collectors = set()
        for collector in matched_collectors:
            for promise, exclusion in itertools.product(
                    collector.promises, exclude):
                if not exclusion.match(promise):
                    collectors.add(collector)
                    break
            else:
                # No exclusions.
                collectors.add(collector)

        analysis = dict(collectors=list(collectors),
                        lookups=suggested_indices,
                        dependencies=include,
                        exclusions=exclude)
        self._cached_query_analyses[wanted] = analysis
        return analysis

    def find(self, query, complete=True):
        """Runs the query and yields entities that match.

        Arguments:
            complete: If True, will trigger collectors as necessary, to ensure
            completness of results.
        """
        if complete:
            self.collect_for(query)

        if isinstance(query, dict):
            results = {}
            for query_name, expr in query.iteritems():
                results[query_name] = self.find(expr, complete=complete)

            return results

        # Try to satisfy the query using available lookup tables.
        search = entity_lookup.EntityQuerySearch(query)
        return search.search(self.entities, self.lookup_tables)

    def find_first(self, query, complete=True):
        for entity in self.find(query, complete):
            return entity

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

        # Plan execution.
        self.update_collectors()

        # to_process is used as a FIFO queue below.
        analysis = self.analyze(wanted)
        to_process = analysis["collectors"]
        suggested_indices = analysis["lookups"]

        # Create indices as suggested by the analyzer.
        for attribute in suggested_indices:
            self.add_attribute_lookup(attribute)

        collectors_seen = set(self.finished_collectors)

        # Collectors with an ingest query are de-facto parsers for things
        # produced by collectors with no ingest query. They may run repeatedly
        # as required.
        repeated = list()

        # Collectors with no dependencies (my favorite).
        simple = list()

        # Queries that collectors depend on.
        queries = set()

        while to_process:
            collector = to_process.pop(0)
            if collector.name in collectors_seen:
                continue

            collectors_seen.add(collector.name)
            if collector.collect_args:
                logging.debug("%s (collect_args '%s') deferred.",
                              collector.name, collector.collect_args)
                repeated.append(collector)
                queries |= set(collector.collect_args.itervalues())

                # Discard the indexing suggestions for ingestion queries
                # because they don't represent normal usage.
                additional = set()
                for query in collector.collect_args.itervalues():
                    additional |= set(self.analyze(query)["collectors"])

                for dependency in additional:
                    logging.debug(
                        "Collector %s depends on collector %s for its ingest "
                        "query '%s'.",
                        collector.name, dependency.name, collector.collect_args)
                    if dependency.name not in collectors_seen:
                        to_process.append(dependency)
            else:
                logging.debug("%s (no dependencies) will run immediately.",
                              collector.name)
                simple.append(collector)

        if not collectors_seen.difference(self.finished_collectors):
            # Looks like we're already populated - no need to do anything.
            return

        logging.info(
            "Will now run %d first-order collectors and %d collectors with "
            "dependencies to satisfy query %s.",
            len(simple), len(repeated), wanted)

        # Execution stage 1: no dependencies.
        logging.debug("%d non-ingesting collectors will now run once.",
                      len(simple))

        for collector in simple:
            effects = {entity_collector.EffectEnum.Duplicate: 0,
                       entity_collector.EffectEnum.Merged: 0,
                       entity_collector.EffectEnum.Added: 0}

            if use_hint or collector.enforce_hint:
                hint = wanted
            else:
                hint = None
                self.finished_collectors.add(collector)

            for _, effect in self.collect(collector, hint=hint):
                effects[effect] += 1

            logging.debug(
                "%s produced %d new entities, %d updated and %d duplicates",
                collector.name,
                effects[entity_collector.EffectEnum.Added],
                effects[entity_collector.EffectEnum.Merged],
                effects[entity_collector.EffectEnum.Duplicate])

        if not repeated:
            # No ingesting collectors scheduled. We're done.
            return

        # Seeding stage for ingesting collectors.
        in_pipeline = IngestionPipeline(queries=queries)
        out_pipeline = IngestionPipeline(queries=queries)
        for query in queries:
            results = self.find(query, complete=False)
            in_pipeline.seed(query, results)
            logging.debug("Pipeline seeded with %d entities matching '%s'",
                          len(results), query)

        # Execution stage 2: collectors with dependencies.

        # Collectors should run in FIFO order:
        repeated.reverse()

        # This will spin until none of the remaining collectors want to run.
        while not in_pipeline.empty:
            # Collectors will read from the in_pipeline and fill the
            # out_pipeline. At the end of each spin the pipelines swap and
            # the new out_pipeline is flushed.
            for collector in repeated:
                # If the collector wants complete input, we pull it from the
                # database. If it just wants one entity at a time, we can use
                # the ingestion pipeline. The semantics of both find methods
                # are identical.
                if collector.complete_input:
                    collector_input = self.find(collector.collect_args,
                                                complete=False)
                else:
                    collector_input = in_pipeline.find(collector.collect_args)

                # The collector requests its prefilter to be called.
                if collector.filter_input:
                    logging.debug("Running %s with input filter.",
                                  collector.name)
                    collector_input_filtered = {}
                    for key, val in collector_input.iteritems():
                        collector_input_filtered[key] = collector.input_filter(
                            hint=hint, entities=val)
                    collector_input = collector_input_filtered
                else:
                    logging.debug("Running %s.", collector.name)

                # The collector requests that we always pass the query hint.
                if use_hint or collector.enforce_hint:
                    hint = wanted
                else:
                    hint = None

                # Feed output back into the pipeline.
                results = self.collect(collector=collector,
                                       collector_input=collector_input,
                                       hint=hint)
                out_pipeline.fill(collector=collector,
                                  ingest=results)

            # Swap & flush, rinse & repeat.
            in_pipeline, out_pipeline = out_pipeline, in_pipeline
            out_pipeline.flush()

        for collector in repeated:
            if not use_hint and not collector.enforce_hint:
                self.finished_collectors.add(collector.name)

    def collect(self, collector, hint, collector_input=None):
        """Runs the collector, registers output and yields any new entities."""
        if collector_input is None:
            collector_input = {}

        for results in collector.collect(hint=hint, **collector_input):
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
