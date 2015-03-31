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

from rekall.entities.query import expression
from rekall.entities.query import matcher as query_matcher
from rekall.entities.query import query as entity_query


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

    def fill(self, ingest, collector, wanted_matcher=None, wanted_handler=None):
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

            if wanted_handler and wanted_matcher.match(entity):
                wanted_handler(entity)

            for query in self.queries:
                if self.matchers[query].match(entity):
                    self.queues[query].append(entity)
                    counts[entity_collector.EffectEnum.Enqueued] += 1
                    self.empty = False

        if any(counts.itervalues()):
            logging.debug(
                "%s results: %d new, %d updated, %d requeued, %d duplicates.",
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
        return self._collectors

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
        # Cast values to their correct types.
        cast_dict = {}
        for key, val in identity_dict.iteritems():
            if isinstance(key, tuple):
                cast_vals = []
                for idx, attr in enumerate(key):
                    attribute = entity_module.Entity.reflect_attribute(attr)
                    cast_vals.append(attribute.typedesc.coerce(val[idx]))
                cast_val = tuple(cast_vals)
            else:
                attribute = entity_module.Entity.reflect_attribute(key)
                cast_val = attribute.typedesc.coerce(val)

            cast_dict[key] = cast_val

        return entity_id.Identity.from_dict(global_prefix=self.identity_prefix,
                                            identity_dict=cast_dict)

    def identify_no_cast(self, identity_dict):
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

        indices = set(entity.indices)

        existing_entities = list(self.find_by_identity(identity))
        effect = entity_collector.EffectEnum.Added
        if existing_entities:
            if (len(existing_entities) == 1 and
                    existing_entities[0].issuperset(entity)):
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
        Depending on how many entities already exist, building the index could
        take a couple of seconds.
        """
        # Don't add the same one twice.
        if self.lookup_tables.get(key, None):
            return

        attribute = entity_module.Entity.reflect_attribute(key)
        if not isinstance(attribute, entity_component.Field):
            logging.info(
                ("Can't create a lookup for %s, because it's not a simple "
                 "field."), attribute)
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
            self.collect_for(identity.as_query())

        results = set()
        for index in identity.indices:
            entity = self.entities.get(index, None)
            if entity:
                results.add(entity)

        if complete:
            results = [self.parse(entity) for entity in results]

        return list(results)

    def find_by_component(self, component, complete=True):
        """Finds all entities that have the component.

        Arguments:
            complete: If True, will attempt to collect the component.
        """
        query = entity_query.Query(expression.ComponentLiteral(component))
        if complete:
            self.collect_for(query)

        return list(self.lookup_tables["components"].lookup(component))

    def find_by_collector(self, collector):
        """Find all entities touched by the collector."""
        return list(self.lookup_tables["collectors"].lookup(str(collector)))

    def matcher_for(self, query):
        """Returns a query matcher for the query (cached)."""
        matcher = self._cached_matchers.setdefault(
            query, query_matcher.QueryMatcher(query))

        return matcher

    def parsers_for(self, entity):
        """Finds collectors that can parse this entity.

        Yields: tuples of:
            - collector instance
            - name of the keyword argument on the collect method under which
              the entity should be passed to the collector.
        """
        for collector in self.collectors.itervalues():
            if len(collector.collect_queries) != 1:
                continue
            for query_name, query in collector.collect_queries.iteritems():
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
        if not isinstance(wanted, entity_query.Query):
            wanted = entity_query.Query(wanted)

        # We cache by the source and not the query because we want to reanalyze
        # queries that are logically equivalent, but expressed differently, in
        # order to have the right cursor positions stored for highlighting in
        # GUI.
        cache_key = wanted.source

        analysis = self._cached_query_analyses.get(cache_key, None)
        if analysis:
            # We want to make a copy exactly one level deep.
            analysis_copy = {}
            for key, value in analysis.iteritems():
                analysis_copy[key] = copy.copy(value)
            return analysis_copy

        analyzer = wanted.execute("QueryAnalyzer")
        include = analyzer.include
        exclude = analyzer.exclude
        suggested_indices = analyzer.latest_indices

        # A collector is a match if any of its promises match any of the
        # dependencies of the query.
        matched_collectors = []
        for collector in self.collectors.itervalues():
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

        # A component is guaranteed if any dependency lists it. It is likely
        # if collectors we depend on output it (though not guaranteed).
        guaranteed_components = set(analyzer.expected_components)
        possible_components = set()

        for dependency in include:
            component = dependency.component
            if component in guaranteed_components:
                continue
            possible_components.add(dependency.component)

        for collector in collectors:
            for promise in collector.promises:
                component = promise.component
                if component in guaranteed_components:
                    continue

                possible_components.add(component)

        analysis = dict(collectors=list(collectors),
                        lookups=suggested_indices,
                        dependencies=include,
                        exclusions=exclude,
                        guaranteed_components=guaranteed_components,
                        possible_components=possible_components)
        self._cached_query_analyses[cache_key] = analysis

        return analysis

    def find(self, query, complete=True, validate=True, query_params=None):
        """Runs the query and yields entities that match.

        Arguments:
            query: Either an instance of the query AST, a query string, or a
                   dictionary of queries. If a dict is given, a new dict will
                   be returned with the same keys and values replaced with
                   results.

            complete: If True, will trigger collectors as necessary, to ensure
                      completness of results.

            validate: Will cause the query to be validated first (mostly for
                      type errors.)
        """
        if isinstance(query, dict):
            results = {}
            for query_name, expr in query.iteritems():
                results[query_name] = self.find(expr, complete=complete,
                                                validate=validate,
                                                query_params=query_params)

            return results

        if not isinstance(query, entity_query.Query):
            query = entity_query.Query(query, params=query_params)

        if validate:
            query.execute("QueryValidator")

        if complete:
            self.collect_for(query)

        # Try to satisfy the query using available lookup tables.
        search = entity_lookup.EntityQuerySearch(query)
        return search.search(self.entities, self.lookup_tables)

    def stream(self, query, handler, query_params=None):
        query = entity_query.Query(query, params=query_params)
        seen = set()

        def _deduplicator(entity):
            if entity in seen:
                return

            seen.add(entity)
            handler(entity)

        self.collect_for(query, result_stream_handler=_deduplicator)
        for entity in self.find(query, complete=False):
            _deduplicator(entity)

    def find_first(self, query, complete=True, validate=True,
                   query_params=None):
        """Like find, but returns just the first result."""
        for entity in self.find(query, complete, validate, query_params):
            return entity

    # pylint: disable=protected-access
    def collect_for(self, wanted, use_hint=False, result_stream_handler=None):
        """Will find and run the appropriate collectors to satisfy the query.

        If use_hint is set to True, 'wanted' will be passed on as hint to
        the collectors. This may result in faster collection, but may result
        in collectors having to run repeatedly.
        """
        # Planning stage.

        if callable(result_stream_handler):
            wanted_matcher = query_matcher.QueryMatcher(wanted)
        else:
            wanted_matcher = None

        self.update_collectors()

        # to_process is used as a FIFO queue below.
        analysis = self.analyze(wanted)
        to_process = analysis["collectors"][:]
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

        # Build up a list of collectors to run, based on dependencies.
        while to_process:
            collector = to_process.pop(0)
            if collector.name in collectors_seen:
                continue

            collectors_seen.add(collector.name)
            if collector.collect_queries:
                logging.debug("Collector %s deferred until stage 2.",
                              collector.name)
                repeated.append(collector)
                queries |= set(collector.collect_queries.itervalues())

                # Discard the indexing suggestions for ingestion queries
                # because they don't represent normal usage.
                additional = set()
                for query in collector.collect_queries.itervalues():
                    additional |= set(self.analyze(query)["collectors"])

                for dependency in additional:
                    logging.debug("Collector %s depends on collector %s.",
                                  collector.name, dependency.name)
                    if dependency.name not in collectors_seen:
                        to_process.append(dependency)
            else:
                logging.debug("%s will run in stage 1.",
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

        for collector in simple:
            effects = {entity_collector.EffectEnum.Duplicate: 0,
                       entity_collector.EffectEnum.Merged: 0,
                       entity_collector.EffectEnum.Added: 0}

            if use_hint or collector.enforce_hint:
                hint = wanted
            else:
                hint = None
                self.finished_collectors.add(collector.name)

            for entity, effect in self.collect(collector, hint=hint):
                if result_stream_handler and wanted_matcher.match(entity):
                    result_stream_handler(entity)

                effects[effect] += 1

            logging.debug(
                "%s produced %d new entities, %d updated and %d duplicates",
                collector.name,
                effects[entity_collector.EffectEnum.Added],
                effects[entity_collector.EffectEnum.Merged],
                effects[entity_collector.EffectEnum.Duplicate])

        if not repeated:
            # No higher-order collectors scheduled. We're done.
            return

        # Seeding stage for higher-order collectors.
        in_pipeline = IngestionPipeline(queries=queries)
        out_pipeline = IngestionPipeline(queries=queries)
        for query in queries:
            results = self.find(query, complete=False)
            in_pipeline.seed(query, results)
            if results:
                logging.debug("Pipeline seeded with %d entities matching '%s'",
                              len(results), query)

        # Execution stage 2: collectors with dependencies.

        # Collectors should run in FIFO order:
        repeated.reverse()

        counter = 0
        # This will spin until none of the remaining collectors want to run.
        while not in_pipeline.empty:
            # TODO (adamsh):
            # There is a better way to detect faulty collector output and
            # infinite loops, but this counter will do for now.
            if counter > 100:
                raise RuntimeError(
                    ("Entity manager exceeded 100 iterations during "
                     "higher-order collector resolution. You most likely "
                     "have a faulty collector."))

            # Collectors will read from the in_pipeline and fill the
            # out_pipeline. At the end of each spin the pipelines swap and
            # the new out_pipeline is flushed.
            for collector in repeated:
                # If the collector wants complete input, we pull it from the
                # database. If it just wants one entity at a time, we can use
                # the ingestion pipeline. The semantics of both find methods
                # are identical.
                if collector.complete_input:
                    collector_input = self.find(collector.collect_queries,
                                                complete=False)
                else:
                    collector_input = in_pipeline.find(
                        collector.collect_queries)

                # The collector requests its prefilter to be called.
                if collector.filter_input:
                    collector_input_filtered = {}
                    for key, val in collector_input.iteritems():
                        collector_input_filtered[key] = collector.input_filter(
                            hint=hint, entities=val)
                    collector_input = collector_input_filtered

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
                                  ingest=results,
                                  wanted_handler=result_stream_handler,
                                  wanted_matcher=wanted_matcher)

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

        result_counter = 0

        if self.session:
            self.session.report_progress(
                "Collecting %(collector)s %(spinner)s",
                collector=collector.name)

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
                try:
                    identity = self.identify({attribute: first_result[0]})
                except entity_id.IdentityError:
                    logging.error(
                        ("Invalid identity %s inferred from output of %s. "
                         "Entity skipped. Full results: %s"),
                        {attribute: first_result[0]},
                        collector,
                        results)
                    continue

            entity, effect = self.register_components(
                identity=identity,
                components=results,
                source_collector=collector.name)

            result_counter += 1
            if result_counter % 100 == 0 and self.session:
                self.session.report_progress(
                    "Collecting %(collector)s %(spinner)s (%(count)d results)",
                    collector=collector.name,
                    count=result_counter)

            yield entity, effect
