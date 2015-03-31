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

import re

from rekall import registry

from rekall.entities.query import analyzer
from rekall.entities.query import query as entity_query


class CostEnum(object):
    NoCost = 0
    LowCost = 1
    NormalCost = 2
    HighCost = 3
    VeryHighCost = 4


class EffectEnum(object):
    """Various outcomes of registering an entity."""

    Enqueued = 0  # Entity was enqueued for processing.
    Added = 1  # Result is a new entity.
    Merged = 2  # Result is an udpated (merged) entity.
    Duplicate = 3  # No new data.


class EntityCollector(object):
    """Base class for entity collectors.

    EntityCollector subclasses need to override the 'collect' method and the
    'outputs' ivar. EntityCollector takes care of registering collected
    entities with the EntityManager, deciding whether the collector should be
    called for manager-driven queries and ensuring collection is only done once
    per cache lifetime.

    Intended subclass overrides:
    ============================

    ### self.outputs (ivar, required):
    Override with a list of collection promises. Each promise should represent
    a component the collector yields on a call to collect, like so:

    outputs = ["Process", "Timestamps"]

    The collector may also specify a value it guarantees will be set on the
    entities it yields. The format for doing so is:

    outputs = ["Struct/type=proc"]

    The collector is not required to actually deliver on all of its promises,
    but it is not allowed to yield something it didn't promise.

    ### self.collect_args (ivar, optional):
    Collectors can specify the kind of input they want using a dictionary of
    queries describing the input, keyed on the names of kwargs they should be
    supplied as. The manager may call collectors with dependencies more than
    once, as new data becomes available.

    Examples:

    # ProcessParser wants proc structs. Its collect method will now receive
    # a keyword arg 'procs' populated with entities matching the query.
    collect_args = {"procs": "Struct/type is 'proc'"}

    # Socket/process relationship inference wants sockets and processes.
    # Its collect method will now receive two keyword args - 'processes' with
    # process entities, and 'sockets' with base object entities.
    collect_args = {"processes": "has component Process",
                    "sockets": "Struct/type" is 'socket'}

    ### self.filter_input (ivar, optional):
    Costly collectors can flip this variable to True, which will cause the
    manager to call self.input_filter to prefilter the ingestion set, giving
    the collector the opportunity to filter out entities it has parsed before.

    ### self.run_cost (ivar, optional):
    Should be set to a CostEnum value, estimating how expensive the collector is
    in terms of performance.

    ### self.enforce_hint (ivar, optional):
    If True, the manager will always supply a hint to the collect function. If
    False, the manager will only supply a hint when it's collecting for
    artifacts.

    ### self.complete_input (ivar, optional):
    If True, will cause the manager to always call the collect method with all
    available results for the ingestion queries, even if they've been sent
    before and haven't been updated since. The results can still be filtered
    with filter_input.
    """

    outputs = []  # Subclasses must override. See above.
    _promises = None  # Promises (SimpleDependency) generated from outputs.

    collect_args = None  # Subclasses may override.
    collect_queries = None  # Will be populated automatically on init.

    run_cost = CostEnum.NormalCost
    enforce_hint = False
    filter_input = False
    complete_input = False

    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    DELIMITER = re.compile(r"[\/=]")

    def __init__(self, entity_manager=None):
        self.manager = entity_manager
        self.session = entity_manager.session
        self._indices_seen = set()
        self.collect_queries = {}
        self._ensure_compile_queries()

    @property
    def profile(self):
        return self.session.profile

    @property
    def name(self):
        return getattr(self, "_name", type(self).__name__)

    @property
    def promises(self):
        self._ensure_compile_promises()
        return self._promises

    def _ensure_compile_promises(self):
        if not self._promises:
            self._promises = [analyzer.SimpleDependency.parse(output)
                              for output in self.outputs]

        # All collectors return Entity.
        self._promises.append(analyzer.SimpleDependency("Entity"))

    def _ensure_compile_queries(self):
        if self.collect_queries or self.collect_args is None:
            return

        for arg, source in self.collect_args.iteritems():
            self.collect_queries[arg] = entity_query.Query(source)

    @property
    def is_collected(self):
        """Set to True after self.collect runs with no hints.

        Running collect with a non-null hint will not flip this."""
        return self.name in self.manager.finished_collectors

    # pylint: disable=unused-argument
    def input_filter(self, hint, entities=None):
        """Filter the ingest set. Use to prevent parsing the same thing twice.

        Default implementation of the ingest filter will keep a set of entities
        it has processed before and filter those out. Subclasses can override.

        NOTE: Ingest filter is disabled by default - subclasses that wish the
        manager to enable it must signal so by setting filter_input to True.
        """
        for entity in entities:
            if not entity.indices & self._indices_seen:
                yield entity

            self._indices_seen |= entity.indices

    def prebuild(self, components, keys):
        """Prebuilds identity based on data in components.

        In the olden days, identities could be arbitrary and were not tied
        to data in the entity. The current API (Manager.identify) theoretically
        still allows creation of identities with arbitrary indices, but that's
        slow, as the data in the entity and the identity then has to be
        type-coerced separately. This method is the new API and only coerces
        data once.

        Arguments:
            components: Instances of Component that the collector is going to
                        yield.
            keys: List of attributes that will be used to build the identity.

        Returns tuple of:
        - The identity.
        - List that can be yielded from Collector.collect, which includes the
          identity.
        """
        index_values = []
        for key in keys:
            component_name, field_name = key.split("/", 1)

            # Find the component.
            for component in components:
                if component.component_name == component_name:
                    index_values.append(component[field_name])
                    break

        identity = self.manager.identify_no_cast(
            {tuple(keys): tuple(index_values)})
        return identity, [identity] + list(components)

    def collect(self, hint):
        """Override to yield components - analogous to 'calculate', but typed.

        Subclasses should override this to yield components that represent the
        data they collect. For example, a pslist collector would yield Process
        components. Only components listed in self.outputs should be yielded
        and no other.

        Output format:
        ==============

        In the simplest case, yield one component at a time. To indicate two
        (or more) components are related, yield both in a list (for example,
        Process and the Struct wrapping the proc struct representing it
        in kernel).

        Unless an identity is specified explicitly, one will be created
        automatically by taking the first field of the first component and
        instantiating an identity with it.

        To specify an identity explicitly, yield the Entity component as first
        in the list and provide the identity in its 'identity' field.

        Examples:
        =========

        # Yielding just one component at a time:
        yield manager.Process(
            pid=proc.p_pid,
            ...)

        # Yielding the process component and the BSD proc struct:
        yield [
            manager.Process(pid=proc.p_pid, ...),
            manager.Struct(base=proc, ...),
        ]

        # In both above examples, the identity will be "Process/pid=(PID here)."
        # Specifying an explicit identity would look like this:
        yield [
            manager.Entity(identity=ProcessIdentity(...)),
            manager.Process(pid=proc.p_pid, ...),
            manager.Struct(base=proc, ...),
        ]

        Optimization hints:
        ===================

        A hint may be passed to the collect method, in which case the collector
        may elect to only collect some information it's capable of collecting
        and not all. For example, a hint to the pslist collector may specify
        that the caller only cares about processes listed by walking the
        process head list. The format of the hint is currently not specified.
        """
        pass

    @classmethod
    def is_active(cls, session):
        return cls.run_cost <= session.GetParameter("max_collector_cost")

    @property
    def entities(self):
        """Returns this collector's entities."""
        return self.session.entities.find_by_collector(self.name)
