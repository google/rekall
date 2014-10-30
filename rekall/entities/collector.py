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


class CostEnum(object):
    NoCost = 0
    LowCost = 1
    NormalCost = 2
    HighCost = 3
    VeryHighCost = 4


class EntityCollector(object):
    """Base class for entity collectors.

    EntityCollector subclasses need to override the 'collect' method and the
    'outputs' ivar. EntityCollector takes care of registering collected
    entities with the EntityManager, deciding whether the collector should be
    called for manager-driven queries and ensuring collection is only done once
    per cache lifetime.
    """

    outputs = []  # Subclasses must override. See 'can_collect' below.
    _promises = None  # Promises (SimpleDependency) generated from outputs.

    ingests = None  # Subclasses may override.

    # Used to decide which collectors to enable.
    run_cost = CostEnum.NormalCost

    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    DELIMITER = re.compile(r"[\/=]")

    def __init__(self, entity_manager=None):
        self.manager = entity_manager
        self.session = entity_manager.session

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

    @property
    def is_collected(self):
        """Set to True after self.collect runs with no hints.

        Running collect with a non-null hint will not flip this."""
        return self.name in self.manager.finished_collectors

    def collect(self, hint=None, ingest=None):
        """Override to yield components - analogous to 'calculate', but typed.

        Subclasses should override this to yield components that represent the
        data they collect. For example, a pslist collector would yield Process
        components. Only components listed in self.outputs should be yielded
        and no other.

        Output format:
        ==============

        In the simplest case, yield one component at a time. To indicate two
        (or more) components are related, yield both in a list (for example,
        Process and the MemoryObject wrapping the proc struct representing it
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
            manager.MemoryObject(base_object=proc, ...),
        ]

        # In both above examples, the identity will be "Process/pid=(PID here)."
        # Specifying an explicit identity would look like this:
        yield [
            manager.Entity(identity=ProcessIdentity(...)),
            manager.Process(pid=proc.p_pid, ...),
            manager.MemoryObject(base_object=proc, ...),
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
