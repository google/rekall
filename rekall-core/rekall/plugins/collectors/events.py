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

from rekall.entities import definitions
from rekall.entities import collector


class EventInferenceCollector(collector.EntityCollector):
    """Generates Events from entities that have Timestamps."""

    outputs = ["Event"]
    collect_args = dict(entities="has component Timestamps")

    run_cost = collector.CostEnum.NoCost

    @classmethod
    def is_active(cls, session):
        return True

    # pylint: disable=protected-access
    def collect(self, hint, entities=None):
        manager = self.manager
        for entity in entities:
            for field in definitions.Timestamps.component_fields:
                timestamp = getattr(entity.components.Timestamps, field.name)
                action = field.name.replace("_at", "")
                if not timestamp:
                    continue

                event_identity = manager.identify({
                    ("Event/timestamp", "Event/action", "Event/target"):
                    (timestamp, action, entity.identity)})

                if timestamp:
                    yield [event_identity,
                           definitions.Event(target=entity.identity,
                                             timestamp=timestamp,
                                             action=action)]
