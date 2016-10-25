#!/usr/bin/env python2

# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
#
# Author: Michael Cohen scudette@google.com
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

__author__ = "Michael Cohen <scudette@google.com>"

"""Client Actions are plugins which run in live mode.

A flow will deliver a number of actions to execute.
"""
from rekall_agent import common
from rekall_agent import serializer


class Action(common.AgentConfigMixin, serializer.SerializedObject):
    """Requests a client action to run on the agent.

    Action implementations will extend this message.
    """

    schema = [
        dict(name="flow_id",
             doc="Unique flow name that owns this request."),
        dict(name="condition",
             doc="An Efilter condition to evaluate before running."),
        dict(name="session", type="dict",
             doc="If provided, runs this action in a dedicated session."),
    ]

    @property
    def client_id(self):
        return self._config.client.writeback.client_id

    def is_active(self):
        """Returns true is this action is active."""
        if self.condition:
            try:
                if not list(self._session.plugins.search(self.condition)):
                    return False

            # If the query failed to run we must ignore this flow.
            except Exception as e:
                self._session.logging.exception(e)
                return False

        return True

    def run(self, flow_obj=None):
        """Called by the client to execute this action.

        Returns a list of collections that have been written by this action.
        """
