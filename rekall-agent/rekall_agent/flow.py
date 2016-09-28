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

"""Flows are routines that run in the controller and schedule jobs for clients.
"""
import os
import time

from rekall_agent import action
from rekall_agent import common
from rekall_agent import result_collections
from rekall_agent import serializer

from rekall_agent.messages import batch


class FlowStatus(batch.BatchTicket):
    """Information about flow's progress.

    As the agent works through the flow, this ticket will be updated with status
    information.
    """

    schema = [
        dict(name="client_id"),
        dict(name="flow_id"),

        dict(name="logs", repeated=True,
             doc="Log lines from the client."),

        dict(name="status", type="choices",
             choices=["Pending", "Started", "Done", "Error"]),

        dict(name="error",
             doc="If an error occurred, here will be the error message."),

        dict(name="backtrace",
             doc="If an error occurred, here will be the backtrace."),

        dict(name="current_action", type=action.Action,
             doc="The currently running client action."),

        dict(name="collections", type=result_collections.CollectionSpec,
             repeated=True,
             doc="The collections produced by the flow."),
    ]



class Flow(serializer.SerializedObject):
    """A Flow is a sequence of client actions.

    To launch a flow simply build a Flow object and call its start() method.
    """
    schema = [
        dict(name="client_id"),

        dict(name="flow_id",
             doc="Flow unique ID of this flow."),

        dict(name="condition",
             doc="An EFilter query to evaluate if the flow should be run."),

        dict(name="created_time", type="epoch",
             doc="When the flow was created."),

        dict(name="creator",
             doc="The user that created this flow."),

        dict(name="ttl", type="int", default=60*60*24,
             doc="How long should this flow remain active."),

        dict(name="ticket", type=FlowStatus,
             doc="Ticket keeping the state of this flow."),

        dict(name="actions", type=action.Action, repeated=True,
             doc="The action requests sent to the client."),
    ]

    def generate_actions(self):
        """Yields one or more Action() objects.

        Should be overridden by derived classes.
        """
        return []

    def start(self):
        """Launch the flow."""
        self._config = self._session.GetParameter("agent_config")
        if not self.client_id:
            self.client_id = self._session.GetParameter(
                "controller_context")
            if not self.client_id:
                raise RuntimeError("A client_id must be provided.")

        # Make a random flow id.
        self.flow_id = "F_%s" % os.urandom(5).encode("hex")
        self.created_time = time.time()

        self.actions = list(self.generate_actions())

        # Create a ticket location for the agent to report progress.
        self.ticket.client_id = self.client_id
        self.ticket.status = "Pending"
        self.ticket.flow_id = self.flow_id
        self.ticket.location = self._config.server.flow_ticket_for_client(
            "FlowStatus", self.flow_id, path_template="{client_id}",
            expiration=time.time() + self.ttl)
        self.ticket.send_message()

        # Add the new flow to the jobs file.
        jobs_location = self._config.server.jobs_queue_for_server(
            self.client_id)

        # Note this happens under lock.
        jobs_location.read_modify_write(self._add_flow_to_jobs_file)

        # Announce the new flow.
        FlowAnnouncement.from_keywords(
            location=self._config.server.ticket_for_server(
                "FlowAnnouncement", self.client_id, self.flow_id),
            flow=self,
            session=self._session).send_message()

    def expiration(self):
        return time.time() + self.ttl

    def _add_flow_to_jobs_file(self, jobs_file_content):
        """Safely add flow to the jobs file.

        This also trims the jobs file to remove all flows which have been
        completed.
        """
        jobs_file = JobFile.from_json(jobs_file_content, session=self._session)

        # Remove those flows which are done.
        filtered_flows = []
        for flow_obj in common.THREADPOOL.imap_unordered(
                self._check_flow_active, jobs_file.flows):
            if flow_obj:
                filtered_flows.append(flow_obj)

        # Make sure the flows are sorted by create time.
        filtered_flows.sort(key=lambda x: x.created_time)

        jobs_file.flows = filtered_flows

        jobs_file.flows.append(self)

        return jobs_file.to_json()

    def _check_flow_active(self, flow_obj):
        ticket_location = self._config.server.ticket_for_server(
            "FlowStatus", flow_obj.client_id, flow_obj.flow_id)
        data = ticket_location.read_file()
        if data:
            try:
                flow_status = FlowStatus.from_json(data, session=self._session)
            except ValueError:
                return

            # Remove flows which do not need to be processed again by the
            # client from the jobs file. Note the tickets remain in place.
            if flow_status.status in ["Done", "Error"]:
                self._session.logging.debug(
                    "Removed old flow %s", flow_obj.flow_id)
                return

        return flow_obj


class JobFile(serializer.SerializedObject):
    """The contents of the jobs file.

    The job file contains a list of flows to execute. Each flow contains a list
    of client actions.
    """

    schema = [
        dict(name="flows", type=Flow, repeated=True,
             doc="A list of flows issued to this client."),
    ]


class FlowStatsCollection(result_collections.GenericSQLiteCollection):
    _tables = [dict(
        name="default",
        columns=[
            dict(name="type"),
            dict(name="status"),
            dict(name="created", type="epoch"),
            dict(name="flow_id"),
            dict(name="flow_data"),
            dict(name="ticket_data")
        ]
    )]


class FlowAnnouncement(batch.BatchTicket):
    """A new flow was created."""
    schema = [
        dict(name="flow", type=Flow,
             doc="The flow that was created."),
    ]

    def process(self, context):
        # Just group flow announcements by client id. We do all the real work in
        # the end() method.
        context.setdefault(self.flow.client_id, []).append(self.flow)

    @classmethod
    def end(cls, context, session=None):
        # Each client's flow collection can be modified on its own
        # independently.
        common.THREADPOOL.map(
            cls._process_flows,
            [(flows, client_id, session)
             for client_id, flows in context.iteritems()])

    @staticmethod
    def _process_flows(_args):
        flows, client_id, session = _args
        config = session.GetParameter("agent_config")
        flow_collection = FlowStatsCollection.from_keywords(
            session=session,
            location=config.server.flow_db_for_server(client_id))

        flow_collection.open("a")

        for flow_obj in flows:
            flow_collection.insert(
                type=flow_obj.__class__.__name__,
                created=flow_obj.created_time,
                flow_id=flow_obj.flow_id,
                flow_data=flow_obj.to_json())

        flow_collection.close()
