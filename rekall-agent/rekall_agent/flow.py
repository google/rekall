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

"""Flows are collections of client actions.
Scheduling a Flow
=================

The controller starts by creating a Flow object. The flow object has the
following important parts:

1) An optional condition: will be evaluated by the client prior to executing the
   flow.

2) A list of Action() objects. The client will execute each of these in turn.

3) A FlowStatus ticket: The client will save a status message prior to running
   each action.

Once the flow message is created, the controller will queue it on one of the
queues. Regular flows are queued in a specific client queue but hunts are queued
on one of the general hunt queues.

After queuing the flow message into a jobs file, the controller will update the
client's flow database.

Running the Flow
================

The client agent checks one of its jobs queues for flow messages. When it
discovers a new message it:

1) Evaluates the efilter condition if present. Flows which do not satisfy the
   condition will be ignored.

2) If the condition evaluates, the client will write a FlowStatus ticket with a
   "Pending" status prior to running each of the actions specified in the flow.

3) Once the actions are all finished, the FlowStatus is marked with a status of
   "Done" or "Error" depending on the final outcome. This completes the flow's
   processing by the client, which will ignore this flow from now on.


Batch processing
================

FlowStatus messages maintain the current state of each flow. The FlowStatus
batch updates the client's flow collection to reflect the latest view of flow's
activities.

"""
import os
import time

from rekall import plugin

from rekall_agent import action
from rekall_agent import common
from rekall_agent import location
from rekall_agent import result_collections
from rekall_agent import output_plugin
from rekall_agent import serializer
from rekall_agent.config import agent
from rekall_agent.messages import batch
from rekall_agent.messages import resources


class FlowStatus(batch.BatchTicket):
    """Information about flow's progress.

    As the agent works through the flow, this ticket will be updated with status
    information.
    """

    schema = [
        dict(name="client_id"),

        dict(name="flow_id"),

        dict(name="timestamp", type="epoch"),

        dict(name="quota", type=resources.Quota,
             doc="The total resources used until now."),

        dict(name="logs", repeated=True,
             doc="Log lines from the client."),

        dict(name="status", type="choices",
             choices=["Pending", "Started", "Done", "Error", "Crash"]),

        dict(name="error",
             doc="If an error occurred, here will be the error message."),

        dict(name="backtrace",
             doc="If an error occurred, here will be the backtrace."),

        dict(name="current_action", type=action.Action,
             doc="The currently running client action."),

        dict(name="collections", type=result_collections.CollectionSpec,
             repeated=True,
             doc="The collections produced by the flow."),

        dict(name="files", type=location.Location, repeated=True, hidden=True,
             doc="The list of files uploaded."),
    ]

    def process(self, context, ticket_location):
        # Verify this ticket. We only process valid tickets that came from a
        # valid location. Note that since the location is generally signed this
        # ensure the ticket is written to the location the server decided in
        # advance. We ignore invalid messages and they will be deleted.
        components = ticket_location.to_path().split("/")
        # Example of valid URL:
        # /bucket/tickets/FlowStatus/F_4f47d99ead/C.4dd70be22bc56fc3/Z021
        if (components[-2] != self.client_id or
            components[-3] != self.flow_id or
            components[-4] != self.__class__.__name__):
            raise IOError("Ticket location unexpected.")

        # Just group by client id. We do all the real work in the end() method.
        context.setdefault(self.client_id, []).append(self)

    @classmethod
    def end(cls, context, session=None):
        config = session.GetParameter("agent_config_obj")

        # Read all the flow objects for the tickets at once before we take the
        # lock.
        flow_ids = []
        for _, tickets in context.iteritems():
            flow_ids.extend([t.flow_id for t in tickets])

        flows = {}
        for flow_data in common.THREADPOOL.map(
                lambda f: config.server.flows_for_server(f).read_file(),
                set(flow_ids)):
            flow_obj = Flow.from_json(flow_data, session=session)
            flows[flow_obj.flow_id] = flow_obj

        # Each client's flow collection can be modified on its own
        # independently.
        common.THREADPOOL.map(
            cls._process_flows,
            [(tickets, client_id, session, flows)
             for client_id, tickets in context.iteritems()])

    @staticmethod
    def _process_flows(_args):
        tickets, client_id, session, flows = _args
        config = session.GetParameter("agent_config_obj")

        def _update_flow_info(flow_collection, tickets):
            """Update the collection atomically."""
            # Process all tickets for all flows in the same client.
            for ticket in tickets:
                flow_id = ticket.flow_id

                flow_collection.replace(
                    condition=dict(flow_id=flow_id),
                    status=ticket.status, ticket_data=ticket.to_json(),
                    last_active=ticket.timestamp,
                )

                flow_obj = flows.get(flow_id)
                flow_obj.post_process([ticket])

        FlowStatsCollection.transaction(
            config.server.flow_db_for_server(client_id),
            _update_flow_info, tickets, session=session)


class HuntStatus(FlowStatus):
    def process(self, context, ticket_location):
        components = ticket_location.to_path().split("/")
        if (components[-2] != self.client_id or
            components[-3] != self.flow_id or
            components[-4] != self.__class__.__name__):
            raise IOError("Ticket location unexpected.")

        # Just group by flow id. We do all the real work in the end() method.
        context.setdefault(self.flow_id, []).append(self)

    @staticmethod
    def _process_flows(_args):
        tickets, flow_id, session, flows = _args
        config = session.GetParameter("agent_config_obj")

        def _update_flow_info(flow_collection, tickets):
            """Update the collection atomically."""
            # Process all tickets in the same hunt (flow_id) from different
            # clients.
            for ticket in tickets:
                # We only care about clients which are done.
                if ticket.status in ["Done", "Error"]:
                    flow_collection.insert(
                        client_id=ticket.client_id,
                        status=ticket.status,
                        executed=ticket.timestamp,
                        ticket_data=ticket.to_json(),
                    )

            flow_obj = flows.get(flow_id)
            flow_obj.post_process(tickets)

        HuntStatsCollection.transaction(
            config.server.hunt_db_for_server(flow_id),
            _update_flow_info, tickets, session=session)


class Flow(common.AgentConfigMixin, serializer.SerializedObject):
    """A Flow is a sequence of client actions.

    To launch a flow simply build a Flow object and call its start() method.
    """
    schema = [
        dict(name="client_id",
             doc="A client id to target this flow on."),

        dict(name="queue",
             doc="A queue to launch this one. When specified this flow is "
             "run as a hunt."),

        dict(name="flow_id",
             doc="Unique ID of this flow, will be populated when launched."),

        dict(name="condition",
             doc="An EFilter query to evaluate if the flow should be run."),

        dict(name="created_time", type="epoch",
             doc="When the flow was created."),

        dict(name="creator", private=True,
             doc="The user that created this flow."),

        dict(name="ttl", type="int", default=60*60*24,
             doc="How long should this flow remain active."),

        dict(name="ticket", type=FlowStatus,
             doc="Ticket keeping the state of this flow."),

        dict(name="actions", type=action.Action, repeated=True,
             doc="The action requests sent to the client."),

        dict(name="output_plugins", type=output_plugin.OutputPlugin,
             repeated=True, private=True,
             doc="A list of output plugins to post process the results."),

        dict(name="session", type=agent.RekallSession,
             doc="The session that will be invoked for this flow."),

        dict(name="quota", type=resources.Quota,
             doc="The total resources the flow is allows to use."),
    ]

    def is_hunt(self):
        """Is this flow running as a hunt?"""
        return self.queue

    def generate_actions(self):
        """Yields one or more Action() objects.

        Should be overridden by derived classes.
        """
        return []

    def validate(self):
        # pylint: disable=access-member-before-definition
        if not self.client_id:
            self.client_id = self._session.GetParameter(
                "controller_context") or None

        if not self.client_id and not self.queue:
            raise plugin.InvalidArgs(
                "Hunt Queue name must be provided if client id is "
                "not provided.")

    def start(self):
        """Launch the flow."""
        self.validate()

        # There are some differences in the ways flows and hunts are organized.
        if self.is_hunt():
            self.ticket = HuntStatus(session=self._session)
            self.flow_id = "H_%s" % os.urandom(5).encode("hex")

        else:
            self.ticket = FlowStatus(session=self._session)
            self.flow_id = "F_%s" % os.urandom(5).encode("hex")

        # Make a random flow id.
        self.created_time = time.time()
        self.actions = list(self.generate_actions())

        # Create a ticket location for the agent to report progress.
        self.ticket.client_id = self.client_id
        self.ticket.status = "Started"
        self.ticket.flow_id = self.flow_id
        self.ticket.quota = self.quota

        self.ticket.location = self._config.server.flow_ticket_for_client(
            self.ticket.__class__.__name__,
            self.flow_id, path_template="{client_id}",
            expiration=time.time() + self.ttl)

        def _add_flow(flow_collection):
            flow_collection.insert(
                status="Pending",
                type=self.__class__.__name__,
                created=self.created_time,
                flow_id=self.flow_id)

            # Add the new flow to the jobs file.
            jobs_location = self._config.server.jobs_queue_for_server(
                client_id=self.client_id, queue=self.queue)

            # Note this happens under lock so we should be able to handle
            # concurrent access.
            jobs_location.read_modify_write(
                self._add_flow_to_jobs_file, flow_collection)

        FlowStatsCollection.transaction(
            self._config.server.flow_db_for_server(self.client_id, self.queue),
            _add_flow, session=self._session)

        # Store this flow object in the centralized flow id location.
        self._config.server.flows_for_server(self.flow_id).write_file(
            self.to_json())

    def expiration(self):
        return time.time() + self.ttl

    def _add_flow_to_jobs_file(self, jobs_file_content, flow_collection):
        """Safely add flow to the jobs file.

        This also trims the jobs file to remove all flows which have been
        completed.
        """
        try:
            jobs_file = JobFile.from_json(
                jobs_file_content, session=self._session)
        except Exception:
            # Something went wrong reading the old jobs. This can happen if the
            # jobs format has changed since they were last written, so they no
            # longer validate. Just start again with fresh jobs.
            jobs_file = JobFile(session=self._session)

        # Remove those flows which are done.
        filtered_flows = []
        for flow_obj in jobs_file.flows:
            # If the status in the flow database is "Pending" we need to keep
            # the flow in the jobs file.
            if flow_collection.query(
                    "select * from tbl_default where status = 'Pending'"):
                filtered_flows.append(flow_obj)

        # Make sure the flows are sorted by create time.
        filtered_flows.sort(key=lambda x: x.created_time)

        jobs_file.flows = filtered_flows

        # Add ourselves to the jobs file.
        new_job = self.copy()

        # Clear all private fields - these should never be transmitted to the
        # client.
        for field_desc in new_job.get_descriptors():
            if field_desc.get("private"):
                new_job.SetMember(field_desc["name"], None)

        jobs_file.flows.append(new_job)

        return jobs_file.to_json()

    def post_process(self, tickets):
        """Post process this flow's tickets.

        When a flow ticket is received the flow receives the ticket with this
        method. Flows that wish to do something with the ticket can override
        this method.
        """
        for output_plugin_obj in self.output_plugins:
            output_plugin_obj.post_process(self, tickets)


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
    """This collection maintains high level information about flows.

    The collection exists either in the client's namespace (where it describes
    flows targetted to the client) or in the label namespace (where it describes
    all hunts run on the label).

    e.g.
    bucket/C.123354/flows.sqlite   <---- client's flow database.
    bucket/labels/All/flows.sqlite <----- Describes all flows targetted at this
       label (otherwise known as hunts).
    """
    _tables = [dict(
        name="default",
        columns=[
            dict(name="type"),
            dict(name="status"),
            dict(name="created", type="epoch"),
            dict(name="last_active", type="epoch"),
            dict(name="flow_id"),
            dict(name="ticket_data"),
        ]
    )]


class HuntStatsCollection(result_collections.GenericSQLiteCollection):
    """Maintain high level information about the hunt."""

    _tables = [
        dict(
            name="default",
            columns=[
                dict(name="client_id"),
                dict(name="status"),
                dict(name="executed", type="epoch"),
                dict(name="ticket_data"),
            ]
        )]
