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
import time
import psutil

from rekall_agent import action
from rekall_agent import crypto
from rekall_agent import result_collections
from rekall_agent import serializer
from rekall_agent.messages import agent
from rekall_agent.messages import batch


# Time the agent was first started.
START_TIME = time.time()


class RekallClient(serializer.SerializedObject):
    """Client information."""
    schema = [
        dict(name="client_id"),
        dict(name="public_key", type=crypto.RSAPublicKey,
             doc="The client's public key"),
        dict(name="system_info", type=agent.Uname),
    ]


class ClientStatisticsCollection(result_collections.GenericSQLiteCollection):
    """Keeps statistics about all clients."""
    _tables = [dict(
        name="default",
        columns=[
            dict(name="client_id"),
            dict(name="fqdn"),
            dict(name="system"),
            dict(name="architecture"),
            dict(name="boot_time"),
            dict(name="agent_start_time"),
        ]
    )]


class Startup(batch.BatchTicket):
    """A message sent to the startup location.

    This message contains important information about the client.
    """
    schema = [
        dict(name="client_id"),

        dict(name="client_info", type=agent.ClientInformation,
             doc="Information about the client agent itself."),

        dict(name="boot_time", type="epoch",
             doc="Time the system booted last."),

        dict(name="agent_start_time", type="epoch",
             doc="Time the agent started."),

        dict(name="timestamp", type="epoch",
             doc="The timestamp this message was created."),

        dict(name="system_info", type=agent.Uname,
             doc="Information about the running system"),

        dict(name="public_key", type=crypto.RSAPublicKey,
             doc="The public key of the client."),
    ]

    @classmethod
    def begin(cls, context, session=None):
        """Get the global client metadata collection."""
        context["messages"] = []

    @classmethod
    def end(cls, context, session=None):
        config = session.GetParameter("agent_config_obj")

        def _update_client_records(collection, messages):
            for message in messages:
                collection.delete(client_id=message["client_id"])
                collection.insert(**message)

        # Modify the collection atomically.
        ClientStatisticsCollection.transaction(
            config.server.client_db_for_server(),
            _update_client_records, context["messages"],
            session=session)

    def process(self, context, ticket_location):
        """This method runs once on each ticket.

        Note that this method runs inside a threadpool.
        """
        components = ticket_location.to_path().split("/")

        # Ensure the ticket location matches the ticket content.
        if (components[-2] != self.client_id or
            components[-3] != self.__class__.__name__):
            raise IOError("Ticket location unexpected.")

        # Verify the client id and public key match.
        if self.public_key.client_id() != self.client_id:
            raise crypto.CipherError("Public key incompatible with client_id")

        # Update the client's record by deleting the old one and inserting a new
        # one.
        context["messages"].append(
            dict(client_id=self.client_id,
                 fqdn=self.system_info.fqdn,
                 system=self.system_info.system,
                 architecture=self.system_info.architecture,
                 boot_time=self.boot_time,
                 agent_start_time=self.agent_start_time,
             )
        )

        # Modify the client record atomically.
        self._config.server.client_record_for_server(
            self.client_id).read_modify_write(self._update_client_record)

    def _update_client_record(self, json_data):
        record = RekallClient.from_json(json_data or "{}",
                                        session=self._session)
        record.client_id = self.client_id
        record.public_key = self.public_key
        record.system_info = self.system_info

        return record.to_json()


class StartupAction(action.Action):
    """The startup message.

    When the client starts up it sends a message to the client containing vital
    information about itself. This allows the client to self enroll without any
    server action at all. The workflow is:

    1) The client reads the deployment manifest file. The manifest is validated.

    2) The manifest file contains a list of JobRequests including the startup
       action. This JobRequest contains a Location for storing the
       StartupMessageBatch() message.

    2) The client prepares and populates a StartupMessageBatch() message.

    3) The client writes the StartupMessageBatch() message to its specified
       Location.

    4) The client proceeds to poll for its jobs queue. The client is now
       enrolled.

    In the server an EnrollerBatch runs collecting the StartupMessage messages
    and updating the relevant ClientInformation() objects at the client's VFS
    path.

    Using this information the client may be tasked with new flows.

    This enrollment scheme has several benefits:

    1) It does not depend on server load. Clients are enrolled immediately and
       do not need to wait for the server to do anything.

    2) The interrogate step is done at once at startup time every time. The
       system therefore has a fresh view of all clients all the time. Unlike GRR
       which runs the interrogate flow weekly it is not necessary to wait for an
       interrogation in order to view fresh client information.

    3) We can handle a huge influx of enrollment messages with minimal server
       resources. While agents are immediately enrolled, the rate at which
       clients can be tasked depends only on the rate at which the
       EnrollerBatch() can process through them.

    This is important when the system is first deployed because at that time all
    the new clients will be attempting to communicate at the same time.

    """

    schema = [
        dict(name="startup_message", type=Startup,
             doc="The batch job that will be launched with the results."),
    ]

    def enroll(self):
        """Generate a new client_id.

        This runs only if the agent does not know its client_id.
        """
        private_key = crypto.RSAPrivateKey(session=self._session).generate_key()
        self._config.client.writeback.private_key = private_key

        client_id = private_key.public_key().client_id()
        self._config.client.writeback.client_id = client_id

        self._session.logging.info("Creating a new client_id %s", client_id)
        self._config.client.save_writeback()

    def run(self, flow_obj=None):
        if not self.is_active():
            return []

        if not self._config.client.writeback.client_id:
            self.enroll()

        self.startup_message.update(
            client_id=self._config.client.writeback.client_id,
            boot_time=psutil.boot_time(),
            agent_start_time=START_TIME,
            timestamp=time.time(),
            system_info=agent.Uname.from_current_system(session=self._session),
            public_key=self._config.client.writeback.private_key.public_key(),
        )

        self.startup_message.send_message()
