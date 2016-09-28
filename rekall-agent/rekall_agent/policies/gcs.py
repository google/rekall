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

"""A Google Cloud Storage based policy.

Google Cloud Storage offers the ability to store files in buckets. Since Rekall
Agent is file based, this is a perfect fit.

Before you can use this policy you will need to create a bucket and a service
account:

1. In the Google Cloud Platform console, select Storage, Create Bucket and
   select a name for the bucket.

2. In the IAM & Admin screen select "Service Accounts" and "Create Service
   Account"

3. The service account credentials can be downloaded as a json file. Place the
   json file in some location (e.g. ~/.rekall_agent_service_account)

4. Initialize your configuration. This will generate keys and create the
manifest file and upload it into the bucket:

$ rekal agent_server_initialize_gcs /path/to/config/
  --service_account_path  ~/.rekall_agent_service_account  \
  --bucket name_of_bucket \
  --client_writeback_path /etc/rekall.agent.writeback

Main policy:
 - The jobs queues are implemented as files in the following directory:
      {root_path}/{client_id}/jobs

"""

from rekall_agent.config import agent
from rekall_agent.locations import cloud


class GCSServerPolicy(agent.ServerPolicy):

    schema = [
        dict(name="bucket",
             doc="The name of the bucket"),

        dict(name="ticket_bucket",
             doc="The bucket used for publishing tickets."),

        dict(name="service_account", type=cloud.ServiceAccount,
             doc="Service account credentials for cloud deployments."),
    ]

    # The following convention hold:
    # If the method returns a Location to be used in server code it ends with
    # "for_server". Otherwise it ends with "for_client" to be passed to the
    # client's use.

    def jobs_queue_for_server(self, client_id):
        """Returns a Location for the client's job queue.

        Used by the server to manipulate the client's job queue.
        """
        # The client's jobs queue itself is publicly readable since the client
        # itself has no credentials.
        return self.service_account.create_oauth_location(
            bucket=self.bucket, path="/".join((client_id, "jobs")),
            public=True)

    def client_db_for_server(self):
        """The global client database."""
        return self.service_account.create_oauth_location(
            bucket=self.bucket, path="clients.sqlite")

    def flow_db_for_server(self, client_id):
        return self.service_account.create_oauth_location(
            bucket=self.bucket, path=client_id + "/flows.sqlite")

    def client_record_for_server(self, client_id):
        """The client specific information."""
        return self.service_account.create_oauth_location(
            bucket=self.bucket, path="%s/client.metadata" % client_id)

    def flows_for_server(self, client_id, flow_id):
        """A location to write flow objects."""
        return self.service_account.create_oauth_location(
            bucket=self.bucket, path="/".join(
                (client_id, "flows", flow_id)))

    def ticket_for_server(self, batch_name, *args):
        """The location of the ticket queue for this batch."""
        return self.service_account.create_oauth_location(
            bucket=self.bucket, path="/".join(
                ("tickets", batch_name) + args))

    def vfs_path_for_client(self, client_id, path, mode="w", expiration=None,
                            vfs_type="analysis"):
        """Returns a Location for storing the path in the client's VFS area.

        Passed to the agent to write on client VFS.
        """
        return self.service_account.create_signed_url_location(
            bucket=self.bucket, mode=mode, path="/".join(
                (client_id, "vfs", vfs_type, path.lstrip("/"))),
            expiration=expiration)

    def vfs_prefix_for_client(self, client_id, path="", expiration=None,
                              vfs_type="files"):
        """Returns a Location suitable for storing a path using the prefix."""
        return self.service_account.create_signed_policy_location(
            bucket=self.bucket, path_prefix="/".join(
                (client_id, "vfs", vfs_type, path.lstrip("/"))),
            expiration=expiration)

    def flow_ticket_for_client(self, batch_name, *ticket_names, **kw):
        """Returns a Location for the client to write tickets.

        When we issue requests to the client, we need to allow the client to
        report progress about the progress of the flow requests running on the
        client. We do this by instructing the client to write a "Flow Ticket" to
        the ticket location.
        """
        expiration = kw.pop("expiration", None)
        path_template = kw.pop("path_template", None)
        return self.service_account.create_signed_policy_location(
            bucket=self.bucket,
            path_prefix="/".join(("tickets", batch_name) + ticket_names),
            path_template=path_template,
            expiration=expiration)

    def flow_metadata_collection_for_server(self, client_id):
        if not client_id:
            raise RuntimeError("client id expected")
        return self.service_account.create_oauth_location(
            bucket=self.bucket, path="/".join(
                (client_id, "flows.sqlite")
            ))


class GCSAgentPolicy(agent.ClientPolicy):
    """A policy controller for a simple file based agent."""

    def get_jobs_queues(self):
        """Returns a list of Location object for reading the jobs queue.

        A client can track a set of queues at the same time depending on the
        policy.

        In this implementation we track the client's individual jobs queue as
        well as a job queue for each client label. This allows very efficient
        hunting because writing a single job request in a label queue will run
        on all clients in that label.
        """
        # The jobs queue is world readable.
        result = [
            cloud.GCSUnauthenticatedLocation.from_keywords(
                session=self._session, bucket=self.manifest_location.bucket,
                path="/".join([self.client_id, "jobs"]))
        ]

        for label in self.labels:
            result.append(
                cloud.GCSUnauthenticatedLocation.from_keywords(
                    session=self._session, bucket=self.manifest_location.bucket,
                    path="/".join(["labels", label, "jobs"]))
            )

        return result
