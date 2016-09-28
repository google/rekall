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

"""A Files based policy.

This uses local files on the same system to run the client/server. It can not be
used across different systems but it is a nice way to test local installations.

Main policy:
 - The jobs queues are implemented as files in the following directory:
      {root_path}/{client_id}/jobs


"""

import os

from rekall_agent.config import agent
from rekall_agent.locations import files


class FileBasedServerPolicy(agent.ServerPolicy):
    """This server deployment policy is centered around files.

    It can only work locally on the same machine since this produces Location
    objects that refer to the local filesystem. It is sufficient, however, to
    test the system end to end.
    """

    schema = [
        dict(name="root_path",
             doc="The root path we use to store the entire installation.")
    ]

    def jobs_queue_for_client(self, client_id):
        """Returns a Location for the client's job queue."""
        return files.FileLocation.from_keywords(
            session=self._session, path=os.path.join(
                self.root_path, client_id, "jobs"))

    def get_client_vfs_path(self, client_id, path):
        """Returns a Location for storing the path in the client's VFS area."""
        return files.FileLocation.from_keywords(
            session=self._session, path=os.path.join(
                self.root_path, client_id, "vfs", path.lstrip(os.path.sep)))

    def get_client_vfs_prefix(self, client_id, path):
        """Returns a Location suitable for storing a path using the prefix."""
        return files.FileLocation.from_keywords(
            session=self._session, path=os.path.join(
                self.root_path, client_id, "vfs", path.lstrip(os.path.sep)))

    def get_ticket_location(self, client_id, flow_id):
        """Returns a Location for the client to write flow tickets.

        When we issue requests to the client, we need to allow the client to
        report progress about the progress of the flow requests running on the
        client. We do this by instructing the client to write a "Flow Ticket" to
        the ticket location.
        """
        return files.FileLocation.from_keywords(
            session=self._session, path=os.path.join(
                self.root_path, client_id, "flows",
                flow_id + "." + "ticket"))

    def get_flow_metadata_collection(self, client_id):
        return files.FileLocation.from_keywords(
            session=self._session, path=os.path.join(
                self.root_path, client_id, "flows.sqlite"))


class FileBasedAgentPolicy(agent.ClientPolicy):
    """A policy controller for a simple file based agent."""

    schema = [
        dict(name="root_path",
             doc="The root path for the entire installation."),
    ]

    def get_jobs_queue(self):
        """Returns a Location object for reading the jobs queue."""
        return files.FileLocation.from_keywords(
            session=self._session, path=os.path.join(
                self.root_path, self.client_id, "jobs"))
