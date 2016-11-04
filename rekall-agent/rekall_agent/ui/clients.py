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

"""Search for clients."""

from rekall.plugins.overlays import basic
from rekall_agent import common
from rekall_agent.client_actions import interrogate


class SearchClients(common.AbstractControllerCommand):
    name = "show_clients"

    __args = [
        dict(name="client_id", positional=True, required=False,
             help="Exact match on client id"),

        dict(name="hostname",
             help="Partial match on hostname"),

        dict(name="limit", type="IntParser", default=20,
             help="Number of rows to show."),
    ]

    table_header = [
        dict(name="Online"),
        dict(name="client_id"),
        dict(name="hostname"),
        dict(name="os"),
        dict(name="MAC"),
        dict(name="Usernames"),
        dict(name="first_time"),
        dict(name="last_time"),
        dict(name="Labels"),
        dict(name="install_time"),
    ]

    table_options = dict(
        auto_widths=True
    )

    def collect(self):
        with interrogate.ClientStatisticsCollection.load_from_location(
                self._config.server.client_db_for_server(),
                session=self.session) as collection:

            conditions = {}
            if self.plugin_args.client_id:
                conditions["client_id"] = self.plugin_args.client_id

            if self.plugin_args.hostname:
                conditions["fqdn like ?"] = (
                    "%" + self.plugin_args.hostname + "%")

            for row in collection.query(
                    limit=self.plugin_args.limit, **conditions):
                yield dict(client_id=row["client_id"],
                           hostname=row["fqdn"],
                           os="%s %s" % (row["system"], row["architecture"]),
                           last_time=basic.UnixTimeStamp(
                               session=self.session,
                               value=row["agent_start_time"])
                )
