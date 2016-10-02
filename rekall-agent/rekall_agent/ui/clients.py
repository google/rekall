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
    ]

    table_header = [
        dict(name="Online"),
        dict(name="ID", cname="client_id"),
        dict(name="Host", cname="hostname"),
        dict(name="OS", cname="os"),
        dict(name="MAC"),
        dict(name="Usernames"),
        dict(name="First Seen", cname="first_time"),
        dict(name="Last Seen", cname="last_time"),
        dict(name="Labels"),
        dict(name="OS Install", cname="install_time"),
    ]

    table_options = dict(
        auto_widths=True
    )

    def collect(self):
        collection = interrogate.ClientStatisticsCollection.load_from_location(
            self.config.server.client_db_for_server(), session=self.session)

        query = "select * from tbl_default "
        condition = []
        condition_value = []

        if self.plugin_args.client_id:
            condition.append("client_id = ?")
            condition_value.append(self.plugin_args.client_id)

        if self.plugin_args.hostname:
            condition.append("fqdn like ?")
            condition_value.append("%" + self.plugin_args.hostname + "%")

        if condition:
            query += " where " + " and ".join(condition)

        for row in collection.query(query=query, query_args=condition_value):
            yield dict(client_id=row["client_id"],
                       hostname=row["fqdn"],
                       os="%s %s" % (row["system"], row["architecture"]),
                       last_time=basic.UnixTimeStamp(
                           session=self.session,
                           value=row["agent_start_time"])
            )
