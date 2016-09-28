# Rekall Memory Forensics
#
# Copyright 2016 Google Inc. All Rights Reserved.
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

"""Plugins to inspect flows."""

from rekall_agent import common
from rekall_agent import flow


class AgentControllerShowFlows(common.AbstractControllerCommand):
    name = "show_flows"

    table_header = [
        dict(name="state"),
        dict(name="flow_id"),
        dict(name="type"),
        dict(name="created"),
        dict(name="last_active"),
    ]

    def collect(self):
        collection = flow.FlowStatsCollection.from_keywords(
            session=self.session,
            location=self.config.server.flow_db_for_server(self.client_id))

        collection.open("r")
        ticket_locations = []
        for row in collection.query():
            flow_id = row["flow_id"]
            ticket_locations.append(
                self.config.server.ticket_for_server(
                    "FlowStatus", self.client_id, flow_id))

        # Collect the tickets for each flow.
        tickets = {}
        for ticket_data in common.THREADPOOL.imap_unordered(
                lambda x: x.read_file(), ticket_locations):
            status = flow.FlowStatus.from_json(
                ticket_data, session=self.session)
            tickets[status.flow_id] = status

        # Now show all the flows.
        for row in collection.query():
            flow_id = row["flow_id"]
            ticket = tickets.get(flow_id)
            if ticket:
                status = ticket.status
            else:
                status = "Pending"

            yield dict(state=status,
                       flow_id=flow_id,
                       type=row["type"],
                       created=row["created"])
