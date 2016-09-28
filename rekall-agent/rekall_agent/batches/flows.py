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

"""This batch job processes flow launch tickets.

We maintain flow statistics based on the tickets..
"""
from rekall_agent import batch
from rekall_agent import flow
from rekall_agent import result_collections


class FlowStatsCollection(result_collections.GenericSQLiteCollection):
    """A summary of all flows in this client."""
    _tables = [
        # Table describes the high level flow information.
        dict(name="default",
             columns=[
                 dict(name="id", type="unicode"),
                 dict(name="name", type="unicode"),
                 dict(name="created", type="epoch"),
                 dict(name="creator", type="unicode"),
             ]),

        # Table describes execution of each job.
        dict(name="status",
             columns=[
                 dict(name="id", type="unicode"),
                 dict(name="request_id", type="int"),
                 dict(name="state", type="unicode"),
                 dict(name="error", type="unicode"),
                 dict(name="backtrace", type="unicode"),
                 dict(name="start", type="epoch"),
                 dict(name="end", type="epoch"),
             ]),
    ]


class FlowProcessorBatch(batch.AbstractBatch):
    """Process Flow tickets.

    The intention of this flow is to maintain a long term index of the flows run
    on a specific client. We maintain a collection of high level information
    about flows.

    This is useful for the view_flows plugin.
    """

    name = "batch_FlowProcessorBatch"

    #batch_args_cls = flow.FlowProcessorBatch

    def postprocess_flow(self, client_id, flow_id):
        flow_location = self.config.server.flows_for_server(client_id, flow_id)
        flow_info = flow.FlowInformation.from_json(
            flow_location.read_file(), session=self.session)
        flow_info.args.postprocess()

    def _process_tickets_for_client(self, client_id, tickets):
        flow_collection = FlowStatsCollection.from_keywords(
            session=self.session,
            location=self.config.server.flow_metadata_collection_for_server(
                client_id)
        )

        # Write the summaries into the collection.
        flow_collection.open("a")
        for ticket in tickets:
            # This is a Job Ticket
            if isinstance(ticket, flow.FlowProcessorBatchJobTicketArgs):
                flow_collection.insert(
                    table="status",
                    id=ticket.flow_id,
                    request_id=ticket.request_id,
                    state=ticket.state,
                    error=ticket.error,
                    backtrace=ticket.backtrace,
                    start=ticket.start,
                    end=ticket.end)

                # The entire flow is complete, launch any post processing
                # required.
                if ticket.final:
                    self.postprocess_flow(client_id, ticket.flow_id)

            else:
                flow_collection.insert(
                    table="default",
                    name=ticket.information.flow_name,
                    id=ticket.information.flow_id,
                    created=ticket.information.created_time,
                    creator=ticket.information.creator)

        flow_collection.close()

    def process(self, tickets):
        groups = {}
        for ticket in tickets:
            groups.setdefault(ticket.client_id, []).append(ticket)

        for client_id, group in groups.iteritems():
            self._process_tickets_for_client(client_id, group)
            yield dict(message="Processed %s for client %s" % (
                len(group), client_id))
