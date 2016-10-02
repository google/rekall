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
import base64
import json

import arrow

from rekall import plugin
from rekall import utils

from rekall_agent import common
from rekall_agent import flow
from rekall_agent import serializer


class AgentControllerShowFlows(common.AbstractControllerCommand):
    name = "show_flows"

    __args = [
        dict(name="limit", type="IntParser", default=20,
             help="Total results to display"),
    ]

    table_header = [
        dict(name="state"),
        dict(name="flow_id"),
        dict(name="type"),
        dict(name="created"),
        dict(name="last_active"),
        dict(name="collections"),
    ]

    table_options = dict(
        auto_widths=True,
    )

    def collect_db(self, collection):
        # Now show all the flows.
        for i, row in enumerate(collection.query(order_by="created desc")):
            if i > self.plugin_args.limit:
                break

            ticket = flow.FlowStatus.from_json(
                row["ticket_data"], session=self.session)

            last_active = row["last_active"]
            if last_active:
                last_active = arrow.Arrow.fromtimestamp(last_active)

            collections = [x.location.get_canonical().to_path()
                           for x in ticket.collections]

            yield dict(state=row["status"],
                       flow_id=row["flow_id"],
                       type=row["type"],
                       created=arrow.Arrow.fromtimestamp(row["created"]),
                       last_active=last_active,
                       collections=collections)

    def collect(self):
        if not self.client_id:
            raise plugin.PluginError("Client ID must be specified.")

        collection = flow.FlowStatsCollection.load_from_location(
            self.config.server.flow_db_for_server(self.client_id),
            session=self.session)

        return self.collect_db(collection)


class AgentControllerShowHunts(AgentControllerShowFlows):
    name = "show_hunts"

    __args = [
        dict(name="queue", default="All",
             help="The hunt queue."),
    ]

    def collect(self):
        collection = flow.FlowStatsCollection.load_from_location(
            self.config.server.flow_db_for_server(queue=self.plugin_args.queue),
            session=self.session)

        return self.collect_db(collection)


class SerializedObjectInspectorMixin(object):
    """A plugin Mixin which inspects a SerializedObject."""

    __args = [
        dict(name="verbosity", type="IntParser", default=0,
             help="If non zero show all fields."),
    ]

    table_header = [
        dict(name="Field", type="TreeNode", max_depth=5, width=20),
        dict(name="Value", width=60),
        dict(name="Description")
    ]

    def _explain(self, flow_obj, depth=0, ignore_fields=None):
        for descriptor in flow_obj.get_descriptors():
            field = descriptor["name"]

            # Only show requested fields in non-verbose mode.
            if (not self.plugin_args.verbosity and
                ignore_fields and field in ignore_fields):
                continue

            if not flow_obj.HasMember(field):
                continue

            value = flow_obj.GetMember(field)

            if isinstance(value, str):
                value = base64.b64encode(value)

            display_value = utils.SmartUnicode(value)

            if (not self.plugin_args.verbosity and len(display_value) > 45):
                display_value = display_value[:45] + " ..."

            yield dict(
                Field=field,
                Value=display_value,
                Description=descriptor.get("doc", ""),
                highlight="important" if descriptor.get("user") else "",
                depth=depth)

            if (isinstance(value, serializer.SerializedObject)):
                for row in self._explain(value, depth=depth+1):
                    yield row

class InspectFlow(SerializedObjectInspectorMixin,
                  common.AbstractControllerCommand):
    name = "inspect_flow"

    __args = [
        dict(name="flow_id", required=True, positional=True,
             help="The flow to examine"),
    ]

    table_header = [
        dict(name="", cname="divider", type="Divider")
    ] + SerializedObjectInspectorMixin.table_header

    def _get_collection(self):
        if not self.client_id:
            raise plugin.PluginError("Client ID must be specified.")

        return flow.FlowStatsCollection.load_from_location(
            self.config.server.flow_db_for_server(self.client_id),
            session=self.session)

    def get_flow_object(self, flow_id=None):
        if flow_id is None:
            flow_id = self.plugin_args.flow_id

        collection = self._get_collection()
        for row in collection.query(flow_id=flow_id):
            flow_obj = flow.Flow.from_json(row["flow_data"],
                                           session=self.session)
            return flow_obj

    def collect(self):
        collection = self._get_collection()
        for row in collection.query(flow_id=self.plugin_args.flow_id):
            flow_obj = flow.Flow.from_json(row["flow_data"],
                                           session=self.session)

            yield dict(divider="Flow Object (%s)" % flow_obj.__class__.__name__)
            for x in self._explain(flow_obj, ignore_fields=set([
                    "ticket", "actions"
            ])):
                yield x

            ticket = flow.FlowStatus.from_json(row["ticket_data"],
                                               session=self.session)

            yield dict(divider="Flow Status Ticket")

            for x in self._explain(ticket, ignore_fields=set([
                    "location", "client_id", "flow_id", "collections"
            ])):
                yield x

            if ticket.collections:
                yield dict(divider="Collections")

                for collection in ticket.collections:
                    yield dict(
                        Field=collection.__class__.__name__,
                        Value=collection.location.get_canonical().to_path(),
                        Description="")

            if ticket.error:
                yield dict(divider="Error")
                yield dict(Field="ticket.error", Value=ticket.error)

            if ticket.backtrace:
                yield dict(divider="Backtrace")
                yield dict(Field="ticket.backtrace", Value=ticket.backtrace)



class AgentControllerRunFlow(SerializedObjectInspectorMixin,
                             common.AbstractControllerCommand):
    name = "launch_flow"

    __args = [
        dict(name="flow", type="Choices", positional=True, required=True,
             choices=utils.JITIteratorCallable(
                 utils.get_all_subclasses, flow.Flow),
             help="The flow to launch"),

        dict(name="args", type="Any", positional=True, default={},
             help="Arguments to the flow (use explain_flow to see valid args)."
             "This may also be a JSON encoded string"),

        dict(name="queue",
             help="Which queue to schedule the hunt on."),

        dict(name="condition",
             help="An EFilter query to evaluate if the flow should be run."),
    ]

    def make_flow_object(self):
        flow_cls = flow.Flow.ImplementationByClass(self.plugin_args.flow)
        if not flow_cls:
            raise plugin.PluginError("Unknown flow %s" % self.plugin_args.flow)

        args = self.plugin_args.args
        if isinstance(args, basestring):
            try:
                args = json.loads(args)
            except Exception as e:
                raise plugin.PluginError(
                    "args should be a JSON string of a dict: %s" % e)

        if not isinstance(args, dict):
            raise plugin.PluginError("args should be a dict")

        flow_obj = flow_cls.from_primitive(
            args, session=self.session)

        flow_obj.client_id = self.client_id
        flow_obj.queue = self.plugin_args.queue

        return flow_obj

    def collect(self):
        # Now launch the flow.
        flow_obj = self.make_flow_object()
        flow_obj.start()

        for x in self._explain(flow_obj):
            yield x


CANNED_CONDITIONS = dict(
    OS_WINDOWS="any from agent_info() where key=='system' and value=='Windows'",
    OS_LINUX="any from agent_info() where key=='system' and value=='Linux'",
    OS_OSX="any from agent_info() where key=='system' and value=='Darwin'",
)


class AgentControllerRunHunt(AgentControllerRunFlow):
    """Launch a hunt on many clients at once.

    Rekall does not treat hunts as different or special entities - a hunt is
    just a flow which targets multiple systems. However, for users it is
    sometimes helpful to think in terms of a "hunt". This plugin makes it easier
    to launch the hunt.
    """
    name = "launch_hunt"

    __args = [
        # Flows are scheduled on the client's flow queue but hunts are generally
        # scheduled on a Label Queue (e.g. the All queue schedules to all
        # agents).
        dict(name="queue", default="All",
             help="Which queue to schedule the hunt on."),

        # This should only be set if no condition is specified.
        dict(name="canned_condition", type="Choices", default=None,
             choices=CANNED_CONDITIONS,
             help="Canned conditions for the hunt."),
    ]

    def make_flow_object(self):
        # Hunts run on all clients.
        self.client_id = None

        # If a canned condition was specified automatically add it.
        if self.plugin_args.canned_condition:
            self.plugin_args.condition = CANNED_CONDITIONS[
                self.plugin_args.canned_condition]

        flow_obj = super(AgentControllerRunHunt, self).make_flow_object()

        return flow_obj

    def collect(self):
        # Now launch the flow.
        flow_obj = self.make_flow_object()
        flow_obj.start_hunt(self.plugin_args.queue)

        for x in self._explain(flow_obj):
            yield x


class AgentControllerExplainFlows(common.AbstractControllerCommand):
    """Explain all the parameters a flow may take."""
    name = "explain_flow"

    __args = [
        dict(name="flow", type="Choices", positional=True, required=True,
             choices=utils.JITIteratorCallable(
                 utils.get_all_subclasses, flow.Flow),
             help="The flow to explain"),

        dict(name="verbosity", type="IntParser", default=0,
             help="If non zero show all fields."),

        dict(name="recursive", type="Bool",
             help="Show recursively nested fields."),
    ]

    table_header = [
        dict(name="Field", type="TreeNode", max_depth=5),
        dict(name="Type"),
        dict(name="Description")
    ]

    table_options = dict(
        auto_widths=True,
    )

    def _explain(self, flow_cls, depth=0):
        for descriptor in flow_cls.get_descriptors():
            user_accessible = descriptor.get("user")
            if self.plugin_args.verbosity < 1 and not user_accessible:
                continue

            field = descriptor["name"]
            field_type = descriptor.get("type", "string")

            field_description = field_type
            if isinstance(field_type, type):
                field_description = "(%s)" % field_type.__name__

            yield dict(Field=field,
                       Type=field_description,
                       Description=descriptor.get("doc", ""),
                       depth=depth)

            if (self.plugin_args.recursive and
                isinstance(field_type, type) and
                issubclass(field_type, serializer.SerializedObject)):
                for row in self._explain(field_type, depth=depth+1):
                    #row["Field"] = "%s.%s" % (field, row["Field"])
                    yield row

    def collect(self):
        flow_cls = flow.Flow.ImplementationByClass(self.plugin_args.flow)
        for x in self._explain(flow_cls):
            yield x
