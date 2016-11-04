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
import os
import time

import arrow

from rekall import plugin
from rekall import utils

from rekall_agent import common
from rekall_agent import flow
from rekall_agent import result_collections
from rekall_agent import serializer
from rekall_agent.locations import files
from rekall_agent.ui import renderers


CANNED_CONDITIONS = dict(
    OS_WINDOWS="any from agent_info() where key=='system' and value=='Windows'",
    OS_LINUX="any from agent_info() where key=='system' and value=='Linux'",
    OS_OSX="any from agent_info() where key=='system' and value=='Darwin'",
)


class AgentControllerShowFlows(common.AbstractControllerCommand):
    name = "show_flows"

    __args = [
        dict(name="limit", type="IntParser", default=20,
             help="Total results to display"),
    ]

    table_header = [
        dict(name="state", width=8),
        dict(name="flow_id", width=14),
        dict(name="type", width=18),
        dict(name="created", width=19),
        dict(name="last_active", width=19),
        dict(name="collections"),
    ]

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

    def _check_pending_flow(self, row):
        """Check for flow tickets.

        For pending flows, it is possible that the worker just has not caught
        up. We try to show it anyway by checking for the tickets.
        """
        if row["state"] == "Pending":
            ticket_location = self._config.server.ticket_for_server(
                "FlowStatus", row["flow_id"], self.client_id)

            # The client will actually add a nonce to this so we need to find
            # all subobjects.
            for sub_object in ticket_location.list_files():
                # The subobject is a canonical path, we need to authorize it.
                data = self._config.server.canonical_for_server(
                    sub_object.location).read_file()
                if data:
                    ticket = flow.FlowStatus.from_json(
                        data, session=self.session)
                    row["state"] = "%s(*)" % ticket.status
                    row["collections"] = [sub_object.location.to_path()]
                    row["last_active"] = ticket.timestamp

    def collect(self):
        if not self.client_id:
            raise plugin.PluginError("Client ID must be specified.")

        with flow.FlowStatsCollection.load_from_location(
                self._config.server.flow_db_for_server(self.client_id),
                session=self.session) as collection:
            rows = list(self.collect_db(collection))
            common.THREADPOOL.map(self._check_pending_flow, rows)
            for row in rows:
                row["collections"] = [
                    renderers.UILink("gs", x) for x in row["collections"]]
                row["flow_id"] = renderers.UILink("f", row["flow_id"])
                yield row


class AgentControllerShowHunts(AgentControllerShowFlows):
    name = "show_hunts"

    __args = [
        dict(name="queue", default="All",
             help="The hunt queue."),
    ]

    def collect(self):
        with flow.FlowStatsCollection.load_from_location(
                self._config.server.flow_db_for_server(
                    queue=self.plugin_args.queue),
                session=self.session) as collection:
            for row in self.collect_db(collection):
                row["flow_id"] = renderers.UILink("h", row["flow_id"])
                yield row


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

    def _explain(self, obj, depth=0, ignore_fields=None):
        if isinstance(obj, serializer.SerializedObject):
            for x in self._collect_serialized_object(
                    obj, depth=depth, ignore_fields=ignore_fields):
                yield x

        elif isinstance(obj, basestring):
            yield dict(Value=obj)

        elif isinstance(obj, list):
            yield dict(Value=", ".join(obj))

        else:
            raise RuntimeError("Unable to render object %r" % obj)

    def _collect_list(self, list_obj, field, descriptor, depth):
        yield dict(
            Field=field,
            Value="(Array)",
            Description=descriptor.get("doc", ""),
            highlight="important" if descriptor.get("user") else "",
            depth=depth)

        for i, value in enumerate(list_obj):
            for row in self._explain(value, depth=depth):
                row["Field"] = "[%s] %s" % (i, row.get("Field", ""))
                if descriptor.get("user"):
                    row["highlight"] = "important"

                yield row

    def _collect_dict(self, dict_obj, field, descriptor, depth):
        yield dict(
            Field=field,
            Value="(Dict)",
            Description=descriptor.get("doc", ""),
            highlight="important" if descriptor.get("user") else "",
            depth=depth)

        for key, value in sorted(dict_obj.iteritems()):
            for row in self._explain(value, depth=depth+1):
                row["Field"] = ". " + key
                if descriptor.get("user"):
                    row["highlight"] = "important"

                yield row

    def _collect_serialized_object(self, flow_obj, depth=0, ignore_fields=None):
        for descriptor in flow_obj.get_descriptors():
            # Skip hidden fields if verbosity is low.
            if self.plugin_args.verbosity < 2 and descriptor.get("hidden"):
                continue

            field = descriptor["name"]
            # Only show requested fields in non-verbose mode.
            if (not self.plugin_args.verbosity and
                ignore_fields and field in ignore_fields):
                continue

            if not flow_obj.HasMember(field):
                continue

            value = flow_obj.GetMember(field)
            if isinstance(value, serializer.SerializedObject):
                display_value = "(%s)" % value.__class__.__name__

            elif isinstance(value, str):
                display_value = base64.b64encode(value)

            elif isinstance(value, unicode):
                display_value = value

            elif isinstance(value, list):
                for x in self._collect_list(value, field, descriptor, depth):
                    yield x

                continue

            elif isinstance(value, dict):
                for x in self._collect_dict(value, field, descriptor, depth):
                    yield x

                continue

            else:
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
        dict(name="divider", type="Divider")
    ] + SerializedObjectInspectorMixin.table_header

    def _get_collection(self, client_id):
        return flow.FlowStatsCollection.load_from_location(
            self._config.server.flow_db_for_server(client_id),
            session=self.session)

    def get_flow_object(self, flow_id=None):
        if flow_id is None:
            flow_id = self.plugin_args.flow_id

        return flow.Flow.from_json(
            self._config.server.flows_for_server(flow_id).read_file(),
            session=self.session)

    def collect(self):
        flow_obj = self.get_flow_object(self.plugin_args.flow_id)
        with self._get_collection(flow_obj.client_id) as collection:
            yield dict(divider="Flow Object (%s)" % flow_obj.__class__.__name__)

            for x in self._explain(flow_obj, ignore_fields=set([
                    "ticket", "actions"
            ])):
                yield x

            for row in collection.query(flow_id=self.plugin_args.flow_id):
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
                        link = renderers.UILink(
                            "gs", collection.location.get_canonical().to_path())
                        yield dict(
                            Field=collection.__class__.__name__,
                            Value=link,
                            Description="", nowrap=True)

                if ticket.files:
                    yield dict(divider="Uploads")

                    for upload in ticket.files:
                        link = renderers.UILink(
                            "gs", upload.get_canonical().to_path())
                        yield dict(Value=link, nowrap=True)

                if ticket.error:
                    yield dict(divider="Error")
                    yield dict(Field="ticket.error", Value=ticket.error)

                if ticket.backtrace:
                    yield dict(divider="Backtrace")
                    yield dict(Field="ticket.backtrace", Value=ticket.backtrace)



class InspectHunt(InspectFlow):
    name = "inspect_hunt"

    __args = [
        dict(name="limit", type="IntParser", default=20,
             help="Limit of rows to display"),
        dict(name="graph_clients", type="Bool",
             help="Also plot a graph of client participation."),
    ]

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="Field", width=20),
        dict(name="Time", width=20),
        dict(name="Value", width=20),
        dict(name="Description")
    ]

    def _get_collection(self):
        return flow.HuntStatsCollection.load_from_location(
            self._config.server.hunt_db_for_server(self.plugin_args.flow_id),
            session=self.session)

    def graph_clients(self, collection):
        """Draw a graph of client engagement."""
        # This is optionally dependent on presence of matplotlib.
        try:
            from matplotlib import pyplot
        except ImportError:
            raise plugin.PluginError(
                "You must have matplotlib installed to plot graphs.")

        total_clients = 0
        base = None
        data_x = []
        data_y = []
        for row in collection.query(order_by="executed"):
            total_clients += 1
            if base is None:
                base = row["executed"]
            data_x.append(row["executed"] - base)
            data_y.append(total_clients)

        fig = pyplot.figure()
        ax = fig.add_subplot(111)
        ax.plot(data_x, data_y)
        start_time = arrow.Arrow.fromtimestamp(base)
        ax.set_title("Clients in Hunt %s" % self.plugin_args.flow_id)
        ax.set_xlabel("Seconds after %s (%s)" % (
            start_time.ctime(), start_time.humanize()))
        ax.set_ylabel("Total Client Count")
        pyplot.show()

    def collect(self):
        with self._get_collection() as collection:
            flow_obj = self.get_flow_object(self.plugin_args.flow_id)

            if self.plugin_args.graph_clients:
                self.graph_clients(collection)

            yield dict(divider="Flow Object (%s)" % flow_obj.__class__.__name__)
            for x in self._explain(flow_obj, ignore_fields=set([
                    "ticket", "actions"
            ])):
                yield x

            yield dict(divider="Summary")
            yield dict(Field="Total Clients",
                       Value=list(collection.query(
                           "select count(*) as c from tbl_default"
                       ))[0]["c"])

            yield dict(Field="Successful Clients",
                       Value=list(collection.query(
                           "select count(*) as c from tbl_default "
                           "where status = 'Done'"))[0]["c"])

            yield dict(Field="Errors Clients",
                       Value=list(collection.query(
                           "select count(*) as c from tbl_default "
                           "where status = 'Error'"))[0]["c"])

            total = 0
            yield dict(divider="Results")
            for row in collection.query(
                    status="Done", limit=self.plugin_args.limit):
                ticket = flow.FlowStatus.from_json(row["ticket_data"],
                                                   session=self.session)

                for result in ticket.collections:
                    if total > self.plugin_args.limit:
                        break

                    yield dict(Field=ticket.client_id,
                               Time=ticket.timestamp,
                               Value=renderers.UILink(
                                   "gs", result.location.to_path()),
                               nowrap=True)
                    total += 1

            yield dict(divider="Uploads")

            total = 0
            for row in collection.query(
                    status="Done", limit=self.plugin_args.limit):
                ticket = flow.FlowStatus.from_json(row["ticket_data"],
                                                   session=self.session)

                for result in ticket.files:
                    if total > self.plugin_args.limit:
                        break

                    yield dict(Field=ticket.client_id,
                               Time=ticket.timestamp,
                               Value=renderers.UILink(
                                   "gs", result.to_path()),
                               nowrap=True)
                    total += 1

            for row in collection.query(
                    status="Error", limit=self.plugin_args.limit):
                ticket = flow.FlowStatus.from_json(row["ticket_data"],
                                                   session=self.session)

                yield dict(Field=ticket.client_id,
                           Time=ticket.timestamp,
                           Value=ticket.error, nowrap=True)


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

        # This should only be set if no condition is specified.
        dict(name="canned_condition", type="Choices", default=None,
             choices=CANNED_CONDITIONS,
             help="Canned conditions for the hunt."),

        dict(name="live", type="Choices", default="API",
             choices=["API", "Memory"],
             help="Live mode to use"),

        dict(name="quota", type="IntParser", default=3600,
             help="Total number of CPU seconds allowed for this flow."),
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

        flow_obj = flow_cls.from_primitive(args, session=self.session)
        flow_obj.client_id = self.client_id
        flow_obj.queue = self.plugin_args.queue
        flow_obj.session.live = self.plugin_args.live

        # If a canned condition was specified automatically add it.
        if self.plugin_args.canned_condition:
            flow_obj.condition = CANNED_CONDITIONS[
                self.plugin_args.canned_condition]
        elif self.plugin_args.condition:
            flow_obj.condition = self.plugin_args.condition

        # Specify flow quota.
        flow_obj.quota.user_time = self.plugin_args.quota

        return flow_obj

    def collect(self):
        # Now launch the flow.
        flow_obj = self.make_flow_object()
        flow_obj.start()

        for x in self._explain(flow_obj):
            yield x


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
    ]


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


class AgentControllerExportCollections(common.AbstractControllerCommand):
    """Exports all collections from the hunt or flow."""
    name = "export"
    __args = [
        dict(name="flow_id", positional=True, required=True,
             help="The flow or hunt ID we should export."),

        dict(name="dumpdir", positional=True, required=True,
             help="The output directory we use export to.")
    ]

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="Message")
    ]

    def _collect_hunts(self, flow_obj):
        with flow.HuntStatsCollection.load_from_location(
                self._config.server.hunt_db_for_server(flow_obj.flow_id),
                session=self.session) as hunt_db:
            collections_by_type = {}
            uploads = []
            for row in hunt_db.query():
                status = flow.HuntStatus.from_json(row["ticket_data"],
                                                   session=self.session)
                for collection in status.collections:
                    collections_by_type.setdefault(
                        collection.collection_type, []).append(
                            (collection, status.client_id))
                    uploads.extend(status.files)

            yield dict(divider="Exporting Collections")
            # Now create a new collection by type into the output directory.
            for output_location in common.THREADPOOL.imap_unordered(
                    self._dump_collection,
                    collections_by_type.iteritems()):
                yield dict(Message=output_location.to_path())

            yield dict(divider="Exporting files")
            for output_location in common.THREADPOOL.imap_unordered(
                    self._dump_uploads,
                    uploads):
                yield dict(Message=output_location.to_path())

    def _collect_flows(self, flow_obj):
        with flow.FlowStatsCollection.load_from_location(
                self._config.server.flow_db_for_server(flow_obj.client_id),
                session=self.session) as flow_db:
            collections_by_type = {}
            uploads = []
            for row in flow_db.query(flow_id=flow_obj.flow_id):
                status = flow.FlowStatus.from_json(row["ticket_data"],
                                                   session=self.session)
                for collection in status.collections:
                    collections_by_type.setdefault(
                        collection.collection_type, []).append(
                            (collection, status.client_id))
                uploads.extend(status.files)

            yield dict(divider="Exporting Collections")
            # Now create a new collection by type into the output directory.
            for output_location in common.THREADPOOL.imap_unordered(
                    self._dump_collection,
                    collections_by_type.iteritems()):
                yield dict(Message=output_location.to_path())

            yield dict(divider="Exporting files")
            for output_location in common.THREADPOOL.imap_unordered(
                    self._dump_uploads,
                    uploads):
                yield dict(Message=output_location.to_path())

    def _dump_uploads(self, download_location):
        output_location = files.FileLocation.from_keywords(
            path=os.path.join(self.plugin_args.dumpdir,
                              self.flow_id, "files",
                              download_location.to_path()),
            session=self.session)

        local_filename = self._config.server.canonical_for_server(
            download_location).get_local_filename()
        output_location.upload_local_file(local_filename)

        return output_location

    def _dump_collection(self, args):
        type, collections = args
        output_location = files.FileLocation.from_keywords(
            path=os.path.join(self.plugin_args.dumpdir,
                              self.flow_id, "collections", type),
            session=self.session)

        # We assume all the collections of the same type are the same so we can
        # just take the first one as the template for the output collection.
        output_collection = collections[0][0].copy()

        # Add another column for client_id.
        output_collection.tables[0].columns.append(
            result_collections.ColumnSpec.from_keywords(
                name="client_id", session=self.session))
        output_collection.location = output_location
        with output_collection.create_temp_file():
            common.THREADPOOL.map(
                self._copy_single_location,
                ((output_collection, x, y) for x, y in collections))

        return output_location

    def _copy_single_location(self, args):
        output_collection, canonical_collection, client_id = args
        with canonical_collection.load_from_location(
                self._config.server.canonical_for_server(
                    canonical_collection.location),
                session=self.session) as collection:
            for row in collection:
                output_collection.insert(client_id=client_id, **row)

    def collect(self):
        self.flow_id = self.plugin_args.flow_id
        if self.flow_id.startswith("f:") or self.flow_id.startswith("h:"):
            self.flow_id = self.flow_id[2:]

        flow_obj = flow.Flow.from_json(
            self._config.server.flows_for_server(self.flow_id).read_file(),
            session=self.session)

        if flow_obj.is_hunt():
            return self._collect_hunts(flow_obj)

        else:
            return self._collect_flows(flow_obj)

        return []


class FlowLauncherAndWaiterMixin(object):
    """A mixin to implement launching and waiting for flows to complete."""

    def launch_and_wait(self, flow_obj):
        """A Generator of messages."""
        flow_db_location = self._config.server.flow_db_for_server(
            self.client_id)

        flow_db_stat = flow_db_location.stat()

        flow_obj.start()

        # Wait until the flow arrives.
        while 1:
            new_stat = flow_db_location.stat()
            if flow_db_stat and new_stat.generation > flow_db_stat.generation:
                with flow.FlowStatsCollection.load_from_location(
                        flow_db_location, session=self.session) as flow_db:
                    tickets = []
                    for row in flow_db.query(flow_id=flow_obj.flow_id):
                        if row["status"] in ["Done", "Error"]:
                            tickets.append(
                                flow.FlowStatus.from_json(row["ticket_data"],
                                                          session=self.session))

                    if tickets:
                        return tickets

            time.sleep(2)
