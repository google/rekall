import time

from rekall_lib import serializer
from rekall_lib.rekall_types import actions
from rekall_lib.rekall_types import location
from rekall_lib.rekall_types import resources


class Status(serializer.SerializedObject):
    schema = [
        dict(name="timestamp", type="epoch"),
        dict(name="status", type="choices",
             choices=["Pending", "Started", "Done", "Error", "Crash"]),
        dict(name="error",
             doc="If an error occurred, here will be the error message."),
        dict(name="backtrace",
             doc="If an error occurred, here will be the backtrace."),
    ]


class FlowStatus(Status):
    """Information about flow's progress.

    As the agent works through the flow, this ticket will be updated with status
    information.
    """
    schema = [
        dict(name="client_id"),
        dict(name="flow_id"),
        dict(name="quota", type=resources.Quota,
             doc="The total resources used until now."),
        dict(name="logs", repeated=True,
             doc="Log lines from the client."),
        dict(name="current_action", type=actions.Action,
             doc="The currently running client action."),
        dict(name="collection_ids", repeated=True,
             doc="The collections produced by the flow."),
        dict(name="total_uploaded_files", type="int", default=0,
             doc="Total number of files we uploaded."),
        dict(name="files", type=location.Location, repeated=True, hidden=True,
             doc="The list of files uploaded."),
    ]

class HuntStatus(serializer.SerializedObject):
    """High level information about the hunt."""
    schema = [
        dict(name="total_clients", type="int"),
        dict(name="total_success", type="int"),
        dict(name="total_errors", type="int"),
    ]


class Ticket(serializer.SerializedObject):
    """Baseclass for all tickets.

    A Ticket is sent by the client to modify the flow status. Tickets are sent
    when the flow status changes, such as when it is accepted, completed or
    progressed.
    """
    schema = [
        dict(name="location", type=location.Location,
             doc="Where the ticket should be written."),
    ]

    def send_status(self, status):
        """Send a complete response to the specified location.

        Args: status is a Status() instance.
        """
        status.timestamp = time.time()
        self.location.write_file(status.to_json())


class Flow(serializer.SerializedObject):
    """A Flow is a sequence of client actions.

    To launch a flow simply build a Flow object and call its start() method.
    """
    schema = [
        dict(name="name",
             doc="A name for this flow"),

        dict(name="client_id",
             doc="A client id to target this flow on."),

        dict(name="queue",
             doc="A queue to launch this on. When specified this flow is "
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

        dict(name="ticket", type=Ticket,
             doc="Ticket keeping the state of this flow."),

        dict(name="actions", type=actions.Action, repeated=True,
             doc="The action requests sent to the client."),

        dict(name="quota", type=resources.Quota,
             doc="The total resources the flow is allowed to use."),

        dict(name="status", type=FlowStatus,
             doc="The final status of this flow - to be sent to the ticket."),

        dict(name="file_upload", type=location.Location,
             doc="If included, we use this location to upload files to."),
    ]

    def is_hunt(self):
        """Is this flow running as a hunt?"""
        return self.queue

    def generate_actions(self):
        """Yields one or more Action() objects.

        Should be overridden by derived classes.
        """
        return []

    def start(self):
        """Launch the flow."""
        raise NotImplementedError()

    def expiration(self):
        return time.time() + self.ttl


class CannedFlow(serializer.SerializedObject):
    """A canned flow can be used to make a flow object."""
    schema = [
        dict(name="name"),
        dict(name="description"),
        dict(name="category"),
        dict(name="actions", type=actions.Action, repeated=True)
    ]

class LastClientState(serializer.SerializedObject):
    """Information kept about the last client ping."""
    schema = [
        dict(name="timestamp", type="epoch",
             comment="The last time the client pinged us."),
        dict(name="latlong",
             comment="The location from where the request came from."),
        dict(name="city",
             comment="The city where the request came from"),
        dict(name="ip",
             comment="The IP address where the request came from"),
    ]

class JobFile(serializer.SerializedObject):
    """The contents of the jobs file.

    The job file contains a list of flows to execute. Each flow contains a list
    of client actions.
    """

    schema = [
        dict(name="flows", type=Flow, repeated=True,
             doc="A list of flows issued to this client."),
    ]


class Manifest(serializer.SerializedObject):
    """The manifest is the first thing retrieved from the server.

    The client uses this to authenticate the server and run the startup flow.
    """
    schema = [
        dict(name="startup", type=Flow,
             doc="The initial flow to run when connecting to the server."),
    ]


class PluginConfiguration(serializer.SerializedObject):
    """Plugin specific configuration."""
    schema = []


class ClientPolicy(serializer.SerializedObject):
    """The persistent state of the agent."""

    schema = [
        dict(name="manifest_location", type=location.Location,
             doc="The location of the installation manifest file. "
             "NOTE: This must be unauthenticated because it contains "
             "information required to initialize the connection."),

        dict(name="writeback_path",
             doc="Any persistent changes will be written to this location."),

        dict(name="labels", repeated=True,
             doc="A set of labels for this client."),

        dict(name="poll", type="bool", default=True,
             help="If set, the agent will poll the server for new jobs. "
             "Otherwise the agent will poll once and exit."),

        dict(name="poll_min", type="int", default=5,
             doc="How frequently to poll the server."),

        dict(name="poll_max", type="int", default=60,
             doc="How frequently to poll the server."),

        dict(name="notifier", type=location.NotificationLocation,
             doc="If this is set we use the notifier to also "
             "control poll rate."),

        dict(name="plugins", type=PluginConfiguration, repeated=True,
             doc="Free form plugin specific configuration."),

        dict(name="secret", default="",
             doc="A shared secret between the client and server. "
             "This is used to share data with all clients but "
             "hide it from others.")
    ]


class ServerPolicy(serializer.SerializedObject):
    """The configuration of all server side batch jobs.

    There are many ways to organize the agent's server side code. Although
    inherently the Rekall agent is all about tranferring files to the server,
    there has to be a systemic arrangement of where to store these files and how
    to deliver them (i.e. the Location object's specification).

    The final choice of Location objects is therefore implemented via the
    ServerPolicy object. Depending on the type of deployment, different
    parameters will be required, but ultimately the ServerPolicy object will be
    responsible to produce the required Location objects.

    This is the baseclass of all ServerPolicy objects.
    """
    schema = []


class Configuration(serializer.SerializedObject):
    """The agent configuration system.

    Both client side and server side configuration exist here, but on clients,
    the server side will be omitted.
    """

    schema = [
        dict(name="server", type=ServerPolicy,
             doc="The server's configuration."),

        dict(name="client", type=ClientPolicy,
             doc="The client's configuration."),
    ]


class AuditMessage(serializer.SerializedObject):
    """An audit message written in the audit log."""

    schema = [
        dict(name="format",
             doc="Format string to format the audit message."),
        dict(name="user",
             doc="The user who made the request."),
        dict(name="token_id",
             doc="The token that was used to make this request - if any."),

    ]

    def format_message(self):
        return self.format % self.to_primitive()
