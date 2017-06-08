import time

from rekall_lib import serializer
from rekall_lib.types import actions
from rekall_lib.types import collections
from rekall_lib.types import location
from rekall_lib.types import resources


class RekallSession(serializer.SerializedObject):
    """A message describing a Rekall Session."""

    schema = [
        dict(name="live", type="choices", default="API",
             choices=["API", "Memory"],
             doc="The Rekall live mode"),
    ]


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

        dict(name="rekall_session", type=RekallSession,
             doc="The session that will be invoked for this flow."),

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
