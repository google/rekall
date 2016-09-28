import time
import threading

from rekall_agent import common
from rekall_agent import serializer
from rekall_agent import location


class BatchTicket(serializer.SerializedObject):
    """Baseclass for all batch tickets.

    Batch jobs are launched from tickets placed in the ticket bucket. This
    object forms the ticket message itself. It will typically be extended by
    real batch messages with additional fields specific to that batch job.

    We typically try to have the agent send the complete result set to the
    server for batch processing. A job request will invoke a client action with
    several parameters. Usually one of the parameters is a batch ticket prepared
    by the server which the agent fills in the required parameters then calls
    its send_message() method, which writes it into the correct batch queue.
    """

    schema = [
        dict(name="location", type=location.Location,
             doc="Where the ticket should be written."),
        dict(name="timestamp", type="epoch")
    ]

    def __init__(self, *args, **kwargs):
        super(BatchTicket, self).__init__(*args, **kwargs)
        self._config = self._session.GetParameter("agent_config")

    def send_message(self):
        """Send a complete batch response to the specified location."""
        self.timestamp = time.time()

        try:
            to_send = self.copy()
            to_send.location = self.location.get_canonical()
            self.location.write_file(to_send.to_json())
        except IOError as e:
            self._session.logging.exception(e)

    @classmethod
    def begin(cls, context, session=None):
        """Called once at the beginning of the batch run.

        context is a dict which may be used to keep context through this batch
        run.
        """

    @classmethod
    def end(cls, context, session=None):
        """Called once at the end of the batch run."""

    def process(self, context):
        """Called once on each instance to process this instance."""


class BatchRunner(object):
    """Runs through a single batch processing job."""

    def __init__(self, session, batch_name=None, batch_cls=None):
        self.session = session
        self.batch_cls = (batch_cls or
                          BatchTicket.ImplementationByClass(batch_name))
        self._config = self.session.GetParameter("agent_config")
        if not self.batch_cls:
            raise RuntimeError(
                "Batch implementation %s not known." % batch_name)

        self.batch_name = batch_name or batch_cls.__name__
        self.lock = threading.RLock()

    def run(self):
        """Generates tickets from the batch queue."""
        self.context = {}
        ticket_locations = []
        queue_location = self._config.server.ticket_for_server(
            self.batch_name)

        for ticket_stat in queue_location.list_files():
            ticket_locations.append(ticket_stat.location)

        # Nothing to do here.
        if not ticket_locations:
            return

        self.batch_cls.begin(self.context, session=self.session)
        try:
            common.THREADPOOL.map(self._process_ticket, ticket_locations)
        finally:
            self.batch_cls.end(self.context, session=self.session)

    def _process_ticket(self, ticket_location):
        try:
            batch = self.batch_cls.from_json(
                ticket_location.read_file(),
                session=self.session)
            with self.lock:
                batch.process(self.context)
        finally:
            # Remove the ticket from the batch queue.
            ticket_location.delete()
