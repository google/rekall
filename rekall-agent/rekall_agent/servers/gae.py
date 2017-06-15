"""Server configuration for Google App Engine.

NOTE: The Google App Engine app does not use this code, therefore none of the
*_for_server() handlers are implemented.
"""
import time

from rekall_lib.types import location
from rekall_agent.config import agent
from rekall_agent.locations import http
from rekall_lib import utils



class GAEServerPolicy(agent.ServerPolicy):
    """A Stand along HTTP Server."""
    schema = [
        dict(name="base_url", default="http://127.0.0.1/",
             doc="The base URL for the AppEngine project."),
    ]

    def manifest_for_client(self):
        return http.HTTPLocation.New(
            session=self._session,
            expiration=time.time() + 365 * 24 * 60 *60,
            path_prefix="/manifest",
            access=["READ"],
        )

    def hunt_vfs_path_for_client(self, hunt_id, path_prefix="", expiration=None,
                                 vfs_type="analysis",
                                 path_template="{client_id}"):
        return http.HTTPLocation.New(
            session=self._session,
            access=["WRITE"],
            path_prefix=utils.join_path(
                "hunts", hunt_id, "vfs", vfs_type, path_prefix),
            path_template=path_template + "/{nonce}",
            expiration=expiration)

    def vfs_prefix_for_client(self, client_id, path="", expiration=None,
                              vfs_type="files"):
        """Returns a Location suitable for storing a path using the prefix."""
        return http.HTTPLocation.New(
            session=self._session,
            access=["WRITE"],
            path_prefix=utils.join_path(
                client_id, "vfs", vfs_type, path),
            path_template="{subpath}/{nonce}",
            expiration=expiration)

    def flow_ticket_for_client(self, batch_name, *ticket_names, **kw):
        """Returns a Location for the client to write tickets.

        When we issue requests to the client, we need to allow the client to
        report progress about the progress of the flow requests running on the
        client. We do this by instructing the client to write a "Flow Ticket" to
        the ticket location.
        """
        expiration = kw.pop("expiration", None)
        path_template = kw.pop("path_template", None)
        return http.HTTPLocation.New(
            session=self._session,
            access=["WRITE"],
            path_prefix=utils.join_path("tickets", batch_name, *ticket_names),
            path_template=path_template + "/{nonce}",
            expiration=expiration)

    def vfs_path_for_client(self, client_id, path, mode="w", expiration=None,
                            vfs_type="analysis"):
        """Returns a Location for storing the path in the client's VFS area.

        Passed to the agent to write on client VFS.
        """
        if mode == "r":
            access = ["READ"]
        elif mode == "w":
            access = ["WRITE"]
        else:
            raise ValueError("Invalid mode")

        return http.HTTPLocation.New(
            session=self._session,
            access=access,
            path_prefix=utils.join_path(client_id, "vfs", vfs_type, path),
            expiration=expiration)


class GAEClientPolicy(agent.ClientPolicy):
    """Clients which connect to Google AppEngine."""
    schema = [
        dict(name="job_locations", type=location.Location, repeated=True,
             doc="A list of locations to query jobs from."),
    ]

    def get_jobs_queues(self):
        return [
            http.HTTPLocationImpl.from_keywords(
                session=self._session, base=self.manifest_location.base,
                path_prefix=utils.join_path("jobs", self.client_id,
                                            self.secret))
        ]
