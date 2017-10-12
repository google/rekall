"""Server configuration for Google App Engine.

NOTE: The Google App Engine app does not use this code, therefore none of the
*_for_server() handlers are implemented.
"""
from rekall_agent.config import agent
from rekall_agent.locations import http_location
from rekall_lib.rekall_types import location


class GAEClientPolicy(agent.ClientPolicyImpl):
    """Clients which connect to Google AppEngine."""
    schema = [
        dict(name="job_locations", type=location.Location, repeated=True,
             doc="A list of locations to query jobs from."),
    ]

    def get_jobs_queues(self):
        return [
            http_location.HTTPLocationImpl.from_keywords(
                session=self._session, base=self.manifest_location.base,
                path_prefix="jobs",
                path_template="?last_flow_time=%s" % (
                    self._config.client.writeback.last_flow_time.timestamp),
            )
        ]
