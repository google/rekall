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

"""This plugin implements the Rekall DFIR agent.

The agent receives Flow() messages from the server (as delivered in JobFile
locations), and executes the Action() jobs contained within them, uploading the
results back to the server. The agent goes through the following phases:

1) When first started, the agent reads the server's manifest file:
   - The server's certificate is verified using the agent's embedded CA cert.

2) The Action() specified in the manifest are executed (usually the Startup
   action).
   - The startup action uploads information about the client to the server. This
     includes the client's public key and client id.

3) The agent then polls the jobs files for new flows (flows with a creation time
   after the agent's own writeback.last_flow_time timestamp).

4) These actions are executed and results are uploaded to the server.
"""
import time
import traceback

from rekall import utils
from rekall_agent import common
from rekall_agent import flow
from rekall_agent.config import agent
from rekall_agent.messages import agent as agent_messages


class _LocationTracker(object):
    def __init__(self, location):
        self.location = location
        self.last_modified = 0

    def get_data(self):
        data = self.location.read_file(if_modified_since=self.last_modified)
        if data:
            self.last_modified = time.time()

        return data


class RekallAgent(common.AbstractAgentCommand):
    """The Rekall DFIR Agent."""

    name = "agent"

    # If we currently running under quota management, this will contain the
    # quota object.
    _quota = None

    def _get_session(self, session_parameters):
        kwargs = session_parameters.to_primitive(True)
        rekall_session = self.session.clone(**kwargs)

        # Pass the agent config to the child session.
        rekall_session.SetParameter("agent_config_obj", self._config)

        # Make sure progress dispatches are propagated.
        rekall_session.progress = self.session.progress

        return rekall_session

    def _run_flow(self, flow_obj):
        # Flow has a condition - we only run the flow if the condition matches.
        if flow_obj.condition:
            try:
                if not list(self.session.plugins.search(flow_obj.condition)):
                    self.session.logging.debug(
                        "Ignoring flow %s because condition %s is not true.",
                        flow_obj.flow_id, flow_obj.condition)
                    return

            # If the query failed to run we must ignore this flow.
            except Exception as e:
                self.session.logging.exception(e)
                return

        # Prepare the session specified by this flow.
        rekall_session = self._get_session(flow_obj.session)

        for action in flow_obj.actions:
            # Make a progress ticket for this action if required.
            flow_obj.ticket.status = "Started"
            flow_obj.ticket.client_id = self._config.client.writeback.client_id
            flow_obj.ticket.current_action = action
            flow_obj.ticket.timestamp = time.time()

            try:
                # Write the ticket to set a checkpoint.
                flow_obj.ticket.send_message()

                # Run the action with the new session, and report the produced
                # collections. Note that the ticket contains all collections for
                # all actions cumulatively.
                action_to_run = action.from_primitive(
                    action.to_primitive(), session=rekall_session)

                for collection in (action_to_run.run(flow_obj=flow_obj) or []):
                    collection.location = collection.location.get_canonical()
                    flow_obj.ticket.collections.append(collection)

            except Exception as e:
                flow_obj.ticket.status = "Error"
                flow_obj.ticket.error = utils.SmartUnicode(e)
                flow_obj.ticket.backtrace = traceback.format_exc()
                flow_obj.ticket.send_message()
                self.session.logging.exception(e)
                return

        flow_obj.ticket.status = "Done"
        flow_obj.ticket.current_action = None
        flow_obj.ticket.send_message()

    def _process_flows(self, flows):
        """Process all the flows and report the number that ran."""
        self.sessions_cache = {}
        flows_ran = 0
        try:
            for flow_obj in flows:
                if not isinstance(flow_obj, flow.Flow):
                    continue

                # We already did this flow before.
                if flow_obj.created_time > self.writeback.last_flow_time:
                    if (flow_obj.created_time.float_timestamp + flow_obj.ttl <
                        time.time()):
                        self.session.logging.debug(
                            "Ignoreing flow id %s - expired", flow_obj.flow_id)
                        continue

                    flows_ran += 1
                    self.writeback.current_ticket = flow_obj.ticket
                    self.writeback.last_flow_time = flow_obj.created_time

                    # Sync the writeback in case we crash.
                    self._config.client.save_writeback()

                    # Start counting resources from now.
                    self._quota = flow_obj.ticket.quota
                    self._quota.start()

                    self._run_flow(flow_obj)

                    # We ran the flow with no exception - remove transaction.
                    self.writeback.current_ticket = None
        finally:
            # At least one flow ran - we need to checkpoint the last ran time in
            # persistent agent state so we do not run it again.
            if flows_ran > 0:
                self._config.client.save_writeback()

            # Stop measuring quotas.
            self._quota = None

        return flows_ran

    def _read_all_flows(self):
        result = []
        for data in common.THREADPOOL.imap_unordered(
                _LocationTracker.get_data, self.jobs_locations):
            try:
                if data:
                    job_file = flow.JobFile.from_json(
                        data, session=self.session)
                    result.extend(job_file.flows)

            except Exception as e:
                if self.session.GetParameter("debug"):
                    raise

                self.session.logging.error("Error %r: %s", e, e)

        return result

    def _startup(self):
        """Go through the startup sequence."""
        # Get the manifest file.
        manifest_data = self._config.client.manifest_location.read_file()
        if not manifest_data:
            self.session.logging.info("Unable to read manifest file.")
            return False

        # We need to verify the manifest. First do we trust the server
        # certificate?
        signed_manifest = agent.SignedManifest.from_json(
            manifest_data, session=self.session)

        server_cert = signed_manifest.server_certificate
        server_cert.verify(
            self._config.ca_certificate.get_public_key())

        # Ok we trust the server, now make sure it signed the data properly.
        server_public_key = server_cert.get_public_key()
        server_public_key.verify(signed_manifest.data,
                                 signed_manifest.signature)

        # Now that we trust the manifest we copy it into our running
        # configuration.
        self._config.manifest = agent.Manifest.from_json(
            signed_manifest.data, session=self.session)

        # Did we crash last time?
        if self.writeback.current_ticket:
            self.session.logging.debug(
                "Reporting crash for %s",
                self.writeback.current_ticket.flow_id)
            self.writeback.current_ticket.status = "Crash"
            self.writeback.current_ticket.timestamp = time.time()
            self.writeback.current_ticket.send_message()
            self.writeback.current_ticket = None
            self._config.client.save_writeback()

        # Now run the startup actions.
        for action in self._config.manifest.startup_actions:
            # Run the action with the new session, and report the produced
            # collections. Note that the ticket contains all collections for
            # all actions cumulatively.
            action_to_run = action.from_primitive(
                action.to_primitive(),
                session=self._get_session(
                    self._config.manifest.rekall_session))

            try:
                action_to_run.run(flow_obj=None)
            except Exception as e:
                self.session.logging.error(
                    "Error running startup action: %s", e)

        return True

    def _check_quota(self, *_, **__):
        if self._quota and not self._quota.check():
            # Catch 22: If we exceeded our quota we must turn off quota
            # management or we wont be able to actually send the error back (due
            # to lack of quota).
            self._quota = None
            raise RuntimeError("Resource Exceeded.")

    @utils.safe_property
    def writeback(self):
        return self._config.client.writeback

    def collect(self):
        """Main entry point for the Rekall agent.

        This never exits.
        """
        # Register our quota check as a Rekall Session progress handler.
        self.session.progress.Register("agent", self._check_quota)
        self.session.SetParameter("agent_mode", "client")

        self.poll_wait = self._config.client.poll_min

        # Startup loop. Spin here until we can verify the server manifest.
        while 1:
            try:
                if self._startup():
                    break
            except Exception as e:
                self.session.logging.exception("Error: %s", e)

            time.sleep(60)

        # Must be done after the startup sequence in case enrollment changes
        # client id and therefore changes the job queues.
        self.jobs_locations = [_LocationTracker(x)
                               for x in self._config.client.get_jobs_queues()]

        # Spin here running jobs.
        while 1:
            flows_ran = 0
            try:
                flows_ran = self._process_flows(self._read_all_flows())
            except Exception as e:
                self.session.logging.exception("Error reading flows.")

            # Adjust the poll interval based on what happened.
            if flows_ran:
                # Switch to fast poll.
                self.poll_wait = self._config.client.poll_min
            else:
                # Slowly drift to slow poll
                self.poll_wait += 5
                if self.poll_wait > self._config.client.poll_max:
                    self.poll_wait = self._config.client.poll_max

            # Wait a bit for the next poll.
            time.sleep(self.poll_wait)


class AgentInfo(common.AbstractAgentCommand):
    """Just emit information about the agent.

    The output format is essentially key value pairs. This is useful for efilter
    queries.
    """
    name = "agent_info"

    table_header = [
        dict(name="key"),
        dict(name="value")
    ]

    def collect(self):
        uname = agent_messages.Uname.from_current_system(session=self.session)
        for k, v in uname.to_primitive().iteritems():
            yield dict(key=k, value=v)
