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

import json
import platform
import socket
import time
import traceback

import psutil

from rekall import plugin
from rekall_agent import common

# Required for plugins.
from rekall_lib import crypto
from rekall_lib import serializer
from rekall_lib import utils
from rekall_lib.types import agent
from rekall_lib.types import client
from rekall_lib.types import resources

from wheel import pep425tags


# Time the agent was first started.
START_TIME = time.time()


class ResourcesImpl(resources.Resources):
    """Measure resource usage."""

    _start_user_time = _start_system_time = _start_wall_time = 0
    _counting = False
    _proc = None

    def __init__(self, *args, **kwargs):
        super(ResourcesImpl, self).__init__(*args, **kwargs)
        self._proc = psutil.Process()

    def start(self):
        """Reset internal resource counters and start measuring."""
        cpu_times = self._proc.cpu_times()

        self._start_user_time = cpu_times.user
        self._start_system_time = cpu_times.system
        self._start_wall_time = time.time()
        self._counting = True
        self._signal_modified()

    def stop(self):
        """Stop measuring."""
        self._counting = False

    def update(self):
        cpu_times = self._proc.cpu_times()
        if self._counting:
            self.user_time = cpu_times.user - self._start_user_time
            self.system_time = cpu_times.system - self._start_system_time
            self.wall_time = time.time() - self._start_wall_time

    def to_primitive(self):
        """Freeze the current resources upon serialization."""
        self.update()
        return super(ResourcesImpl, self).to_primitive(self)

    @property
    def total_time(self):
        self.update()
        return self.user_time + self.system_time


class QuotaImpl(ResourcesImpl, resources.Quota):
    _last_check_time = 0

    def start(self):
        self.used.start()

    def check(self):
        """Ensure our resource use does not exceed the quota."""
        now = time.time()
        # Skip checking if we got called less than 1 seconds ago.
        if now - self._last_check_time < 1:
            return True

        self._last_check_time = now
        return self.used.total_time <= self.total_time


class UnameImpl(client.Uname):
    """Stores information about the system."""

    @classmethod
    def from_current_system(cls, session=None):
        """Gets a Uname object populated from the current system"""
        uname = platform.uname()
        fqdn = socket.getfqdn()
        system = uname[0]
        architecture, _ = platform.architecture()
        if system == "Windows":
            service_pack = platform.win32_ver()[2]
            kernel = uname[3]  # 5.1.2600
            release = uname[2]  # XP, 2000, 7
            version = uname[3] + service_pack  # 5.1.2600 SP3, 6.1.7601 SP1
        elif system == "Darwin":
            kernel = uname[2]  # 12.2.0
            release = "OSX"  # OSX
            version = platform.mac_ver()[0]  # 10.8.2
        elif system == "Linux":
            kernel = uname[2]  # 3.2.5
            release = platform.linux_distribution()[0]  # Ubuntu
            version = platform.linux_distribution()[1]  # 12.04

        # Emulate PEP 425 naming conventions - e.g. cp27-cp27mu-linux_x86_64.
        pep425tag = "%s%s-%s-%s" % (pep425tags.get_abbr_impl(),
                                    pep425tags.get_impl_ver(),
                                    str(pep425tags.get_abi_tag()).lower(),
                                    pep425tags.get_platform())

        return cls.from_keywords(
            session=session,
            system=system,
            architecture=architecture,
            node=uname[1],
            release=release,
            version=version,
            machine=uname[4],              # x86, x86_64
            kernel=kernel,
            fqdn=fqdn,
            pep425tag=pep425tag,
        )


class StartupActionImpl(common.AgentConfigMixin, client.StartupAction):
    def enroll(self):
        """Generate a new client_id.

        This runs only if the agent does not know its client_id.
        """
        private_key = crypto.RSAPrivateKey(session=self._session).generate_key()
        self._config.client.writeback.private_key = private_key

        client_id = private_key.public_key().client_id()
        self._config.client.writeback.client_id = client_id

        self._session.logging.info("Creating a new client_id %s", client_id)
        self._config.client.save_writeback()

    def run(self, flow_obj=None):
        if not self.is_active():
            return []

        if not self._config.client.writeback.client_id:
            self.enroll()

        message = client.StartupMessage.from_keywords(
            client_id=self._config.client.writeback.client_id,
            boot_time=psutil.boot_time(),
            agent_start_time=START_TIME,
            timestamp=time.time(),
            system_info=UnameImpl.from_current_system(session=self._session),
        )
        self._session.logging.debug("Sending client startup message to server.")
        self.location.write_file(message.to_json())


class _LocationTracker(object):
    def __init__(self, location):
        self.location = location
        self.last_modified = 0

    def get_data(self):
        data = self.location.read_file(if_modified_since=self.last_modified)
        if data:
            self.last_modified = time.time()

        return data


class RunFlow(common.AgentConfigMixin,
              plugin.TypedProfileCommand,
              plugin.Command):
    """Run the flows specified."""
    name = "run_flow"

    table_header = [
        dict(name="status"),
    ]

    __args = [
        dict(name="flow", positional=True,
             help="A string encoding a Flow JSON object."),
        dict(name="flow_filename",
             help="A filename containing an encoded Flow JSON object."),
    ]

    def _get_session(self, session_parameters):
        rekall_session = self.session.clone(**session_parameters)

        # Make sure progress dispatchers are propagated.
        rekall_session.progress = self.session.progress

        return rekall_session

    def _run_flow(self):
        # Flow has a condition - we only run the flow if the condition matches.
        if self.flow.condition:
            try:
                if not list(self.session.plugins.search(self.flow.condition)):
                    self.session.logging.debug(
                        "Ignoring flow %s because condition %s is not true.",
                        self.flow.flow_id, self.flow.condition)
                    return

            # If the query failed to run we must ignore this flow.
            except Exception as e:
                self.session.logging.exception(e)
                return

        # Prepare the session specified by this flow.
        rekall_session = self._get_session(self.flow.rekall_session)
        status = self.flow.status
        for action in self.flow.actions:
            try:
                # Make a progress ticket for this action if required.
                status.status = "Started"
                status.client_id = self._config.client.client_id
                status.current_action = action

                yield status

                # Run the action with the new session, and report the produced
                # collections. Note that the ticket contains all collections for
                # all actions cumulatively.
                action_to_run = serializer.unserialize(
                    action.to_primitive(),
                    session=rekall_session,
                    strict_parsing=False)

                for collection in (action_to_run.run(flow_obj=self.flow) or []):
                    status.collections.append(collection)

                # Update the server on our progress
                self.flow.ticket.send_status(status)

            except Exception as e:
                status.status = "Error"
                status.error = utils.SmartUnicode(e)
                status.backtrace = traceback.format_exc()
                yield status
                self.flow.ticket.send_status(status)
                self.session.logging.exception(e)
                return

        status.status = "Done"
        status.current_action = None
        yield status

    def collect(self):
        self.flow = self.plugin_args.flow
        if isinstance(self.flow, basestring):
            self.flow = serializer.unserialize(
                json.loads(self.flow), session=self.session,
                # Allow for future addition of fields.
                strict_parsing=False)

        elif isinstance(self.flow, dict):
            self.flow = serializer.unserialize(
                self.flow, session=self.session,
                strict_parsing=False)

        elif not isinstance(self.flow, agent.Flow):
            raise plugin.PluginError("Flow must be provided as JSON string.")

        for status in self._run_flow():
            self.flow.ticket.send_status(status)
            yield dict(status=status.copy())


class RekallAgent(common.AbstractAgentCommand):
    """The Rekall DFIR Agent."""

    name = "agent"

    # If we currently running under quota management, this will contain the
    # quota object.
    _quota = None

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
                if not isinstance(flow_obj, agent.Flow):
                    continue

                # We already did this flow before.
                if flow_obj.created_time > self.writeback.last_flow_time:
                    if (flow_obj.created_time.float_timestamp + flow_obj.ttl <
                        time.time()):
                        self.session.logging.debug(
                            "Ignoreing flow id %s - expired", flow_obj.flow_id)
                        continue

                    flows_ran += 1
                    self.writeback.current_flow = flow_obj
                    self.writeback.current_flow.status.timestamp = time.time()

                    # Sync the writeback in case we crash.
                    self._config.client.save_writeback()

                    # Start counting resources from now.
                    self._quota = flow_obj.quota
                    self._quota.start()

                    try:
                        for status in self.session.plugins.run_flow(flow_obj):
                            self.session.logging.debug("Status: %s", status)
                    finally:
                        # We ran the flow with no exception - remove
                        # transaction.
                        self.writeback.current_flow = None
                        self._config.client.save_writeback()

        finally:
            # Stop measuring quotas.
            self._quota = None

        return flows_ran

    def _read_all_flows(self):
        result = []
        for data in common.THREADPOOL.imap_unordered(
                _LocationTracker.get_data, self.jobs_locations):
            try:
                if data:
                    job_file = serializer.unserialize(
                        json.loads(data), session=self.session,
                        strict_parsing=False)
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

        manifest = agent.Manifest.from_json(
            manifest_data, session=self.session)

        # Did we crash last time? If so, send the old flow a crash ticket.
        current_flow = self.writeback.current_flow
        if current_flow:
            self.session.logging.debug("Reporting crash for %s",
                                       current_flow.flow_id)

            status = current_flow.status
            status.timestamp = time.time()
            status.status = "Crash"
            current_flow.ticket.send_status(status)

            self.writeback.current_flow = None
            self._config.client.save_writeback()

        # Now run the startup flow.
        for status in self.session.plugins.run_flow(manifest.startup).collect():
            self.session.logging.debug("Status: %s", status)

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
        uname = UnameImpl.from_current_system(session=self.session)
        for k, v in uname.to_primitive().iteritems():
            yield dict(key=k, value=v)
