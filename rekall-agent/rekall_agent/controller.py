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

"""The controller schedules flows on Rekall agents."""
from rekall.plugins.common import address_resolver
from rekall_agent import common


class ControllerAddressResolver(address_resolver.AddressResolverMixin,
                                common.AbstractControllerCommand):
    pass


class RekallAgentController(common.AbstractAgentCommand):
    """Main entry point for running the agent controller."""
    name = "agent_controller"

    def render(self, renderer):
        self.session.session_name = "Rekall Agent"
        self.session.SetParameter("agent_mode", "controller")
        self.session.plugins.shell().render(renderer)


class RekallAgentControllerClientContext(common.AbstractControllerCommand):
    """A plugin which changes the client context.

    Having a client context set avoids the need to specify it each time.
    """
    name = "cc"

    interactive = True
    context = None

    __args = [
        dict(name="client_id", positional=True,
             help="Client id to switch to."),
    ]

    table_header = [
        dict(name="message"),
    ]

    suppress_headers = True

    def __enter__(self):
        """Use this plugin as a context manager.

        When used as a context manager we save the state of the client
        and then restore it on exit. This prevents the address resolver from
        losing its current state and makes switching contexts much faster.
        """
        self.context = self.session.GetParameter("controller_context")
        return self

    def __exit__(self, unused_type, unused_value, unused_traceback):
        # Restore the process context.
        self.SwitchClientContext(self.context)

    def SwitchClientContext(self, client_id=None):
        message = "Switching to client context: {0} ".format(client_id)

        # Reset the address resolver for the new context.
        self.session.SetCache(
            "controller_context", client_id, volatile=False)
        self.session.logging.debug(message)

        # Set the session name to this client.
        if client_id:
            self.session.session_name = client_id
        else:
            self.session.session_name = "Rekall Agent"

        return message

    def collect(self):
        yield dict(message=self.SwitchClientContext(
            self.plugin_args.client_id))
