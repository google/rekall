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
import os
import yaml
from rekall import kb
from rekall import obj

from rekall_agent.config import agent


class AgentMode(kb.ParameterHook):
    name = "mode_agent"

    def calculate(self):
        return self.session.GetParameter("agent_config_obj") != None


class ClientAgentMode(kb.ParameterHook):
    name = "mode_client"

    def calculate(self):
        return self.session.GetParameter("agent_mode") == "client"


class AgentControllerMode(kb.ParameterHook):
    name = "mode_controller"

    def calculate(self):
        return self.session.GetParameter("agent_mode") == "controller"


class AgentConfigHook(kb.ParameterHook):
    name = "agent_config_obj"

    def calculate(self):
        config_data = self.session.GetParameter("agent_config_data")
        if not config_data:
            config_data = os.environ.get("REKALL_AGENT_CONFIG")

        if not config_data:
            # The configuration file can be given in the session, or specified
            # on the command line. This is the path to the agent config file.
            agent_config = self.session.GetParameter("agent_configuration")
            if not agent_config:
                agent_config = os.environ.get("REKALL_AGENT_CONFIG_FILE")

            if agent_config:
                # Set the search path to the location of the configuration
                # file. This allows @file directives to access files relative to
                # the main config file.
                if self.session.GetParameter("config_search_path") == None:
                    self.session.SetParameter(
                        "config_search_path", [os.path.dirname(agent_config)])

                with open(agent_config, "rb") as fd:
                    config_data = fd.read()

        if not config_data:
            return obj.NoneObject("No valid configuration provided in session.")

        return agent.Configuration.from_primitive(
            session=self.session, data=yaml.safe_load(config_data))
