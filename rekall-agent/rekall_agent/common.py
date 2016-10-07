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
import logging
import os
from multiprocessing.pool import ThreadPool

import yaml

from rekall import plugin
from rekall_agent.config import agent


class LogExceptions(object):
    def __init__(self, callable):
        self.__callable = callable

    def __call__(self, *args, **kwargs):
        try:
            result = self.__callable(*args, **kwargs)
        except Exception as e:
            logging.exception(e)
            raise

        # It was fine, give a normal answer
        return result


class LoggingPool(ThreadPool):
    """The default threadpool swallows exceptions."""

    def apply_async(self, func, *args, **kwargs):
        return super(LoggingPool, self).apply_async(
            LogExceptions(func), *args, **kwargs)

    def imap_unordered(self, func, *args, **kwargs):
        return super(LoggingPool, self).imap_unordered(
            LogExceptions(func), *args, **kwargs)

    def map(self, func, *args, **kwargs):
        return super(LoggingPool, self).map(
            LogExceptions(func), *args, **kwargs)


# A threadpool for reading all messages from a the ticket queue efficiently.
THREADPOOL = LoggingPool(100)



class AbstractAgentCommand(plugin.TypedProfileCommand,
                           plugin.Command):
    """All commands running on the rekall agent extend this."""
    __abstract = True

    PHYSICAL_AS_REQUIRED = False
    PROFILE_REQUIRED = False

    __args = [
        dict(name="agent_config", required=False,
             help="Configuration file for the agent. If not specified, "
             "configuration is read from the session, or a default local "
             "configuration is used.")
    ]

    def __init__(self, *args, **kwargs):
        super(AbstractAgentCommand, self).__init__(*args, **kwargs)
        # The configuration file can be given in the session, or specified on
        # the command line.
        agent_config = self.session.GetParameter(
            "agent_config", self.plugin_args.agent_config)

        if not agent_config:
            raise TypeError("No valid configuration provided.")

        if isinstance(agent_config, basestring):
            # Set the search path to the location of the configuration
            # file. This allows @file directives to access files relative to the
            # main config file.
            if self.session.GetParameter("config_search_path") == None:
                self.session.SetParameter(
                    "config_search_path", [os.path.dirname(agent_config)])

            with open(agent_config, "rb") as fd:
                self.config = agent.Configuration.from_primitive(
                    session=self.session, data=yaml.safe_load(fd.read()))

        elif isinstance(agent_config, agent.Configuration):
            self.config = agent_config

        else:
            raise TypeError("agent_config must be an instance of "
                            "agent.Configuration, not %s." % type(
                                agent_config))

        self.session.SetParameter("agent_config", self.config)


class AbstractControllerCommand(AbstractAgentCommand):
    __abstract = True

    __args = [
        dict(name="client_id",
             help="The client_id. If not specified we use the context as set "
             "by the cc() plugin.")
    ]

    @classmethod
    def is_active(cls, session):
        return session.GetParameter("agent_mode") != None

    def __init__(self, *args, **kwargs):
        super(AbstractControllerCommand, self).__init__(*args, **kwargs)
        self.client_id = (self.plugin_args.client_id or
                          self.session.GetParameter("controller_context") or
                          None)
