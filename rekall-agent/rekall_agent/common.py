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
from multiprocessing.pool import ThreadPool
from rekall import config
from rekall import plugin


config.DeclareOption("agent_configuration", group="Rekall Agent",
                     help="The Rekall Agent configuration file. When "
                     "specified Rekall switches to Agent mode.")


class AgentConfigMixin(object):

    @property
    def _config(self):
        session = getattr(self, "_session", None) or getattr(self, "session")
        return session.GetParameter("agent_config_obj")


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



class AbstractAgentCommand(AgentConfigMixin, plugin.TypedProfileCommand,
                           plugin.Command):
    """All commands running on the rekall agent extend this."""
    __abstract = True

    PHYSICAL_AS_REQUIRED = False
    PROFILE_REQUIRED = False

    mode = "mode_agent"

    __args = []


class AbstractControllerCommand(AbstractAgentCommand):
    mode = "mode_controller"

    __abstract = True

    __args = [
        dict(name="client_id",
             help="The client_id. If not specified we use the context as set "
             "by the cc() plugin.")
    ]

    CLIENT_REQUIRED = False

    def __init__(self, *args, **kwargs):
        super(AbstractControllerCommand, self).__init__(*args, **kwargs)
        self.client_id = (self.plugin_args.client_id or
                          self.session.GetParameter("controller_context") or
                          None)

        if self.CLIENT_REQUIRED and not self.client_id:
            raise plugin.PluginError("Client ID is required.")
