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

"""Defines the basic agent configuration system."""
import base64
import json
import os

import arrow
import six

from rekall import obj
from rekall_agent import common
from rekall_lib import crypto
from rekall_lib.rekall_types import agent
from rekall_lib import serializer


class ExternalFileMixin(object):
    """This mixin allows parameters to be defined using filter notation.

    Sometimes it is more convenient to specify certain fields come from external
    sources. This mixin allows the following sources:

    field_name@environ <---- reads field_name from the specified environment
    name if this is set.

    field_name@file <----- reads file_name from the specified file if the file
    can be found.
    """

    @classmethod
    def from_primitive(cls, data, session=None):
        if not data:
            data = {}

        # This is the search_path for configuration files.
        search_path = session.GetParameter("config_search_path", ["."])

        result = {}
        for k, v in six.iteritems(data):
            if "@" in k:
                field_name, filter_name = k.split("@", 1)
                if filter_name == "env":
                    if v in os.environ:
                        session.logging.info(
                            "Fetching %s from env %s", field_name, v)
                        result[field_name] = json.loads(os.environ[v])
                elif filter_name == "file":
                    file_data = cls._locate_file_data_in_search_path(
                        v, search_path)
                    if file_data is None:
                        session.logging.warn(
                            "Unable to find file %s for field %s", v,
                            field_name)
                    else:
                        result[field_name] = file_data

                elif filter_name == "json_file":
                    file_data = cls._locate_file_data_in_search_path(
                        v, search_path)
                    if file_data is None:
                        session.logging.warn(
                            "Unable to find file %s for field %s", v,
                            field_name)
                    else:
                        result[field_name] = json.loads(file_data)

            else:
                result[k] = v

        return super(ExternalFileMixin, cls).from_primitive(
            result, session=session)

    @staticmethod
    def _locate_file_data_in_search_path(path, search_paths):
        # Allow homedir and environment vars to be specified.
        path = os.path.expandvars(os.path.expanduser(path))
        if os.path.isabs(path):
            try:
                return open(path, "rt").read()
            except IOError:
                return
        else:
            for search in search_paths:
                try:
                    path_to_try = os.path.join(search, path)
                    return open(path_to_try, "rt").read()
                except IOError:
                    continue


class ClientWriteback(serializer.SerializedObject):
    """Locate agent state that will be saved in json writeback file.

    This should be very small because the state is checkpointed frequently.
    """

    schema = [
        dict(name="last_flow_time", type="epoch", default=arrow.get(0),
             doc="The create timestamp of the last flow we processed."),

        dict(name="private_key", type=crypto.RSAPrivateKey,
             doc="The client's private key."),

        dict(name="current_flow", type=serializer.SerializedObject,
             doc="The currently running flow.")
    ]

    _client_id = None

    @property
    def client_id(self):
        if self._client_id is None:
            self._client_id = self.private_key.public_key().client_id()
        return self._client_id


class ServerPolicyImpl(ExternalFileMixin,
                       common.AgentConfigMixin,
                       agent.ServerPolicy):
    pass


class ClientPolicyImpl(ExternalFileMixin,
                       common.AgentConfigMixin,
                       agent.ClientPolicy):
    _writeback = obj.NoneObject("No writeback set")

    def plugin_config(self, plugin_cls):
        for plugin in self.plugins:
            if plugin_cls.__name__ == plugin.__class__.__name__:
                return plugin

        return plugin_cls(session=self._session)

    @property
    def client_id(self):
        return self.writeback.client_id

    @property
    def writeback(self):
        if self._writeback == None:
            self._writeback = self.get_writeback()

        return self._writeback

    def get_writeback(self):
        if self._writeback == None and self.writeback_path:
            try:
                self._session.logging.debug(
                    "Will load writeback from %s", self.writeback_path)
                with open(self.writeback_path, "rt") as fd:
                    self._writeback = ClientWriteback.from_primitive(
                        session=self._session, data=json.loads(fd.read()))
            except (IOError, TypeError, AttributeError, ValueError) as e:
                self._session.logging.error(
                    "Failed to decode writeback file: %s", e)
                self._writeback = ClientWriteback(session=self._session)
                self._writeback.private_key.generate_key()
                self.save_writeback()

        return self._writeback

    def set_writeback(self, value):
        self._writeback = value

    def save_writeback(self):
        self._session.logging.debug(
            "Updating writeback %s", self.writeback_path)
        try:
            os.makedirs(os.path.dirname(self.writeback_path))
        except (OSError, IOError):
            pass

        with open(self.writeback_path, "wt") as fd:
            fd.write(self._writeback.to_json())

    _nonce = None
    @property
    def nonce(self):
        """Each time a client is started it will get a unique nonce."""
        if self._nonce is None:
            self._nonce = base64.urlsafe_b64encode(os.urandom(3))

        return self._nonce


class ConfigurationImpl(ExternalFileMixin,
                        agent.Configuration):
    pass
