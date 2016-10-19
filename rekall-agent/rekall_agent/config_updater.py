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

"""This plugin implements the config_updater initialization tool.
"""
import os
import yaml

from rekall import plugin
from rekall import yaml_utils
from rekall_agent import common
from rekall_agent import crypto

from rekall_agent.config import agent
from rekall_agent.client_actions import interrogate


class AgentServerInitialize(plugin.TypedProfileCommand, plugin.Command):
    """The base config initialization plugin.

    Depending on the server deployment type different initialization plugins can
    be implemented.
    """
    __abstract = True

    PHYSICAL_AS_REQUIRED = False
    PROFILE_REQUIRED = False

    __args = [
        dict(name="config_dir", positional=True, required=True,
             help="The directory to write configuration files into."),

        dict(name="client_writeback_path",
             default="/etc/rekall/agent.local.json",
             help="Path to the local client writeback location"),

        dict(name="labels", type="Array", default=["All"],
             help="The list of labels."),
    ]

    table_header = [
        dict(name="Message")
    ]

    ca_private_key_filename = "ca.private_key.pem"
    ca_cert_filename = "ca.cert.pem"
    server_private_key_filename = "server.private_key.pem"
    server_certificate_filename = "server.certificate.pem"
    client_config_filename = "client.config.yaml"
    server_config_filename = "server.config.yaml"

    def generate_keys(self):
        """Generates various keys if needed."""
        ca_private_key_filename = os.path.join(
            self.config_dir, self.ca_private_key_filename)

        ca_cert_filename = os.path.join(
            self.config_dir, self.ca_cert_filename)

        try:
            ca_private_key = crypto.RSAPrivateKey.from_primitive(open(
                ca_private_key_filename).read(), session=self.session)

            ca_cert = crypto.X509Ceritifcate.from_primitive(open(
                ca_cert_filename).read(), session=self.session)

            yield dict(Message="Reusing existing CA keys in %s" %
                       ca_cert_filename)
        except IOError:
            yield dict(
                Message="Generating new CA private key into %s and %s" % (
                    ca_private_key_filename, ca_cert_filename))
            ca_private_key = crypto.RSAPrivateKey(
                session=self.session).generate_key()

            with open(ca_private_key_filename, "wb") as fd:
                fd.write(ca_private_key.to_primitive())

            ca_cert = crypto.MakeCACert(ca_private_key, session=self.session)
            with open(ca_cert_filename, "wb") as fd:
                fd.write(ca_cert.to_primitive())

        # Now same thing with the server keys.
        server_private_key_filename = os.path.join(
            self.config_dir, self.server_private_key_filename)

        server_certificate_filename = os.path.join(
            self.config_dir, self.server_certificate_filename)

        try:
            server_private_key = crypto.RSAPrivateKey.from_primitive(open(
                server_private_key_filename).read(), session=self.session)

            server_certificate = crypto.X509Ceritifcate.from_primitive(open(
                server_certificate_filename).read(), session=self.session)

            yield dict(Message="Reusing existing server keys in %s" %
                       server_certificate_filename)
        except IOError:
            yield dict(
                Message="Generating new Server private keys into %s and %s" % (
                    server_private_key_filename, server_certificate_filename))
            server_private_key = crypto.RSAPrivateKey(
                session=self.session).generate_key()

            with open(server_private_key_filename, "wb") as fd:
                fd.write(server_private_key.to_primitive())

            server_certificate = crypto.MakeCASignedCert(
                unicode("Rekall Agent Server"),
                server_private_key,
                ca_cert,
                ca_private_key,
                session=self.session)

            with open(server_certificate_filename, "wb") as fd:
                fd.write(server_certificate.to_primitive())

        # Ensure the keys verify before we write them.
        server_certificate.verify(ca_cert.get_public_key())

    def write_config(self):
        parameters = self._get_template_parameters()

        # The client config should be completely self contained (i.e. without
        # external file references).
        self.session.SetParameter("config_search_path", [self.config_dir])
        client_config_data = self.client_config_template.format(**parameters)

        client_config = agent.Configuration.from_primitive(
            yaml.safe_load(client_config_data), session=self.session)

        labels = self.plugin_args.labels
        if "All" not in labels:
            labels.append("All")

        client_config.client.labels = labels
        client_config_filename = os.path.join(
            self.config_dir, self.client_config_filename)

        if os.access(client_config_filename, os.R_OK):
            yield dict(
                Message="Client config at %s exists. Remove to regenerate." % (
                    client_config_filename))
        else:
            yield dict(
                Message="Writing client config file %s" % (
                    client_config_filename))

            with open(client_config_filename, "wb") as fd:
                fd.write(yaml_utils.safe_dump(client_config.to_primitive()))

        server_config_data = self.server_config_template.format(**parameters)
        server_config_data += self.client_config_template.format(
            **parameters)

        server_config_filename = os.path.join(
            self.config_dir, self.server_config_filename)

        if os.access(server_config_filename, os.R_OK):
            yield dict(
                Message="Server config at %s exists. Remove to regenerate." % (
                    server_config_filename))
        else:
            yield dict(Message="Writing server config file %s" %
                       server_config_filename)

            with open(server_config_filename, "wb") as fd:
                fd.write(server_config_data)

        # Now load the server config file.
        command_plugin = common.AbstractAgentCommand(
            session=self.session,
            agent_config=server_config_filename)

        self.config = command_plugin.config

    def write_manifest(self):
        yield dict(Message="Writing manifest file.")

        manifest = agent.Manifest.from_keywords(
            session=self.session,

            rekall_session=dict(live="API"),

            # When the client starts up we want it to run the startup action and
            # store the result in the Startup batch queue.
            startup_actions=[
                interrogate.StartupAction.from_keywords(
                    session=self.session,
                    startup_message=(
                        interrogate.Startup.from_keywords(
                            session=self.session,
                            location=self.config.server.flow_ticket_for_client(
                                "Startup", path_template="{client_id}",
                            )
                        )
                    )
                )
            ]
        )

        # Now create a signed manifest.
        signed_manifest = agent.SignedManifest.from_keywords(
            session=self.session,
            data=manifest.to_json(),
            server_certificate=self.config.server.certificate,
        )

        signed_manifest.signature = self.config.server.private_key.sign(
            signed_manifest.data)

        # Now upload the signed manifest to the bucket. Manifest must be
        # publicly accessible.
        upload_location = self.config.server.manifest_for_server()
        yield dict(Message="Writing manifest file to %s" % (
            upload_location.to_path()))

        upload_location.write_file(signed_manifest.to_json())

    def collect(self):
        """This should be an interactive script."""
        self.config_dir = self.plugin_args.config_dir
        if not os.access(self.config_dir, os.R_OK):
            raise plugin.PluginError("Unable to write to config directory %s" %
                                     self.config_dir)

        for method in [self.generate_keys,
                       self.write_config,
                       self.write_manifest]:
            for x in method():
                yield x

        yield dict(Message="Done!")


class AgentServerInitializeGCS(AgentServerInitialize):
    """Initialize the agent server to work in Google Cloud Storage."""

    name = "agent_server_initialize_gcs"

    server_config_template = """
ca_certificate@file: {ca_cert_filename}
server:
  __type__: GCSServerPolicy
  bucket: {bucket}
  ticket_bucket: {bucket}
  service_account@json_file: {service_account}
  certificate@file: {server_certificate_filename}
  private_key@file: {server_private_key_filename}
"""
    client_config_template = """
ca_certificate@file: {ca_cert_filename}
client:
  __type__: GCSAgentPolicy
  manifest_location:
    __type__: GCSUnauthenticatedLocation
    bucket: {bucket}
    path_prefix: /manifest

  writeback_path: {writeback_path}
  labels:
    - All
"""

    manifest_file_template = """

"""

    __args = [
        dict(name="bucket", required=True,
             help="The bucket name for the GCS deployment."),

        dict(name="service_account_path", required=True,
             help="Path to the service account (JSON) credentials"),
    ]

    def _get_template_parameters(self):
        return dict(
            bucket=self.plugin_args.bucket,
            service_account=self.plugin_args.service_account_path,
            server_certificate_filename=self.server_certificate_filename,
            server_private_key_filename=self.server_private_key_filename,
            ca_cert_filename=self.ca_cert_filename,
            writeback_path=self.plugin_args.client_writeback_path,
        )


class AgentServerInitializeLocalHTTP(AgentServerInitialize):
    """Initialize the agent server to work in Google Cloud Storage."""

    name = "agent_server_initialize_http"

    server_config_template = """
ca_certificate@file: {ca_cert_filename}
server:
  __type__: HTTPServerPolicy
  base_url: {base_url}
  certificate@file: {server_certificate_filename}
  private_key@file: {server_private_key_filename}
  bind_port: {bind_port}
  bind_address: {bind_address}

"""
    client_config_template = """
ca_certificate@file: {ca_cert_filename}
client:
  __type__: HTTPClientPolicy
  manifest_location:
    __type__: HTTPLocation
    base: {base_url}
    path: /manifest

  writeback_path: {writeback_path}
  labels: []
"""

    manifest_file_template = """

"""

    __args = [
        dict(name="base_url", required=True,
             help="The publicly accessible URL of the frontend."),

        dict(name="bind_port", type="IntParser", default=8000,
             help="Port to bind to"),

        dict(name="bind_address", default="127.0.0.1",
             help="Address to bind to"),
    ]

    def _get_template_parameters(self):
        return dict(
            base_url=self.plugin_args.base_url,
            bind_port=self.plugin_args.bind_port,
            bind_address=self.plugin_args.bind_address,
            server_certificate_filename=self.server_certificate_filename,
            server_private_key_filename=self.server_private_key_filename,
            ca_cert_filename=self.ca_cert_filename,
            writeback_path=self.plugin_args.client_writeback_path,
        )
