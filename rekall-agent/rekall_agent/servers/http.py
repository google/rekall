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

"""A standalone http server for users that do not want to use Google cloud."""
import base64
import BaseHTTPServer
import cgi
import json
import socket
import SocketServer
import os
import urlparse
import tempfile
import time
import urllib

from email import utils as email_utils

import ipaddr
import arrow

from rekall import utils
from rekall_agent import cache
from rekall_agent import common
from rekall_agent import location
from rekall_agent.config import agent
from rekall_agent.locations import http


class HTTPServerPolicy(agent.ServerPolicy):
    """A Stand along HTTP Server."""
    schema = [
        dict(name="base_url", default="http://127.0.0.1/",
             doc="The base URL to use"),

        dict(name="root_directory", default="/tmp/rekall",
             doc="The root directory to serve files from."),

        dict(name="bind_port", default=8000, type="int",
             doc="The port number to listen on."),

        dict(name="port_max", default=8010, type="int",
             doc="The largest port number to listen on."),

        dict(name="bind_address", default="127.0.0.1",
             doc="The address to bind to"),

        # HTTP server locations must use a local cache.
        dict(name="cache", type=cache.LocalDiskCache,
             doc="Local cache to use."),
    ]

    def jobs_queue_for_server(self, client_id=None, queue=None):
        """Returns a Location for the client's job queue.

        Used by the server to manipulate the client's job queue.

        If a queue is specified, the jobs file is shared under this public queue
        name. Otherwise the jobs file is private to the client_id.
        """
        if queue:
            return http.HTTPLocation.New(
                session=self._session,
                path_prefix="labels/%s/jobs/%s" % (
                    queue, self._config.client.secret),
                public=True)

        # The client's jobs queue itself is publicly readable since the client
        # itself has no credentials.
        return http.HTTPLocation.New(
            session=self._session,
            path_prefix=utils.join_path(client_id, "jobs"),
            public=True)

    def client_db_for_server(self):
        """The global client database."""
        return http.HTTPLocation.New(
            session=self._session,
            path_prefix="clients.sqlite")

    def flow_db_for_server(self, client_id=None, queue=None):
        if queue:
            return http.HTTPLocation.New(
                session=self._session,
                path_prefix="hunts/%s/flows.sqlite" % queue)

        return http.HTTPLocation.New(
            session=self._session,
            path_prefix=client_id + "/flows.sqlite")

    def manifest_for_server(self):
        return http.HTTPLocation.New(
            session=self._session,
            path_prefix="/",
            path_template="?action=manifest",
            access=["READ"]
        )

    def manifest_for_client(self):
        return http.HTTPLocation.New(
            session=self._session,
            expiration=time.time() + 365 * 24 * 60 *60,
            path_prefix="/",
            path_template="?action=manifest",
            access=["READ"],
        )

    def vfs_index_for_server(self, client_id=None):
        return http.HTTPLocation.New(
            session=self._session,
            path_prefix=utils.join_path(client_id, "vfs.index"))

    def hunt_db_for_server(self, hunt_id):
        return http.HTTPLocation.New(
            session=self._session,
            path_prefix="hunts/%s/stats.sqlite" % hunt_id)

    def hunt_result_collection_for_server(self, hunt_id, type):
        return http.HTTPLocation.New(
            session=self._session,
            path_prefix="hunts/%s/%s" % (hunt_id, type))

    def client_record_for_server(self, client_id):
        """The client specific information."""
        return http.HTTPLocation.New(
            session=self._session,
            path_prefix="%s/client.metadata" % client_id)

    def flows_for_server(self, flow_id):
        """A location to write flow objects."""
        return http.HTTPLocation.New(
            session=self._session,
            path_prefix=utils.join_path("flows", flow_id))

    def ticket_for_server(self, batch_name, *args):
        """The location of the ticket queue for this batch."""
        return http.HTTPLocation.New(
            session=self._session, access=["READ", "LIST"],
            path_prefix=utils.join_path("tickets", batch_name, *args),
            path_template="/")

    def canonical_for_server(self, location):
        """Convert a canonical location to a server usable one.

        The server location has full read/write access.
        """
        canonical_location = location.get_canonical()
        return http.HTTPLocation.New(
            session=self._session,
            path_prefix=canonical_location.path_prefix)

    def vfs_path_for_server(self, client_id, path, vfs_type="analysis"):
        """Returns a Location for storing the path in the client's VFS area.

        Passed to the agent to write on client VFS.
        """
        return http.HTTPLocation.New(
            session=self._session, access=["READ", "LIST"],
            path_prefix=utils.join_path(client_id, "vfs", vfs_type, path))


    def flow_metadata_collection_for_server(self, client_id):
        if not client_id:
            raise RuntimeError("client id expected")
        return http.HTTPLocation.New(
            session=self._session,
            path_prefix=utils.join_path(client_id, "flows.sqlite")
        )

    def location_from_path_for_server(self, path):
        """Construct a location from a simple string path.

        Path is just a reference into the bucket of the form:

        {bucket_name}/{object_path}
        """
        if not path:
            path = "/"

        return http.HTTPLocation.New(
            session=self._session,
            path_prefix=path)

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


class HTTPClientPolicy(agent.ClientPolicy):
    """Directly connect to HTTP servers."""
    schema = [
        dict(name="job_locations", type=location.Location, repeated=True,
             doc="A list of locations to query jobs from."),
    ]

    def get_jobs_queues(self):
        # The jobs queue is world readable.
        result = [
            http.HTTPLocation.from_keywords(
                session=self._session, base=self.manifest_location.base,
                path_prefix=utils.join_path(self.client_id, "jobs"))
        ]
        for label in self.labels:
            result.append(
                http.HTTPLocation.from_keywords(
                    session=self._session,
                    base=self.manifest_location.base,
                    # Make sure to append the secret to the unauthenticated
                    # queues to prevent public (non deployment) access.
                    path_prefix=utils.join_path(
                        "labels", label, "jobs", self.secret))
            )

        return result



class RekallHTTPServerHandler(BaseHTTPServer.BaseHTTPRequestHandler, object):
    """HTTP handler for receiving client posts."""
    READ_BLOCK_SIZE = 10 * 1024 * 1024
    protocol_version = "HTTP/1.1"

    public = False

    def __init__(self, request, client_address, server, **kwargs):
        self.session = server.session
        self._config = self.session.GetParameter("agent_config_obj")
        self._cache = cache.LocalDiskCache.from_keywords(
            session=self.session,
            cache_directory=self._config.server.root_directory)
        super(RekallHTTPServerHandler, self).__init__(
            request, client_address, server, **kwargs)

    def authenticate(self, access):
        """Authenticate the request before we do anything."""
        policy_data = self.headers.get("x-rekall-policy")
        signature = self.headers.get("x-rekall-signature")
        if (not policy_data or not signature):
            return False

        try:
            policy_data = base64.b64decode(policy_data)
            signature = base64.b64decode(signature)

            self._config.server.private_key.public_key().verify(
                policy_data, signature)

            policy = http.URLPolicy.from_json(policy_data, session=self.session)
        except (ValueError, AttributeError):
            return False

        # Verify the hmac.
        if (access not in policy.access or
            not self.base_path.startswith(policy.path_prefix) or
            arrow.Arrow.utcnow() > policy.expires):
            self.session.logging.debug("Policy mismatch (%s): %s" % (
                self.base_path, policy))
            return False

        # If the policy does not allow a template then path must match
        # exactly.
        if (policy.path_template == "" and
            self.base_path != policy.path_prefix):
            self.session.logging.debug("Policy mismatch (%s): %s" % (
                self.base_path, policy))
            return False

        self.public = policy.public

        return True

    def _parse_qs(self):
        if "?" in self.path:
            self.base_path, qs = self.path.split("?", 1)
            self.params = urlparse.parse_qs(qs)
        else:
            self.params = {}
            self.base_path = self.path

        # base path is a unicode string so we must decode it from self.path.
        self.base_path = urllib.unquote(self.base_path).decode(
            "utf8", "ignore")

    def do_GET(self):
        """Serve the server pem with GET requests."""
        self._parse_qs()

        # This is an API call.
        if "action" in self.params:
            self.serve_api(self.base_path, self.params)
            return

        if self.authenticate("READ"):
            self.serve_static(self.base_path)
            return

        else:
            public_path = utils.join_path(".public", self.base_path)
            generation = self._cache.get_generation(public_path)
            if generation:
                self.serve_static(public_path)
                return

        # Not authorized.
        self.send_error(403, "You are not authorized to view this location.")

    def log_message(self, format, *args):
        self.session.logging.info(format, *args)

    def serve_api(self, path, params):
        if params["action"] == ["stat"]:
            if not self.authenticate("READ"):
                self.send_error(
                    403, "You are not authorized to view this location.")
                return

            row = self._cache.stat(path)
            if not row:
                self.send_error(404)
                return

            result = location.LocationStat.from_keywords(
                session=self.session,
                created=row["created"],
                updated=row["updated"],
                size=row["size"],
                generation=row["generation"],
                location=http.HTTPLocation.from_keywords(
                    session=self.session,
                    base=self._config.server.base_url,
                    path_prefix=row["path"],
                )
            )
            data = result.to_json()
            self.send_response(200)
            self.send_header("Content-Length", len(data))
            self.end_headers()
            self.wfile.write(data)
            return

        if params["action"] == ["list"]:
            # When listing an object we force a / onto the end to
            # prevent partial matches on non directory boundary.
            if self.base_path and self.base_path[-1] != "/":
                self.base_path += "/"

            # Listing directories requires explicit permission which
            # is different from just READ.
            if not self.authenticate("LIST"):
                self.send_error(
                    403, "You are not authorized to list this location.")
                return

            limit = 100
            if "limit" in params:
                limit = int(params["limit"][0])

            result = []
            for i, row in enumerate(self._cache.list_files(path)):
                if i > limit:
                    break

                result.append(location.LocationStat.from_keywords(
                    session=self.session,
                    created=row["created"],
                    updated=row["updated"],
                    size=row["size"],
                    generation=row["generation"],
                    location=http.HTTPLocation.from_keywords(
                        session=self.session,
                        base=self._config.server.base_url,
                        path_prefix=row["path"],
                        )
                    ).to_primitive())

            data = json.dumps(result, sort_keys=True)
            self.send_response(200)
            self.send_header("Content-Length", len(data))
            self.end_headers()
            self.wfile.write(data)
            return

        elif params["action"] == ["delete"]:
            if not self.authenticate("WRITE"):
                self.send_error(
                    403, "You are not authorized to delete this location.")
                return

            self._cache.expire(path)
            self.send_response(200)
            self.send_header("Content-Length", 0)
            self.end_headers()
            return

        elif params["action"] == ["manifest"]:
            # Ensure client has READ access to the manifest file.
            if not self.authenticate("READ"):
                self.send_error(
                    403, "You are not authorized.")
                return

            self.send_response(200)
            data = self._config.signed_manifest.to_json()
            self.send_header("Content-Length", len(data))
            self.end_headers()
            self.wfile.write(data)
            return

        else:
            self.send_error(404, "Unknown API handler.")

    def serve_static(self, path):
        try:
            generation = self._cache.get_generation(path)
            if not generation:
                self.send_error(404, "File not found")
                return

            if_modified_since = self.headers.get("If-Modified-Since")
            if if_modified_since:
                since = email_utils.parsedate(if_modified_since)
                if since >= time.gmtime(int(generation)/1e6):
                    self.send_response(304)
                    self.send_header("Content-Length", 0)
                    self.end_headers()
                    return

            # File is not modified.
            requested_generation = self.headers.get("If-None-Match")
            if requested_generation == generation:
                self.send_response(304)
                self.send_header("Content-Length", 0)
                self.end_headers()
                return

            local_path = self._cache.get_local_file(path, generation)
            with open(local_path) as fd:
                self.send_response(200)
                fs = os.fstat(fd.fileno())
                self.send_header("ETag", '"%s"' % generation)
                self.send_header("Content-Length", str(fs[6]))
                self.end_headers()

                while True:
                    data = fd.read(self.READ_BLOCK_SIZE)
                    if not data:
                        break

                    self.wfile.write(data)
        except (IOError, AttributeError):
            self.send_error(500, close=True)

    def do_PUT(self):
        self._parse_qs()

        if self.authenticate("WRITE"):
            try:
                if self.headers.get("Transfer-Encoding") == "chunked":
                    self._chunked_upload_file()
                else:
                    self._direct_upload_file()
            except Exception:
                self.send_error(500, close=True)
        else:
            self.send_error(403)

    def _get_generation_from_timestamp(self, timestamp):
        return str(int(timestamp * 1e6))

    def _copy_bytes(self, infd, outfd, length):
        """Copy bytes from infd to outfd."""
        while 1:
            to_read = min(length, self.READ_BLOCK_SIZE)
            if to_read == 0:
                return

            data = infd.read(to_read)
            if not data:
                return

            os.write(outfd, data)
            length -= len(data)

    def _chunked_upload_file(self):
        # First upload the file to a temp directory, then move it into place at
        # once.
        fd, local_filename = tempfile.mkstemp()
        try:
            count = 0
            while 1:
                line = self.rfile.readline()

                # We do not support chunked extensions, just ignore them.
                chunk_size = int(line.split(";")[0], 16)
                if chunk_size == 0:
                    break

                # Copy the chunk into the file store.
                self._copy_bytes(self.rfile, fd, chunk_size)
                count += chunk_size

                # Chunk is followed by \r\n.
                lf = self.rfile.read(2)
                if lf != "\r\n":
                    raise IOError("Unable to parse chunk.")

            # Skip entity headers.
            for header in self.rfile.readline():
                if not header:
                    break
        finally:
            os.close(fd)

        self._move_file_into_place(local_filename)
        self.session.logging.debug("Uploaded %s (%s)", self.base_path, count)

    def _move_file_into_place(self, local_filename):
        # This is the new generation.
        generation = self._get_generation_from_timestamp(time.time())
        # Where shall we put the path.
        path = self.base_path
        if self.public:
            path = utils.join_path(".public", path)

        # FIXME: This must be done under lock.
        match_condition = self.headers.get("If-Match")
        current_generation = self._cache.get_generation(path)
        if (match_condition and
            current_generation != match_condition):
            os.unlink(local_filename)
            self.send_response(304)
            self.send_header("Content-Length", 0)
            self.send_header("ETag", '"%s"' % current_generation)
            self.end_headers()
            return

        self._cache.update_local_file_generation(
            path, generation, local_filename)

        self.send_response(200)
        self.send_header("Content-Length", 0)
        self.send_header("ETag", '"%s"' % generation)
        self.end_headers()

    def _direct_upload_file(self):
        # First upload the file to a temp directory, then move it into place at
        # once.
        fd, local_filename = tempfile.mkstemp()
        try:
            count = 0
            to_read = int(self.headers["content-length"])
            self._copy_bytes(self.rfile, fd, to_read)
        finally:
            os.close(fd)
        self._move_file_into_place(local_filename)
        self.session.logging.debug("Uploaded %s (%s)", self.base_path, count)

    def send_error(self, code, message=None, close=True):
        try:
            short, long = self.responses[code]
        except KeyError:
            short, long = '???', '???'
        if message is None:
            message = short
        explain = long
        content = (self.error_message_format %
                   {'code': code, 'message': cgi.escape(message),
                    'explain': explain})
        self.send_response(code, message)
        self.send_header("Content-Type", self.error_content_type)
        self.send_header('Content-Length', str(len(content)))
        if close:
            self.send_header('Connection', "close")

        self.end_headers()
        if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
            self.wfile.write(content)


class RekallHTTPServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    """The HTTP frontend server."""

    allow_reuse_address = True
    request_queue_size = 500

    address_family = socket.AF_INET6
    protocol_version = "HTTP/1.1"

    # Make sure its easier to kill the server.
    daemon_threads = True

    def __init__(self, server_address, handler, *args, **kwargs):
        self.session = kwargs.pop("session")
        (address, _) = server_address
        version = ipaddr.IPAddress(address).version
        if version == 4:
            self.address_family = socket.AF_INET
        elif version == 6:
            self.address_family = socket.AF_INET6

        BaseHTTPServer.HTTPServer.__init__(
            self, server_address, handler, *args, **kwargs)


def CreateServer(session=None):
    """Start frontend http server."""
    config = session.GetParameter("agent_config_obj")
    httpd = None
    for port in range(config.server.bind_port, config.server.port_max + 1):
        server_address = (config.server.bind_address, port)
        try:
            httpd = RekallHTTPServer(
                    server_address, RekallHTTPServerHandler, session=session)
            break
        except socket.error as e:
            if (e.errno == socket.errno.EADDRINUSE and
                port < config.server.port_max):
                session.logging.info(
                    "Port %s in use, trying %s", port, port + 1)
            else:
                raise

    if not httpd:
        raise RuntimeError("Unable to create http server.")

    sa = httpd.socket.getsockname()
    session.logging.info("Serving HTTP on %s port %d ...", sa[0], sa[1])
    return httpd


class RekallAgentHTTPServer(common.AbstractAgentCommand):
    """A plugin to create a front end server."""
    name = "http_server"

    __args = [
    ]

    def collect(self):
        httpd = CreateServer(session=self.session)
        httpd.serve_forever()
