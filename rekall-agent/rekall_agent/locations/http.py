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

"""Location handlers for a stand alone HTTP server.
"""
import base64
import contextlib
import json
import StringIO
import os
import tempfile
import time
import urllib
from wsgiref import handlers

import requests
from requests import adapters
from rekall import utils
from rekall_agent import location
from rekall_agent import serializer

MAX_BUFF_SIZE = 10*1024*1024


class URLPolicy(serializer.SerializedObject):
    """Expresses the policy for managing URLs."""
    schema = [
        dict(name="path_prefix",
             doc="The path prefix to enforce."),

        dict(name="path_template", default="",
             doc="The path template to expand."),

        dict(name="expires", type="epoch",
             doc="When does this policy expire"),

        dict(name="access", type="choices", repeated=True, default=["READ"],
             choices=["READ", "WRITE", "LIST"],
             doc="The allowed access pattern for this operation."),

        dict(name="public", type="bool",
             doc="If set the uploaded object will be public."),
    ]


def _join_url(base, *components):
    return base.rstrip("/") + "/" + utils.join_path(*components).lstrip("/")


class HTTPLocation(location.Location):
    """A stand along HTTP server location."""

    schema = [
        dict(name="base",
             doc="The base URL of the server."),

        dict(name="path_prefix",
             doc="The path to load"),
        dict(name="path_template", default="/",
             doc="The path template to expand."),

        dict(name="policy", type="str", hidden=True,
             doc="The policy blob"),

        dict(name="signature", type="str", hidden=True,
             doc="The signature to use when accessing the resource."),

        dict(name="path_template",
             doc="A template from which to expand the complete path."),

        dict(name="access", type="choices", repeated=True, default=["READ"],
             choices=["READ", "WRITE", "LIST"],
             doc="The allowed access pattern for this operation."),
    ]

    @classmethod
    def New(cls, path_prefix=None, access=None, session=None, expiration=None,
            path_template="", public=False):
        if expiration is None:
            expiration = time.time() + 60 * 60 * 24 * 7

        # By default we give read/write access.
        if access is None:
            access = ["READ", "WRITE"]

        # Make sure paths are always anchored.
        if not path_prefix.startswith("/"):
            path_prefix = "/" + path_prefix

        config = session.GetParameter("agent_config_obj")
        policy = URLPolicy.from_keywords(
            session=session,
            path_prefix=path_prefix,
            path_template=path_template,
            expires=expiration,
            public=public,
            access=access)

        policy_data = policy.to_json()
        signature = config.server.private_key.sign(policy_data)
        base = config.server.base_url
        if not base:
            raise RuntimeError("Unable to determine deployment base url.")

        return HTTPLocation.from_keywords(
            session=session,
            base=config.server.base_url,
            path_prefix=path_prefix,
            policy=policy_data,
            path_template=path_template,
            access=access,
            signature=signature)

    def __init__(self, *args, **kwargs):
        super(HTTPLocation, self).__init__(*args, **kwargs)
        self._cache = self._config.server.cache

    def get_canonical(self, **kwargs):
        return HTTPLocation.from_keywords(
            session=self._session,
            base=self.base,
            path_prefix=self.to_path(**kwargs))

    def get_requests_session(self):
        requests_session = self._session.GetParameter("requests_session")
        if requests_session == None:
            # To make sure we can use the requests session in the threadpool we
            # need to make sure that the connection pool can block. Otherwise it
            # will raise when it runs out of connections and the threads will be
            # terminated.
            requests_session = requests.Session()
            requests_session.mount("https://", adapters.HTTPAdapter(
                pool_connections=10, pool_maxsize=300, max_retries=10,
                pool_block=True))

            requests_session.mount("http://", adapters.HTTPAdapter(
                pool_connections=10, pool_maxsize=300, max_retries=10,
                pool_block=True))

            self._session.SetCache("requests_session", requests_session)

        return requests_session

    def expand_path(self, subpath="", **kwargs):
        """Expand the complete path using the client's config."""
        kwargs["client_id"] = self._config.client.writeback.client_id
        kwargs["nonce"] = self._config.client.nonce
        #kwargs["subpath"] = urllib.quote_plus(
        #    subpath.replace("\\", "/"), safe="/")

        kwargs["subpath"] = subpath

        return self.path_template.format(**kwargs)

    def to_path(self, **kwargs):
        return utils.join_path(self.path_prefix, self.expand_path(**kwargs))

    def _get_parameters(self, if_modified_since=None, **kwargs):
        subpath = self.expand_path(**kwargs)
        path = utils.join_path(self.path_prefix, subpath)
        base_url = _join_url(self.base, path)
        headers = {
            "Cache-Control": "private",
            "x-rekall-policy": base64.b64encode(self.policy),
            "x-rekall-signature": base64.b64encode(self.signature),
        }

        if if_modified_since:
            headers["If-Modified-Since"] = handlers.format_date_time(
                if_modified_since)

        return base_url, {}, headers, path

    def read_file(self, **kw):
        if "READ" not in self.access:
            raise IOError("HTTPLocation is not created for reading.")

        url_endpoint, _, headers, _ = self._get_parameters(**kw)

        resp = self.get_requests_session().get(
            url_endpoint, headers=headers)

        if resp.ok:
            return resp.content

        return ""

    def write_file(self, data, **kwargs):
        if "WRITE" not in self.access:
            raise IOError("HTTPLocation is not created for writing.")

        return self.upload_file_object(StringIO.StringIO(data), **kwargs)

    def upload_file_object(self, fd, completion_routine=None, **kwargs):
        url_endpoint, params, headers, base_url = self._get_parameters(**kwargs)

        resp = self.get_requests_session().put(
            url_endpoint, data=fd,
            params=params, headers=headers)

        self._session.logging.debug("Uploaded file: %s (%s bytes)",
                                    base_url, fd.tell())

        return self._report_error(completion_routine, resp)

    def _report_error(self, completion_routine, response=None,
                      message=None):
        if response:
            # Only include the text in case of error.
            if not response.ok:
                status = location.Status(response.status_code, response.text)
            else:
                status = location.Status(response.status_code)

        else:
            status = location.Status(500, message)

        if response is None or not response.ok:
            if completion_routine:
                return completion_routine(status)

            raise IOError(response.text)
        else:
            if completion_routine:
                completion_routine(status)

        return response.ok

    def list_files(self, max_results=100, **kw):
        url_endpoint, params, headers, _ = self._get_parameters(**kw)
        params["action"] = "list"
        params["limit"] = max_results
        resp = self.get_requests_session().get(
            url_endpoint, params=params, headers=headers)

        if resp.ok:
            for stat in json.loads(resp.text):
                yield location.LocationStat.from_primitive(
                    stat, session=self._session)

    def stat(self, **kw):
        url_endpoint, params, headers, _ = self._get_parameters(**kw)
        params["action"] = "stat"
        resp = self.get_requests_session().get(
            url_endpoint, params=params, headers=headers)

        if resp.ok:
            return location.LocationStat.from_primitive(
                json.loads(resp.text), session=self._session)

    def delete(self, completion_routine=None, **kw):
        url_endpoint, params, headers, _ = self._get_parameters(**kw)
        params["action"] = "delete"
        resp = self.get_requests_session().get(
            url_endpoint, params=params, headers=headers)

        return self._report_error(completion_routine, resp)

    def get_local_filename(self, completion_routine=None, **kwargs):
        # We need to download the file locally.
        url_endpoint, params, headers, base_url = self._get_parameters(
            **kwargs)
        current_generation = self._cache.get_generation(base_url)
        if current_generation:
            headers["If-None-Match"] = current_generation

        with contextlib.closing(
                self.get_requests_session().get(
                    url_endpoint, params=params, headers=headers,
                    stream=True)) as resp:

            # Object not modified just return the cached object.
            if resp.status_code == 304:
                return self._cache.get_local_file(base_url, current_generation)

            if not resp.ok:
                # The file was removed from the server, make sure to expire the
                # local copy too.
                if resp.status_code == 404:
                    self._cache.expire(base_url)
                return self._report_error(completion_routine, resp)

            # Store the generation of this object in the cache.
            current_generation = json.loads(resp.headers["ETag"])
            filename = self._cache.store_at_generation(
                base_url, current_generation,
                iterator=resp.iter_content(chunk_size=1024*1024))

            # Report success.
            self._report_error(completion_routine, resp)

        return filename

    def read_modify_write_local_file(self, modification_cb, *args):
        """Atomically modifies this location.

        We first download this object to the local filesystem cache, then we
        modify it and then try to upload. If another modification occurred we
        replay the callback until success.

        Note that the modification_cb will be called with the filename to
        modify. It may be called multiple times.
        """
        url_endpoint, _, headers, base_url = self._get_parameters()
        for retry in range(5):
            local_file_should_be_removed = False
            current_generation = None
            try:
                try:
                    local_filename = self.get_local_filename()

                    # The current generation in the cache.
                    current_generation = self._cache.get_generation(base_url)
                except IOError:
                    # File does not exist on the server, make a tmpfile.
                    fd, local_filename = tempfile.mkstemp()
                    os.close(fd)

                    # Dont forget to remove the tempfile.
                    local_file_should_be_removed = True

                # Now let the callback modify the file.
                modification_cb(local_filename, *args)

                # We may only write if this is the current generation.
                if current_generation:
                    headers["If-Match"] = current_generation

                resp = self.get_requests_session().put(
                    url_endpoint, data=open(local_filename, "rb"),
                    headers=headers)

                # OK - all went well.
                if resp.ok:
                    new_generation = json.loads(resp.headers["ETag"])
                    # Update the cache into a new generation.
                    self._cache.update_local_file_generation(
                        base_url, new_generation, local_filename)

                    # Do not remove the local file because it was moved by the
                    # cache.
                    local_file_should_be_removed = False
                    self._session.logging.info("Modified: %s", self.to_path())
                    return True

                # The generation on the server has changed. Abort, wait a bit
                # and retry.
                if resp.status_code == 304:
                    time.sleep(0.1 * retry)
                    continue

            finally:
                if local_file_should_be_removed:
                    os.unlink(local_filename)

            raise IOError("Unable to update %s" % self)

    def read_modify_write(self, modification_cb, *args):
        """Atomically modify this location in a race free way.

        modification_cb will receive the content of the file, and passed args
        and should return the new content of the file.

        Note that modification_cb can be called several times if a lock failure
        is detected.

        The underlying implementation is described here:
        https://cloud.google.com/storage/docs/object-versioning
        """
        def cb(filename, modification_cb, *args):
            with open(filename, "rb") as fd:
                data = fd.read()

            new_data = modification_cb(data, *args)

            # Update the file.
            with open(filename, "wb") as fd:
                fd.write(new_data)

        self.read_modify_write_local_file(cb, modification_cb, *args)

    def upload_local_file(self, local_filename=None, fd=None,
                          completion_routine=None, delete=True, **kwargs):
        if local_filename:
            fd = open(local_filename, "rb")

        result = self.upload_file_object(
            fd, completion_routine=completion_routine, **kwargs)

        if delete and local_filename:
            os.unlink(local_filename)

        return result
