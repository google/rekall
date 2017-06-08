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
import StringIO
from wsgiref import handlers

import requests
from requests import adapters
from rekall_lib.types import location
from rekall_lib import serializer
from rekall_lib import utils
from rekall import session
from rekall_agent import common


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


class HTTPLocationImpl(location.HTTPLocation):
    """A stand along HTTP server location."""

    def __init__(self, *args, **kwargs):
        super(HTTPLocationImpl, self).__init__(*args, **kwargs)
        if not isinstance(self._session, session.Session):
            raise TypeError("%s must be instantiated with a Rekall Session" %
                            self.__class__)

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

    def expand_path(self, **kwargs):
        """Expand the complete path using the client's config."""
        return self.path_template.format(
            **common.Interpolator(self._session, **kwargs))

    def to_path(self, **kwargs):
        return utils.join_path(self.path_prefix, self.expand_path(**kwargs))

    def _get_parameters(self, if_modified_since=None, **kwargs):
        if not self.path_prefix and not self.base:
            raise IOError("No base URL specified.")

        subpath = self.expand_path(**kwargs)
        if subpath:
            path = utils.join_path(self.path_prefix, subpath)
        else:
            path = self.path_prefix

        if path:
            base_url = _join_url(self.base, path)
        else:
            base_url = self.base

        headers = {
            "Cache-Control": "private",
        }

        if if_modified_since:
            headers["If-Modified-Since"] = handlers.format_date_time(
                if_modified_since)

        return base_url, {}, headers, path

    def read_file(self, **kw):
        url_endpoint, _, headers, _ = self._get_parameters(**kw)

        resp = self.get_requests_session().get(
            url_endpoint, headers=headers)

        if resp.ok:
            return resp.content

        return ""

    def write_file(self, data, **kwargs):
        return self.upload_file_object(StringIO.StringIO(data), **kwargs)

    def upload_file_object(self, fd, completion_routine=None, **kwargs):
        url_endpoint, params, headers, base_url = self._get_parameters(**kwargs)

        resp = self.get_requests_session().post(
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

        return location.Status(200, response.content)


class BlobUploaderImpl(HTTPLocationImpl, location.BlobUploader):

    def upload_file_object(self, fd, completion_routine=None, **kwargs):
        spec = location.BlobUploadSpecs.from_json(self.read_file(**kwargs))

        # Upload the file to the blob endpoint.
        resp = self.get_requests_session().post(
            spec.url, files={spec.name: fd})

        self._session.logging.debug("Uploaded file: %s (%s bytes)",
                                    spec.url, fd.tell())

        return self._report_error(completion_routine, resp)



class FileUploadLocationImpl(HTTPLocationImpl, location.FileUploadLocation):
    def upload_file_object(self, fd, file_information=None, **kw):
        """Upload a local file.

        Read data from fd. If file_information is provided, then we use this to
        report about the file.
        """
        if file_information is None:
            file_information = location.FileInformation.from_keywords(
                filename=fd.name,
            )

        request = location.FileUploadRequest.from_keywords(
            flow_id=self.flow_id,
            file_information=file_information)

        url_endpoint, _, headers, _ = self._get_parameters(**kw)

        resp = self.get_requests_session().post(
            url_endpoint, data=request.to_json(),
            headers=headers)

        if resp.ok:
            response = location.FileUploadResponse.from_json(resp.content)

            # Upload the file to the blob endpoint.
            self.get_requests_session().post(
                response.url, files={"file": fd})

            self._session.logging.debug("Uploaded file: %s (%s bytes)",
                                        file_information.filename, fd.tell())
