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

"""Location handlers for the Cloud.

This module provides the ability to write to Google Cloud Storage in various
ways.
"""

import base64
import contextlib
import json
import gzip
import os
import rfc822
import StringIO
import urllib
import tempfile
import time

from wsgiref import handlers

import arrow
import httplib2
import requests
from requests import adapters

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives import serialization

from oauth2client import service_account as service_account_module

from rekall import utils
from rekall_agent import common
from rekall_agent import location
from rekall_agent import serializer

__author__ = "Michael Cohen <scudette@google.com>"


MAX_BUFF_SIZE = 10*1024*1024


class ServiceAccount(common.AgentConfigMixin, serializer.SerializedObject):
    """A GCS service account is an entity with delegation privileges.

    A Service account is used for the creation of GCSSignedURLLocation and
    GCSSignedPolicyLocation. Both of these Location objects allow the possessor
    of these to upload files to specific buckets.

    You can obtain a service account from the Google Cloud Console:
    1) Select IAM and admin, Service accounts -> Create Service Account.
    2) Select Role: "Storage Object Admin".
    3) Select "Furnish a new private key" and export to JSON.

    Store the json file and provide the path to it to the
    agent_server_initialize_gcs plugin.
    """

    schema = [
        dict(name="type",
             doc="The type of account (should be 'service_account')"),
        dict(name="private_key", hidden=True),
        dict(name="client_email"),
    ]

    def _sign_blob(self, blob):
        key = serialization.load_pem_private_key(
            str(self.private_key), password=None, backend=openssl.backend)
        signer = key.signer(padding.PKCS1v15(), hashes.SHA256())

        signer.update(str(blob))
        return signer.finalize()

    _scopes = ["https://www.googleapis.com/auth/devstorage.full_control"]
    _oauth_token = None
    _oauth_token_age = 0

    @utils.safe_property
    def oauth_token(self):
        # The google api and oauth2client libraries use httplib2 instead of
        # requests. Unfortunately httplib2 is terrible (not thread safe, no
        # streaming interface) so we just grab the access_token from the
        # credentials object and use it directly in the requests library anyway.
        max_lifetime = (service_account_module.ServiceAccountCredentials.
                        MAX_TOKEN_LIFETIME_SECS)

        # Refresh token at least this often.
        if (self._oauth_token is None or
            self._oauth_token_age < time.time() - max_lifetime / 2):
            credentials = (service_account_module.
                           ServiceAccountCredentials.
                           from_json_keyfile_dict(
                               self.to_primitive(False),
                               scopes=self._scopes))

            # Its ok to use httplib2 just for refreshing the tokens.
            http = httplib2.Http()
            credentials.refresh(http)

            self._oauth_token = credentials.access_token
            self._oauth_token_age = time.time()

        return self._oauth_token

    def create_oauth_location(self, path="", bucket=None, public=False):
        # If the bucket is not specified take it from the server's config.
        if bucket is None:
            bucket = self._config.server.bucket

        headers = GCSHeaders(session=self._session)
        if public:
            headers.SetMember("x-goog-acl", "public-read")

        return GCSOAuth2BasedLocation.from_keywords(
            session=self._session, bucket=bucket, path=path,
            headers=headers)

    def create_signed_policy_location(self, expiration=None, path_prefix=None,
                                      bucket=None, path_template=None):
        """Generate a GCSSignedPolicyLocation object.

        The generated Location object grants its possessor the respected acl
        rights for all paths starting with the specified prefix. Note that
        GCSSignedPolicyLocation is only useful for writing.

        https://cloud.google.com/storage/docs/xml-api/post-object#policydocument
        """
        if expiration is None:
            expiration = int(time.time()) + 60 * 60

        # If the bucket is not specified take it from the server's config.
        if bucket is None:
            bucket = self._config.server.bucket

        policy = dict(expiration=arrow.get(expiration).isoformat(),
                      conditions=[
                          ["starts-with", "$key",
                           utils.join_path(bucket, path_prefix)],
                          {"bucket": bucket},
                          {"Content-Encoding": "gzip"},
                      ])

        encoded_policy = json.dumps(policy, sort_keys=True)
        signature = self._sign_blob(base64.b64encode(encoded_policy))

        return GCSSignedPolicyLocation.from_keywords(
            session=self._session,
            policy=encoded_policy,
            signature=signature,
            bucket=bucket,
            path_prefix=path_prefix,
            path_template=path_template,
            GoogleAccessId=self.client_email,
            expiration=expiration)

    def create_signed_url_location(
            self, mode="r", expiration=None, path=None, bucket=None,
            upload="direct", headers=None, public=False):
        """A Factory for GCSSignedURLLocation() instances.

        Args:
          mode: Can be "r" for reading, "w" for writing.
          expiration: When this URL should expire. By default 1 hour.
          path: The path within the bucket for the object.
          bucket: The bucket name.
        """
        if headers is None:
            headers = GCSHeaders(session=self._session)
            if public:
                headers.SetMember("x-goog-acl", "public-read")
        elif isinstance(headers, dict):
            headers = GCSHeaders.from_primitive(
                headers, self._session)

        if mode == "r":
            method = "GET"

        elif mode == "w":
            method = "PUT"

            if upload == "resumable":
                method = "POST"
                # Resumable uploads require these headers.
                headers.SetMember("x-goog-resumable", "start")

        else:
            raise IOError("Mode not supported")

        if expiration is None:
            # Default 1 hour from now.
            expiration = time.time() + 60 * 60

        # If the bucket is not specified take it from the server's config.
        if bucket is None:
            bucket = self._config.server.bucket

        # Build the signed string according to
        # https://cloud.google.com/storage/docs/access-control/signed-urls#string-components
        components = []
        components.append(method)  # HTTP_Verb
        components.append("")    # Content_MD5
        components.append("")    # Content_Type
        components.append(str(int(expiration))) # Expiration
        for k, v in sorted(headers.to_primitive(False).iteritems()):
            components.append("%s:%s" % (k, v))

        path = urllib.quote(path, safe="/:")
        base_url = "/" + utils.join_path(bucket, path)

        components.append(base_url)  # Canonicalized_Resource

        signature_string = "\n".join(components)
        return GCSSignedURLLocation.from_keywords(
            session=self._session,
            signature=self._sign_blob(signature_string),
            GoogleAccessId=self.client_email,
            expiration=expiration,
            bucket=bucket,
            path=path,
            method=method,
            headers=headers,
            upload=upload,
            )


class GCSLocation(location.Location):
    """The location for the base of the installation on GCS."""
    schema = [
        dict(name="bucket",
             doc="Name of the bucket"),

        dict(name="upload", type="choices", default=u"direct", hidden=True,
             choices=[u"direct", u"resumable"],
             doc="Type of upload mechanism."),

        dict(name="path",
             doc="The path to the object in the bucket."),
    ]

    def __init__(self, *args, **kwargs):
        super(GCSLocation, self).__init__(*args, **kwargs)
        self._cache = self._config.server.cache

    def get_canonical(self, **_):
        return GCSLocation.from_keywords(
            session=self._session,
            bucket=self.bucket,
            path=self.path)

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

    def _get_parameters(self, **_):
        """Get request parameters.

        To be overridden by derived classes.

        Returns
          Tuple of url, parameters, headers
        """
        raise NotImplementedError()


    def read_file(self, completion_routine=None, **kw):
        if self._cache:
            try:
                local_filename = self.get_local_filename(**kw)
                with open(local_filename, "rb") as fd:
                    return fd.read(MAX_BUFF_SIZE)
            except IOError:
                return ""

        # We need to download the file.
        url_endpoint, params, headers, _ = self._get_parameters(
            **kw)

        resp = self.get_requests_session().get(
            url_endpoint, params=params, headers=headers)

        if not resp.ok:
            return self._report_error(completion_routine, resp)

        return resp.content

    def write_file(self, data, **kwargs):
        return self.upload_file_object(StringIO.StringIO(data), **kwargs)

    def _upload_direct(self, fd, completion_routine=None, **kwargs):
        url_endpoint, params, headers, _ = self._get_parameters(**kwargs)

        headers["Content-Encoding"] = "gzip"
        resp = self.get_requests_session().put(
            url_endpoint, data=GzipWrapper(self._session, fd),
            params=params, headers=headers)

        self._session.logging.debug("Uploaded file: %s (%s bytes)",
                                    self.to_path(), fd.tell())

        return self._report_error(completion_routine, resp)

    def _upload_resumable(self, fd, completion_routine=None, **kwargs):
        url_endpoint, params, headers, _ = self._get_parameters(**kwargs)

        fd.seek(0, 2)
        file_length = fd.tell()
        fd.seek(0)

        params["name"] = url_endpoint
        params["uploadType"] = "resumable"

        headers["x-goog-resumable"] = "start"
        headers["Content-Length"] = "0"

        resp = self.get_requests_session().post(
            url_endpoint, params=params, headers=headers)

        # The server will now tell us where to write the chunks.
        try:
            upload_location = resp.headers["Location"]
        except KeyError:
            self._session.logging.error("Unable to upload file: %s", resp.text)
            return self._report_error(completion_routine, resp)

        # Blocksize must be a multiple of 256kb.
        BLOCK_SIZE = 256 * 1024 * 5

        while 1:
            offset = fd.tell()
            data = fd.read(BLOCK_SIZE)
            if not data:
                break

            headers = {

        "Content-Length": str(len(data)),
                "Content-Range": "bytes %d-%d/%d" % (
                    offset, offset + len(data) -1, file_length)
            }
            resp = self.get_requests_session().put(
                upload_location, data=data, headers=headers)

            self._session.report_progress(
                "%s: Uploaded %s/%s", self.to_path(), offset, file_length)

        return self._report_error(completion_routine, resp)

    def upload_file_object(self, fd, completion_routine=None, **kwargs):
        if self.upload == "direct":
            return self._upload_direct(
                fd, completion_routine=completion_routine, **kwargs)

        # Resumable upload
        elif self.upload == "resumable":
            self._upload_resumable(
                fd, completion_routine=completion_routine, **kwargs)

        else:
            self._report_error(completion_routine,
                               message="Unknown upload method")

    def upload_local_file(self, local_filename=None, fd=None,
                          completion_routine=None, delete=True, **kwargs):
        if local_filename:
            fd = open(local_filename, "rb")

        result = self.upload_file_object(
            fd, completion_routine=completion_routine, **kwargs)

        if delete and local_filename:
            os.unlink(local_filename)

        return result

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

    def list_files(self, **kwargs):
        """A generator of Location object below this one."""
        raise NotImplementedError()

    def to_path(self):
        return utils.join_path(self.bucket, self.path)

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

class GCSHeaders(serializer.SerializedObject):

    """Some headers that can be set."""
    schema = [
        dict(name="x-goog-resumable"),
        dict(name="x-goog-acl"),
        dict(name="Content-Encoding"),
    ]


class GCSOAuth2BasedLocation(GCSLocation):
    """This location uses the regular Oauth2 based mechanism.

    This only works on the server with a valid ServiceAccount credential but
    allows us to use the full JSON based API.
    """
    schema = [
        dict(name="headers", type=GCSHeaders, hidden=True),
        dict(name="generation", hidden=True),
    ]

    def _get_parameters(self, if_modified_since=None, generation=None, **_):
        """Calculates the params for the request."""
        base_url = self.to_path()

        url_endpoint = ('https://storage.googleapis.com/%s' % base_url)

        headers = self.headers.to_primitive(False)
        headers["Authorization"] = (
            "Bearer " + self._config.server.service_account.oauth_token)
        headers["Cache-Control"] = "private"
        if if_modified_since:
            headers["If-Modified-Since"] = handlers.format_date_time(
                if_modified_since)

        params = {}
        generation = generation or self.generation
        if generation:
            params["generation"] = generation

        return url_endpoint, params, headers, base_url

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

                headers["Content-Encoding"] = "gzip"
                resp = self.get_requests_session().put(
                    url_endpoint, data=GzipWrapper(
                        self._session, open(local_filename, "rb")),
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

    def stat(self, **kwargs):
        """Gets information about an object."""
        url_endpoint, params, headers, _ = self._get_parameters(**kwargs)
        resp = self.get_requests_session().head(
            url_endpoint, params=params, headers=headers)

        if resp.ok:
            return location.LocationStat.from_keywords(
                session=self._session,
                location=self,
                size=resp.headers["x-goog-stored-content-length"],
                generation=resp.headers["x-goog-generation"],
                created=arrow.Arrow(*(rfc822.parsedate(
                    resp.headers["Last-Modified"])[:7])).timestamp,
           )

    def delete(self, completion_routine=None, **kwargs):
        """Deletes the current location."""
        url_endpoint, params, headers, _ = self._get_parameters(**kwargs)
        resp = self.get_requests_session().delete(
            url_endpoint, params=params, headers=headers)

        return self._report_error(completion_routine, resp)

    def list_files(self, completion_routine=None, paging=100,
                   max_results=100, **kwargs):
        """A generator of Location object below this one."""
        _, params, headers, _ = self._get_parameters(**kwargs)
        url_endpoint = ("https://www.googleapis.com/storage/v1/b/%s/o" %
                        self.bucket)

        params["prefix"] = utils.join_path(self.path)
        params["maxResults"] = paging
        count = 0
        while count < max_results:
            resp = self.get_requests_session().get(
                url_endpoint, params=params, headers=headers)

            if not resp.ok:
                self._report_error(completion_routine, resp)
                return

            data = json.loads(resp.text)
            items = data.get("items", [])
            for item in items:
                sublocation = self.copy()
                sublocation.path = item["name"]
                sublocation.generation = item["generation"]

                count += 1
                yield location.LocationStat.from_keywords(
                    session=self._session,
                    location=sublocation,
                    size=item["size"],
                    generation=item["generation"],
                    created=arrow.get(item["timeCreated"]).timestamp,
                    updated=arrow.get(item["updated"]).timestamp)

            next_page_token = data.get("nextPageToken")
            if not next_page_token or not items:
                break

            params["pageToken"] = next_page_token


class GCSUnauthenticatedLocation(GCSLocation):
    """A read only, unauthenticated location."""

    def _get_parameters(self, if_modified_since=None):
        base_url = self.to_path()

        url_endpoint = ('https://storage.googleapis.com/%s' %
                        base_url.lstrip("/"))

        headers = {"Cache-Control": "private"}
        if if_modified_since:
            headers["If-Modified-Since"] = handlers.format_date_time(
                if_modified_since)

        return url_endpoint, {}, headers, base_url

    def read_file(self, **kw):
        url_endpoint, _, headers, _ = self._get_parameters(**kw)

        resp = self.get_requests_session().get(
            url_endpoint, headers=headers)

        if resp.ok:
            return resp.content

        return ""


class GCSSignedURLLocation(GCSLocation):
    """A Location object which can be used to access a signed URL."""

    schema = [
        dict(name="method", type="choices", default="GET", hidden=True,
             choices=["GET", "POST", "PUT"]),
        dict(name="signature", type="str", hidden=True,
             doc="The signature to use when accessing the resource."),
        dict(name="GoogleAccessId", hidden=True,
             doc="The email form of the service account id"),
        dict(name="expiration", type="int",
             doc="When the url expires."),
        dict(name="headers", type=GCSHeaders, hidden=True),
    ]

    def _get_parameters(self):
        """Calculates the params for the request."""
        base_url = self.to_path()
        url_endpoint = ('https://storage.googleapis.com/%s' %
                        base_url.lstrip("/"))
        params = dict(GoogleAccessId=self.GoogleAccessId,
                      Expires="%d" % self.expiration,
                      Signature=base64.b64encode(self.signature))

        headers = self.headers.to_primitive(False)

        return url_endpoint, params, headers, base_url

    def read_file(self, **kwargs):
        if self.method != "GET":
            raise IOError("GCSSignedURLLocation is not created for reading.")
        return super(GCSSignedURLLocation, self).read_file(**kwargs)

    def write_file(self, data, **kwargs):
        if self.method != "PUT":
            raise IOError("GCSSignedURLLocation is not created for writing.")

        return super(GCSSignedURLLocation, self).write_file(data, **kwargs)

    def get_local_filename(self, completion_routine=None, **kwargs):
        if self.method != "GET":
            raise IOError("Unable to read file. This location is "
                          "only opened for Writing.")

        return super(GCSSignedURLLocation, self).get_local_filename(
            completion_routine=completion_routine, **kwargs)


class GzipWrapper(object):
    """Wrap an fd to produce a compressed stream from it."""
    BUFFER_SIZE = 1024 * 1024

    def __init__(self, session, infd):
        self.session = session
        self.total_read = 0
        self.infd = infd
        self.buff = ""
        self.zipper = gzip.GzipFile(mode="wb", fileobj=self)

    def write(self, data):
        """This function is called by the GzipFile writer."""
        self.buff += data

    def read(self, length=10000000000):
        """This is called by readers if this wrapper."""
        # Read infd until we have length available in self.buff.
        while self.zipper and len(self.buff) < length:
            data = self.infd.read(self.BUFFER_SIZE)
            if not data and self.zipper:
                # infd is finished.
                self.zipper.flush()
                self.zipper.close()
                self.zipper = None
                break

            self.total_read += len(data)
            self.session.report_progress("Read %s bytes", self.total_read)
            self.zipper.write(data)

        result, self.buff = self.buff[:length], self.buff[length:]

        return result

    def flush(self):
        pass

    def __iter__(self):
        while 1:
            data = self.read(self.BUFFER_SIZE)
            if not data:
                break

            yield data


class GCSSignedPolicyLocation(GCSLocation):
    """A Location object which uses a policy to access a URL."""

    schema = [
        dict(name="policy", type="str", hidden=True,
             doc="The policy document."),

        dict(name="signature", type="str", hidden=True,
             doc="The signature to use when accessing the resource."),

        dict(name="path_prefix",
             doc="Access is allowed to all paths starting with this prefix."),

        dict(name="path_template",
             doc="A template from which to expand the complete path."),

        dict(name="GoogleAccessId", hidden=True,
             doc="The email form of the service account id"),

        dict(name="expiration", type="int",
             doc="When the url expires."),

        dict(name="headers", type=GCSHeaders, hidden=True),
    ]

    def expand_path(self, subpath="", **kwargs):
        """Expand the complete path using the client's config."""
        kwargs["client_id"] = self._config.client.writeback.client_id
        kwargs["nonce"] = self._config.client.nonce
        kwargs["subpath"] = subpath

        return self.path_template.format(**kwargs)

    def get_canonical(self, **kwargs):
        return GCSLocation.from_keywords(
            session=self._session,
            bucket=self.bucket,
            path=utils.join_path(self.path_prefix, self.expand_path(**kwargs))
        )

    def _get_parameters(self, **kwargs):
        """Calculates the params for the request."""
        subpath = self.expand_path(**kwargs)
        key = utils.join_path(self.bucket, self.path_prefix, subpath)

        url_endpoint = "https://storage.googleapis.com/"
        params = dict(GoogleAccessId=self.GoogleAccessId,
                      Signature=base64.b64encode(self.signature),
                      Policy=base64.b64encode(self.policy),
                      bucket=self.bucket,
                      key=key)

        params["content-encoding"] = "gzip"
        headers = {"content-encoding": "gzip"}

        return url_endpoint, params, headers, key

    def upload_file_object(self, fd, completion_routine=None, **kwargs):
        url_endpoint, params, headers, base_url = self._get_parameters(**kwargs)
        resp = self.get_requests_session().post(
            url_endpoint, params,
            files=dict(file=GzipWrapper(self._session, fd)),
            headers=headers)

        self._session.logging.debug(
            "Uploaded file: %s (%s bytes)", base_url, fd.tell())

        return self._report_error(completion_routine, resp)
