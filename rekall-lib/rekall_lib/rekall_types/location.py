from builtins import object
from rekall_lib import serializer


class Status(object):
    """Represents the status of a network operation."""

    def __init__(self, code=200, data=""):
        self.code = code
        self.data = data

    def ok(self):
        return self.code == 200


class Location(serializer.SerializedObject):
    """A type specifying a location to upload/download files."""

    # This one object can represent a number of location types.
    schema = []

    def to_path(self):
        return ""

    def read_file(self):
        """Gets the contents of location as a string."""
        raise NotImplementedError()

    def write_file(self, data):
        """Writes data to the location."""
        raise NotImplementedError()


class DevNull(Location):
    """Just swallow all data."""
    def write_file(self, data):
        pass

    def read_file(self):
        return ""


class FileLocation(Location):
    """A Location specifier that handles file paths on the local filesystem.

    Note that this does not work remotely and so it is mostly useful for tests.
    """
    schema = [
        dict(name="path_prefix",
             doc="The path prefix to enforce."),

        dict(name="path_template", default="",
             doc="The path template to expand."),
    ]


class HTTPLocation(Location):
    """A Location specifier that manages a remote HTTP connection.

    This location uses simple GET/POST to read/write smallish files over the
    network.
    """
    schema = [
        dict(name="base",
             doc="The base URL of the server."),
        dict(name="path_prefix",
             doc="The path to load"),
        dict(name="path_template", default="/",
             doc="The path template to expand."),
    ]


class BlobUploadSpecs(serializer.SerializedObject):
    """Sent by the server in the first BlobUploader exchange."""
    schema = [
        dict(name="url",
             doc="The URL to upload to."),
        dict(name="method", default="POST",
             doc="The method to upload (currently only POST)"),
        dict(name="name", default="file",
             doc="The uploaded filename to use"),
    ]


class BlobUploader(HTTPLocation):
    """An uploader of blobs.

    In order to upload a blob, the client needs to contact the server to receive
    an upload URL. This happens in two steps:

    1) The server initiates a read_file() request as per the HTTPLocation
       above. The response is parsed as a BlobUploadSpecs.

    2) The spec is used to perform the actual upload.
    """


class FileInformation(serializer.SerializedObject):
    schema = [
          dict(name="filename"),
          dict(name="st_size", type="int"),
      ]


class FileUploadRequest(serializer.SerializedObject):
    schema = [
        dict(name="flow_id"),
        dict(name="file_information", type=FileInformation),
        dict(name="sha1hash", doc="Used for deduping the file uploads")
    ]


class FileUploadResponse(serializer.SerializedObject):
    schema = [
        dict(name="action", type="choices",
             choices=["Upload", "Skip"], default="Upload"),
        dict(name="url"),
    ]


class FileUploadLocation(HTTPLocation):
    schema = [
        dict(name="flow_id"),
    ]


class NotificationLocation(HTTPLocation):
    """A location which notifies when it changes."""

    def Start(self, callback):
        """Start the loop. Never returns.

        callback is called with each notification.
        """
        raise NotImplementedError()
