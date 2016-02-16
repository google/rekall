# Rekall Memory Forensics
# Copyright 2013 Google Inc. All Rights Reserved.
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

"""IO Abstraction for Rekall.

Since Rekall is a library it should never directly access files: it may be
running on an environment which has no filesystem access for example, or the
files may be stored in an unusual way.

In order to ensure that the file storage mechanism does not need to be hardcoded
in each module, Rekall has an abstracted filesystem access mechanism implemented
through the IO Manager.

The session object should contain an instance of the IOManager() class at the
io_manager attribute, which will be used to create new files, or read from
existing files.
"""

__author__ = "Michael Cohen <scudette@google.com>"

import StringIO
import gzip
import json
import time
import os
import shutil
import urllib2
import urlparse
import zipfile

from rekall import constants
from rekall import obj
from rekall import registry
from rekall import utils

# The maximum size of a single data object we support. This represent the
# maximum amount of data we are prepared to read into memory at once.
MAX_DATA_SIZE = 100000000


class IOManagerError(IOError):
    """An IOError from the IO Manager."""


class EncodeError(IOError):
    """Raised when unable to encode to the IO Manager."""


class DecodeError(IOError):
    """Raised when unable to decode to the IO Manager."""


class IOManager(object):
    """The baseclass for abstracted IO implementations.

    The IO manager classes are responsible for managing access to profiles. A
    profile is a JSON dict which is named using a standard notation. For
    example, the profile for a certain NT kernel is:

    nt/GUID/BF9E190359784C2D8796CF5537B238B42

    The IO manager may actually store the profile file using some other scheme,
    but that internal scheme is private to itself.
    """

    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    order = 100

    def __init__(self, urn=None, mode="r", session=None, pretty_print=True,
                 version=constants.PROFILE_REPOSITORY_VERSION):
        """Initialize the IOManager.

        Args:

          urn: The path to the IO manager. This might contain a scheme or
               protocol specific to a certain IO manager implementation.

          mode: Can be "r" or "w".

          session: The session object.

          pretty_print: If specified we dump sorted yaml data - this ends up
          being more compressible in reality.

          version: The required version of the repository. The IOManager is free
               to implement arbitrary storage for different versions if
               required. Versioning the repository allows us to update the
               repository file format transparently without affecting older
               Rekall versions.

        """
        self.mode = mode
        self.urn = urn
        self.version = version
        if session == None:
            raise RuntimeError("Session must be set")

        self.session = session
        self.pretty_print = pretty_print
        self._inventory = None
        self.location = ""
        self._dirty = False

    @utils.safe_property
    def inventory(self):
        if self._inventory is None:
            self._inventory = self.GetData("inventory", default={})

        return self._inventory

    def ValidateInventory(self):
        try:
            metadata = self.inventory.get("$METADATA")
            if (metadata.get("ProfileClass") == "Inventory"
                    and metadata.get("Type") == "Inventory"):
                return True
        except (AttributeError, IndexError, ValueError):
            pass

        self.session.logging.warn(
            'Inventory for repository "%s" seems malformed. Are you behind a '
            'captive portal or proxy? If this is a custom repository, did you '
            'forget to create an inventory? You must use the '
            'tools/profiles/build_profile_repo.py tool with the --inventory '
            'flag.', self.location or self.urn)

        # If the profile didn't validate, we still fix it so subsequent calls
        # won't generate additional errors. StoreData and FlushInventory also
        # rely on this behaviour.
        if not self._inventory:
            self._inventory = {
                "$METADATA": dict(
                    Type="Inventory",
                    ProfileClass="Inventory"),
                "$INVENTORY": {},
            }

        return False

    def CheckInventory(self, path):
        """Checks the validity of the inventory and if the path exists in it.

        The inventory is a json object at the root of the repository which lists
        all the profiles in this repository. It allows us to determine quickly
        if a profile exists in this repository.
        """
        if self.ValidateInventory():
            return path in self.inventory.get("$INVENTORY")

        return False

    def Metadata(self, path):
        """Returns metadata about a path."""
        inventory = self.inventory.get("$INVENTORY", {})
        return inventory.get(path, {})

    def SetMetadata(self, name, options):
        existing_options = self.Metadata(name)
        existing_options.update(options)
        self.inventory.setdefault("$INVENTORY", {})[name] = existing_options
        self.FlushInventory()

    def FlushInventory(self):
        """Write the inventory to the storage."""
        if not self._dirty:
            return

        self.inventory.setdefault("$METADATA", dict(
            Type="Inventory",
            ProfileClass="Inventory"))
        self.inventory.setdefault("$INVENTORY", dict())

        self.StoreData("inventory", self.inventory)
        self._dirty = False

    def ListFiles(self):
        """Returns a generator over all the files in this container."""
        return []

    def Create(self, name, **options):
        """Creates a new file in the container.

        Returns a file like object which should support the context manager
        protocol. If the file already exists in the container, overwrite it.

        For example:

        with self.session.io_manager.Create("foobar") as fd:
           fd.Write("hello world")

        Args:
          name: The name of the new file.
        """

    def Destroy(self, name):
        """Destroys the file/directory at name's path."""

    def Open(self, name):
        """Opens a container member for reading.

        This should return a file like object which provides read access to
        container members.

        Raises:
          IOManagerError: If the file is not found.
        """

    def Encoder(self, data, **options):
        if options.get("raw"):
            return utils.SmartStr(data)

        if self.pretty_print:
            return utils.PPrint(data)

        return json.dumps(data, sort_keys=True, **options)

    def Decoder(self, raw):
        return json.loads(raw)

    def GetData(self, name, raw=False, default=None):
        """Get the data object stored at container member.

        This returns an arbitrary python object which is stored in the named
        container member. For example, normally a dict or list. This function
        wraps the Open() method above and add deserialization to retrieve the
        actual object.

        Returns None if the file is not found.

        Args:
          name: The name to retrieve the data under.
          raw: If specified we do not parse the data, simply return it as is.
        """
        if default is None:
            default = obj.NoneObject()

        try:
            fd = self.Open(name)
            data = fd.read(MAX_DATA_SIZE)
            if raw:
                return data

            return self.Decoder(data)

        except IOError:
            return default

        except Exception as e:
            self.session.logging.error(
                "Cannot parse profile %s because of decoding error '%s'.",
                name, e)
            return default

    def StoreData(self, name, data, **options):
        """Stores the data in the named container member.

        This serializes the data and stores it in the named member. Not all
        types of data are serializable, so this may raise. For example, when
        using JSON to store the data, arbitrary python objects may not be used.

        Args:
          name: The name under which the data will be stored.
          data: The data to store.

        Common options:
          raw: If true we write the data directly without encoding to json. In
            this case data should be a string.
          uncompressed: File will not be compressed (default gzip compression).
        """
        try:
            to_write = self.Encoder(data, **options)
        except EncodeError:
            self.session.logging.error("Unable to serialize %s", name)
            return

        self._StoreData(name, to_write, **options)

        # Update the inventory.
        if name != "inventory":
            self.inventory.setdefault("$INVENTORY", {})[name] = dict(
                LastModified=time.time())

            self.FlushInventory()

    def _StoreData(self, name, to_write, **options):
        with self.Create(name, **options) as fd:
            fd.write(to_write)
            self._dirty = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass


class DirectoryIOManager(IOManager):
    """An IOManager which stores everything in files.

    We prefer to store the profile file as a gzip compressed file within a
    versioned directory. For example the profile:

    nt/GUID/BF9E190359784C2D8796CF5537B238B42

    will be stored in:

    $urn/nt/GUID/BF9E190359784C2D8796CF5537B238B42.gz

    Where $urn is the path where the DirectoryIOManager was initialized with.
    """

    # Any paths beginning with these prefixes will not be included in the
    # inventory.
    EXCLUDED_PATH_PREFIX = []

    def __init__(self, urn=None, **kwargs):
        super(DirectoryIOManager, self).__init__(**kwargs)
        self.location = self.dump_dir = os.path.normpath(os.path.abspath(
            os.path.expandvars(urn)))
        if not self.version:
            self.version = ""

        self.check_dump_dir(self.dump_dir)
        self.canonical_name = os.path.basename(self.dump_dir)

    @utils.safe_property
    def inventory(self):
        # In DirectoryIOManager the inventory reflects the directory structure.
        if self._inventory is None:
            self._inventory = self.GetData("inventory", default={})
            if not self._inventory:
                self._inventory = self.RebuildInventory()

        return self._inventory

    def RebuildInventory(self):
        """Rebuild the inventory file."""
        result = {
            "$METADATA": dict(
                Type="Inventory",
                ProfileClass="Inventory"),
            "$INVENTORY": {},
        }
        for member in self.ListFiles():
            if not self._is_excluded_member(member):
                result["$INVENTORY"][member] = self.Metadata(member)

        return result

    def _is_excluded_member(self, member):
        for prefix in self.EXCLUDED_PATH_PREFIX:
            if member.startswith(prefix):
                return True

    def CheckInventory(self, path):
        """Checks the validity of the inventory and if the path exists in it.

        The inventory is a json object at the root of the repository which lists
        all the profiles in this repository. It allows us to determine quickly
        if a profile exists in this repository.
        """
        if self.ValidateInventory():
            path = self.GetAbsolutePathName(path)
            return os.access(path, os.R_OK) or os.access(path + ".gz", os.R_OK)
        return False

    def Metadata(self, path):
        path = self.GetAbsolutePathName(path)
        try:
            try:
                st = os.stat(path + ".gz")
            except OSError:
                if os.path.isdir(path):
                    return {}

                st = os.stat(path)

            return dict(LastModified=st.st_mtime)
        except OSError:
            return {}

    def check_dump_dir(self, dump_dir=None):
        if not dump_dir:
            raise IOManagerError("Please specify a dump directory.")

        if self.mode == "w":
            self.EnsureDirectoryExists(self.dump_dir)

        if not os.path.isdir(dump_dir):
            raise IOManagerError("%s is not a directory" % self.dump_dir)

    def GetAbsolutePathName(self, name):
        path = os.path.normpath(
            os.path.join(self.dump_dir, self.version, name))

        if not path.startswith(self.dump_dir):
            raise IOManagerError("Path name is outside container.")

        return path

    def EnsureDirectoryExists(self, dirname):
        try:
            os.makedirs(dirname)
        except OSError:
            pass

    def ListFiles(self):
        top_level = os.path.join(self.dump_dir, self.version)
        for root, _, files in os.walk(top_level):
            for f in files:
                path = os.path.normpath(os.path.join(root, f))

                if path.endswith(".gz"):
                    path = path[:-3]

                # Return paths relative to the dump dir.
                yield path[len(top_level) + 1:]

    def Create(self, name):
        path = self.GetAbsolutePathName(name)
        self.EnsureDirectoryExists(os.path.dirname(path))
        return gzip.open(path + ".gz", "wb")

    def Destroy(self, name):
        path = self.GetAbsolutePathName(name)
        return shutil.rmtree(path)

    def Open(self, name):
        path = self.GetAbsolutePathName(name)
        try:
            result = open(path, "rb")
        except IOError:
            result = gzip.open(path + ".gz")

        self.session.logging.debug("Opened local file %s" % result.name)
        return result

    def _StoreData(self, name, to_write, **options):
        path = self.GetAbsolutePathName(name)
        self.EnsureDirectoryExists(os.path.dirname(path))

        # If we are asked to write uncompressed files we do.
        if options.get("uncompressed"):
            with open(path, "wb") as out_fd:
                out_fd.write(to_write)
            self._dirty = True
            return

        # We need to update the file atomically in case someone else is trying
        # to open it right now. Since the files are expected to be fairly small
        # its ok to compress into memory and just write atomically.
        fd = StringIO.StringIO()
        with gzip.GzipFile(mode="wb", fileobj=fd) as gzip_fd:
            gzip_fd.write(to_write)

        with open(path + ".gz", "wb") as out_fd:
            out_fd.write(fd.getvalue())

        self._dirty = True

    def __str__(self):
        return "Directory:%s" % self.dump_dir


# pylint: disable=protected-access

class SelfClosingFile(StringIO.StringIO):
    def __init__(self, name, manager):
        self.name = name
        self.manager = manager
        StringIO.StringIO.__init__(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.Close()
        else:
            self.manager._Cancel(self.name)

    def Close(self):
        self.manager._Write(self.name, self.getvalue())


class ZipFileManager(IOManager):
    """An IO Manager which stores files in a zip archive."""

    order = 50

    def __init__(self, urn=None, fd=None, **kwargs):
        super(ZipFileManager, self).__init__(**kwargs)
        if fd is None and not urn.lower().endswith("zip"):
            if self.mode == "w":
                raise IOManagerError(
                    "Zip files must have the .zip extensions.")

        self.fd = fd
        if urn is not None:
            self.location = self.file_name = os.path.normpath(
                os.path.abspath(urn))
            self.canonical_name = os.path.splitext(os.path.basename(urn))[0]

        self._OpenZipFile()

        # The set of outstanding writers. When all outstanding writers have been
        # closed we can flush the ZipFile.
        self._outstanding_writers = set()

    @utils.safe_property
    def inventory(self):
        """We do not really need an inventory for zip files.

        We return a fake one based on the zip file's modification time.
        """
        result = {}
        for zipinfo in self.zip.filelist:
            result[zipinfo.filename] = zipinfo.date_time

        return {
            "$INVENTORY": result
        }

    def FlushInventory(self):
        pass

    def _OpenZipFile(self, mode=None):
        try:
            if self.fd is None:
                self.zip = zipfile.ZipFile(
                    self.file_name, mode=mode or self.mode,
                    compression=zipfile.ZIP_DEFLATED)

            elif self.mode == "r":
                self.zip = zipfile.ZipFile(self.fd, mode="r")

            elif self.mode == "a":
                self.zip = zipfile.ZipFile(self.fd, mode="a")

        except zipfile.BadZipfile:
            raise IOManagerError("Unable to read zipfile.")

    def ListFiles(self):
        return self.zip.namelist()

    def _Cancel(self, name):
        self._outstanding_writers.remove(name)

    def _Write(self, name, data):
        self.zip.writestr(name, data)
        self._outstanding_writers.remove(name)
        if not self._outstanding_writers:
            self.zip.close()

            # Reopen the zip file so we may add new members.
            self._OpenZipFile(mode="a")

    def Create(self, name):
        if self.mode not in ["w", "a"]:
            raise IOManagerError("Container not opened for writing.")

        result = SelfClosingFile(name, self)
        self._outstanding_writers.add(name)
        return result

    def Destroy(self, name):
        _ = name
        raise IOManagerError(
            "Removing a file from zipfile is not supported. Use a different "
            "IOManager subclass.")

    def Open(self, name):
        if self.mode not in ["r", "a"]:
            raise IOManagerError("Container not opened for reading.")
        if self.zip is None:
            self._OpenZipFile()

        try:
            return self.zip.open(name)
        except KeyError as e:
            raise IOManagerError(e)

    def __enter__(self):
        self._outstanding_writers.add(self)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._outstanding_writers.remove(self)
        if exc_type is None and not self._outstanding_writers:
            self.zip.close()
            if self.mode in ["w", "a"]:
                self._OpenZipFile(mode="a")

    def Close(self):
        self.zip.close()

    def __str__(self):
        return "ZipFile:%s" % self.file_name


class URLManager(IOManager):
    """Supports opening profile repositories hosted over the web."""

    def __init__(self, urn=None, mode="r", **kwargs):
        super(URLManager, self).__init__(urn=urn, mode=mode, **kwargs)
        if mode != "r":
            raise IOManagerError("%s supports only reading." %
                                 self.__class__.__name__)

        self.url = urlparse.urlparse(urn)
        if self.url.scheme not in ("http", "https"):
            raise IOManagerError("%s supports only http protocol." %
                                 self.__class__.__name__)

    def Create(self, name):
        _ = name
        raise IOManagerError("Write support to http is not supported.")

    def Destroy(self, name):
        _ = name
        raise IOManagerError("Write support to http is not supported.")

    def _GetURL(self, name):
        url = self.url._replace(path="%s/%s/%s" % (
            self.url.path, self.version, name))
        return urlparse.urlunparse(url)

    def Open(self, name):
        url = self._GetURL(name)

        try:
            # Rekall repositories always use gzip to compress the files - so
            # first try with the .gz extension.
            fd = urllib2.urlopen(url + ".gz", timeout=10)
            self.session.logging.debug("Opened url %s.gz" % url)
            return gzip.GzipFile(
                fileobj=StringIO.StringIO(fd.read(MAX_DATA_SIZE)))
        except urllib2.HTTPError:
            # Try to load the file without the .gz extension.
            self.session.logging.debug("Opened url %s" % url)
            return urllib2.urlopen(url, timeout=10)

    def __str__(self):
        return "URL:%s" % self.urn


def Factory(urn, mode="r", session=None, **kwargs):
    """Try to instantiate the IOManager class."""
    for cls in sorted(IOManager.classes.values(), key=lambda x: x.order):
        try:
            return cls(urn=urn, mode=mode, session=session, **kwargs)
        except IOError:
            pass

    raise IOManagerError(
        "Unable to find any managers which can work on %s" % urn)
