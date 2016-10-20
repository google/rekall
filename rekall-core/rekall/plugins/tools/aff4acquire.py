# Rekall Memory Forensics
#
# Copyright 2015 Google Inc. All Rights Reserved.
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

"""This plugin adds the ability for Rekall to acquire an AFF4 image.

It is an alternative to the pmem suite of acquisition tools, which also creates
AFF4 images. The difference being that this plugin will apply live analysis to
acquire more relevant information (e.g. mapped files etc).
"""

__author__ = "Michael Cohen <scudette@google.com>"
import platform
import glob
import os
import re
import stat
import tempfile

from pyaff4 import aff4
from pyaff4 import data_store

try:
    # Cloud support is optional.
    from pyaff4 import aff4_cloud
except ImportError:
    aff4_cloud = None

from pyaff4 import aff4_directory
from pyaff4 import aff4_image
from pyaff4 import aff4_map
from pyaff4 import zip
from pyaff4 import lexicon
from pyaff4 import rdfvalue

from pyaff4 import plugins  # pylint: disable=unused-import

from rekall import constants
from rekall import plugin
from rekall import testlib
from rekall import utils
from rekall import yaml_utils
from rekall.plugins import core


class AFF4ProgressReporter(aff4.ProgressContext):
    def __init__(self, session, **kwargs):
        super(AFF4ProgressReporter, self).__init__(**kwargs)
        self.session = session

    def Report(self, readptr):
        """This will be called periodically to report the progress.

        Note that readptr is specified relative to the start of the range
        operation (WriteStream and CopyToStream)
        """
        readptr = readptr + self.start

        # Rate in MB/s.
        try:
            rate = ((readptr - self.last_offset) /
                    (self.now() - self.last_time) * 1000000 / 1024/1024)
        except ZeroDivisionError:
            rate = "?"

        self.session.report_progress(
            " Reading %sMiB / %sMiB  %s MiB/s     ",
            readptr/1024/1024,
            self.length/1024/1024,
            rate)

        self.last_time = self.now()
        self.last_offset = readptr

        if aff4.aff4_abort_signaled:
            raise RuntimeError("Aborted")


class AddressSpaceWrapper(aff4.AFF4Stream):
    """A wrapper around an address space."""
    def __init__(self, *args, **kwargs):
        self.address_space = kwargs.pop("address_space")
        super(AddressSpaceWrapper, self).__init__(*args, **kwargs)

    def Read(self, length):
        res = self.address_space.read(self.readptr, length)
        return res


class CredentialManager(object):
    """Manage GCE default credentials through the environment."""

    def __init__(self, session=None, gce_credentials_path=None,
                 gce_credentials=None):
        self.gce_credentials_path = gce_credentials_path
        self.gce_credentials = gce_credentials
        self.session = session

    def __enter__(self):
        self.old_env = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        self.fd = None

        if self.gce_credentials_path:
            self.session.logging.debug("Setting GCS credentials to %s",
                                       self.gce_credentials_path)
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = (
                self.gce_credentials_path)

        # Credentials are given inline,
        elif self.gce_credentials:
            with tempfile.NamedTemporaryFile(delete=False) as self.fd:
                self.session.logging.debug("Setting GCS credentials to %s",
                                           self.fd.name)

                self.fd.write(self.gce_credentials)
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self.fd.name

    def __exit__(self, unused_type, unused_value, unused_traceback):
        if self.fd:
            os.unlink(self.fd.name)

        # Restore the previous setting.
        if self.old_env is None:
            os.environ.pop("GOOGLE_APPLICATION_CREDENTIALS", None)
        else:
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self.old_env


class AbstractAFF4Plugin(plugin.TypedProfileCommand, plugin.Command):
    """The base class for all AFF4 plugins."""
    __abstract = True

    __args = [
        dict(name="gce_credentials",
             help="The GCE service account credentials to use."),

        dict(name="gce_credentials_path",
             help="A path to the GCE service account credentials to use."),
    ]

    def __init__(self, *args, **kwargs):
        super(AbstractAFF4Plugin, self).__init__(*args, **kwargs)
        self.credential_manager = CredentialManager(
            self.session,
            self.plugin_args.gce_credentials_path,
            self.plugin_args.gce_credentials)

    def _get_aff4_volume(self, resolver, output_urn, action="Writing"):
        urn_parts = output_urn.Parse()
        if urn_parts.scheme == "file":
            if urn_parts.path.endswith("/"):
                self.session.logging.info(
                    "%s a directory volume on %s", action, output_urn)
                return aff4_directory.AFF4Directory.NewAFF4Directory(
                    resolver, output_urn)

            self.session.logging.info(
                "%s a ZipFile volume on %s", action, output_urn)

            return zip.ZipFile.NewZipFile(resolver, output_urn)

        elif urn_parts.scheme == "gs" and aff4_cloud:
            self.session.logging.info(
                "%s a cloud volume on %s", action, output_urn)

            return aff4_cloud.AFF4GStore.NewAFF4GStore(
                resolver, output_urn)

        else:
            raise plugin.PluginError(
                "URL Scheme: %s not supported for destination: %s" %(
                    urn_parts.scheme, output_urn))


class AFF4Acquire(AbstractAFF4Plugin):
    """Copy the physical address space to an AFF4 file.


    NOTE: This plugin does not require a working profile - unless the user also
    wants to copy the pagefile or mapped files. In that case we must analyze the
    live memory to gather the required files.
    """

    name = "aff4acquire"

    BUFFERSIZE = 1024 * 1024

    # Files larger than this will be stored as regular segments.
    MAX_SIZE_FOR_SEGMENT = 10 * 1024 * 1024

    PROFILE_REQUIRED = False

    __args = [
        dict(name="destination", positional=True,
             help="The destination file to create. "),

        dict(name="destination_url",
             help="The destination AFF4 URL to create. "),

        # If compression is not specified we prefer snappy but if that is not
        # available we use zlib which should always be there.
        dict(name="compression",
             default="snappy" if aff4_image.snappy else "zlib",
             required=False,
             choices=["snappy", "stored", "zlib"],
             help="The compression to use."),

        dict(name="append", type="Boolean", default=False,
             help="Append to the current volume."),

        dict(name="also_memory", type="Boolean", default="auto",
             help="Also acquire physical memory. If not specified we acquire "
             "physical memory only when no other operation is specified."),

        dict(name="also_mapped_files", type="Boolean",
             help="Also get mapped or opened files (requires a profile)"),

        dict(name="also_pagefile", type="Boolean",
             help="Also get the pagefile/swap partition (requires a profile)"),

        dict(name="files", type="ArrayStringParser", required=False,
             help="Also acquire files matching the following globs."),

        dict(name="max_file_size", type="IntParser", default=100*1024*1024,
             help="Maximum file size to acquire.")
    ]

    table_header = [
        dict(name="Message")
    ]

    table_options = dict(
        suppress_headers=True
    )

    def column_types(self):
        return dict(Message=str)

    def __init__(self, *args, **kwargs):
        super(AFF4Acquire, self).__init__(*args, **kwargs)

        if (not self.plugin_args.destination and
            not self.plugin_args.destination_url):
            raise plugin.PluginError(
                "A destination or destination_url must be specified.")

        if self.plugin_args.compression == "snappy":
            self.compression = lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY
        elif self.plugin_args.compression == "stored":
            self.compression = lexicon.AFF4_IMAGE_COMPRESSION_STORED
        elif self.plugin_args.compression == "zlib":
            self.compression = lexicon.AFF4_IMAGE_COMPRESSION_ZLIB

        # Do not acquire memory if we are told to do something else as well,
        # unless specifically asked to.
        if self.plugin_args.also_memory == "auto":
            if any((self.plugin_args.also_mapped_files,
                    self.plugin_args.also_pagefile,
                    self.plugin_args.files)):
                self.plugin_args.also_memory = False
            else:
                self.plugin_args.also_memory = True

    def _default_file_globs(self):
        if platform.system() == "Windows":
            # In Windows we need to collect at least the kernel and all the
            # kernel drivers.
            return [r"C:\Windows\System32\ntoskrnl.exe",
                    r"C:\Windows\System32\*.sys",
                    r"C:\Windows\SysNative\ntoskrnl.exe",
                    r"C:\Windows\SysNative\*.sys"]

        elif platform.system() == "Linux":
            return ["/proc/kallsyms", "/boot/*"]

        return []

    def copy_physical_address_space(self, resolver, volume):
        """Copies the physical address space to the output volume.

        The result is a map object.
        """
        image_urn = volume.urn.Append("PhysicalMemory")
        source = self.session.physical_address_space

        # Mark the stream as a physical memory stream.
        resolver.Set(image_urn, lexicon.AFF4_CATEGORY,
                     rdfvalue.URN(lexicon.AFF4_MEMORY_PHYSICAL))

        with volume.CreateMember(
                image_urn.Append("information.yaml")) as metadata_fd:
            metadata_fd.Write(
                yaml_utils.encode(self.create_metadata(source)))

        yield ("Imaging Physical Memory:\n",)

        # Use an AFF4Image for the actual storage.
        map_data = image_urn.Append("data")

        # Set the compression type on the storage stream.
        resolver.Set(map_data, lexicon.AFF4_IMAGE_COMPRESSION,
                     rdfvalue.URN(self.compression))

        with aff4_map.AFF4Map.NewAFF4Map(
                resolver, image_urn, volume.urn) as image_stream:
            total_length = self._WriteToTarget(resolver, source, image_stream)

        yield ("Wrote {0} mb of Physical Memory to {1}\n".format(
            total_length/1024/1024, image_stream.urn),)

    def _WriteToTarget(self, resolver, source_as, image_stream):
        # Prepare a temporary map to control physical memory acquisition.
        helper_map = aff4_map.AFF4Map(resolver)

        with resolver.CachePut(
                AddressSpaceWrapper(
                    resolver=resolver, address_space=source_as)) as source_aff4:

            total_length = 0
            for run in source_as.get_address_ranges():
                total_length += run.length
                helper_map.AddRange(
                    run.start, run.start, run.length,
                    source_aff4.urn)

            progress = AFF4ProgressReporter(session=self.session,
                                            length=total_length)
            image_stream.WriteStream(helper_map, progress=progress)

        return total_length

    def _copy_address_space_to_image(self, resolver, volume,
                                     image_urn, source):
        """Copy address space into a linear image, padding if needed."""
        resolver.Set(image_urn, lexicon.AFF4_IMAGE_COMPRESSION,
                     rdfvalue.URN(self.compression))

        with aff4_image.AFF4Image.NewAFF4Image(
                resolver, image_urn, volume.urn) as image_stream:
            total_length = self._WriteToTarget(resolver, source, image_stream)

        yield ("Wrote {0} ({1} mb)".format(source.name,
                                           total_length/1024/1024),)

    def linux_copy_mapped_files(self, resolver, volume):
        """Copy all the mapped or opened files to the volume."""
        # Build a set of all files.
        vma_files = set()
        filenames = set()

        for x in self._copy_file_to_image(resolver, volume, "/proc/kallsyms"):
            yield x

        for task in self.session.plugins.pslist().filter_processes():
            for vma in task.mm.mmap.walk_list("vm_next"):
                vm_file_offset = vma.vm_file.obj_offset
                if vm_file_offset in vma_files:
                    continue

                filename = task.get_path(vma.vm_file)
                if filename in filenames:
                    continue

                try:
                    stat_entry = os.stat(filename)
                except (OSError, IOError) as e:
                    self.session.logging.info(
                        "Skipping %s: %s", filename, e)
                    continue

                mode = stat_entry.st_mode
                if stat.S_ISREG(mode):
                    if stat_entry.st_size <= self.plugin_args.max_file_size:
                        filenames.add(filename)
                        vma_files.add(vm_file_offset)

                        for x in self._copy_file_to_image(
                                resolver, volume, filename, stat_entry):
                            yield x
                    else:
                        self.session.logging.info(
                            "Skipping %s: Size larger than %s",
                            filename, self.plugin_args.max_file_size)


    def _copy_file_to_image(self, resolver, volume, filename,
                            stat_entry=None):
        if stat_entry is None:
            try:
                stat_entry = os.stat(filename)
            except (OSError, IOError):
                return

        image_urn = volume.urn.Append(utils.SmartStr(filename))
        out_fd = None
        try:
            with open(filename, "rb") as in_fd:
                yield ("Adding file {0}".format(filename),)
                resolver.Set(
                    image_urn, lexicon.AFF4_STREAM_ORIGINAL_FILENAME,
                    rdfvalue.XSDString(os.path.abspath(filename)))

                progress = AFF4ProgressReporter(
                    session=self.session,
                    length=stat_entry.st_size)

                if stat_entry.st_size < self.MAX_SIZE_FOR_SEGMENT:
                    with volume.CreateMember(image_urn) as out_fd:
                        # Only enable compression if we are using it.
                        if (self.compression !=
                                lexicon.AFF4_IMAGE_COMPRESSION_STORED):
                            out_fd.compression_method = zip.ZIP_DEFLATE
                        out_fd.WriteStream(in_fd, progress=progress)
                else:
                    resolver.Set(image_urn, lexicon.AFF4_IMAGE_COMPRESSION,
                                 rdfvalue.URN(self.compression))

                    with aff4_image.AFF4Image.NewAFF4Image(
                            resolver, image_urn, volume.urn) as out_fd:
                        out_fd.WriteStream(in_fd, progress=progress)

        except IOError:
            try:
                # Currently we can only access NTFS filesystems.
                if self.session.profile.metadata("os") == "windows":
                    self.session.logging.debug(
                        "Unable to read %s. Attempting raw access.", filename)

                    # We can not just read this file, parse it from the NTFS.
                    self._copy_raw_file_to_image(
                        resolver, volume, filename)
            except IOError:
                self.session.logging.warn(
                    "Unable to read %s. Skipping.", filename)


        finally:
            if out_fd:
                resolver.Close(out_fd)

    def _copy_raw_file_to_image(self, resolver, volume, filename):
        image_urn = volume.urn.Append(utils.SmartStr(filename))

        drive, base_filename = os.path.splitdrive(filename)
        if not base_filename:
            return

        ntfs_session = self.session.add_session(
            filename=r"\\.\%s" % drive,
            profile="ntfs")

        ntfs_session.plugins.istat(2)

        ntfs = ntfs_session.GetParameter("ntfs")
        mft_entry = ntfs.MFTEntryByName(base_filename)
        data_as = mft_entry.open_file()

        self._copy_address_space_to_image(resolver, volume, image_urn,
                                          data_as)

        resolver.Set(image_urn, lexicon.AFF4_STREAM_ORIGINAL_FILENAME,
                     rdfvalue.XSDString(os.path.abspath(filename)))

    def windows_copy_mapped_files(self, resolver, volume):
        filenames = set()

        for task in self.session.plugins.pslist().filter_processes():
            for vad in task.RealVadRoot.traverse():
                try:
                    file_obj = vad.ControlArea.FilePointer
                    file_name = file_obj.file_name_with_drive()
                    if not file_name:
                        continue

                except AttributeError:
                    continue

                if file_name in filenames:
                    continue

                filenames.add(file_name)
                for x in self._copy_file_to_image(resolver, volume, file_name):
                    yield x

        object_tree_plugin = self.session.plugins.object_tree()
        for module in self.session.plugins.modules().lsmod():
            try:
                path = object_tree_plugin.FileNameWithDrive(
                    module.FullDllName.v())

                for x in self._copy_file_to_image(resolver, volume, path):
                    yield x
            except IOError:
                self.session.logging.debug(
                    "Unable to read %s. Skipping.", path)


    def copy_mapped_files(self, resolver, volume):
        # Forces profile autodetection if needed.
        profile = self.session.profile

        os_name = profile.metadata("os")
        if os_name == "windows":
            for  x in self.windows_copy_mapped_files(resolver, volume):
                yield x
        elif os_name == "linux":
            for x in self.linux_copy_mapped_files(resolver, volume):
                yield x

    def copy_files(self, resolver, volume, globs):
        """Copy all the globs into the volume."""
        for glob_expression in globs:
            for path in glob.glob(glob_expression):
                path = os.path.abspath(path)
                for x in self._copy_file_to_image(resolver, volume, path):
                    yield x

    def copy_page_file(self, resolver, volume):
        pagefiles = self.session.GetParameter("pagefiles")
        for filename, _ in pagefiles.values():
            yield ("Imaging pagefile {0}\n".format(filename),)
            for x in self._copy_raw_file_to_image(resolver, volume, filename):
                yield x

    def create_metadata(self, source):
        """Returns a dict with a standard metadata format.

        We gather data from the session.
        """
        result = dict(Imager="Rekall %s (%s)" % (constants.VERSION,
                                                 constants.CODENAME),
                      Registers={},
                      Runs=[])

        if self.session.HasParameter("dtb"):
            result["Registers"]["CR3"] = self.session.GetParameter("dtb")

        if self.session.HasParameter("kernel_base"):
            result["KernBase"] = self.session.GetParameter("kernel_base")

        for run in source.get_address_ranges():
            result["Runs"].append(dict(start=run.start, length=run.length))

        return result

    def collect(self):
        if self.compression:
            yield ("Will use compression: {0}\n".format(self.compression),)

        # Did the user select any actions which require access to memory?
        self.memory_access_options = any(
            (self.plugin_args.also_memory, self.plugin_args.also_pagefile,
             self.plugin_args.also_mapped_files))

        # Do we need to access memory?
        if self.memory_access_options:
            # If no address space is specified we try to operate in live mode.
            if self.session.plugins.load_as().GetPhysicalAddressSpace() == None:
                yield ("Will load physical address space from live plugin.",)

                with self.session.plugins.live():
                    for x in self.collect_acquisition():
                        yield x
                    return

        for x in self.collect_acquisition():
            yield x

    def collect_acquisition(self):
        """Do the actual acquisition."""
        # If destination looks like a URN, just let the AFF4 library handle it.
        if self.plugin_args.destination:
            output_urn = rdfvalue.URN.NewURNFromFilename(
                self.plugin_args.destination)

        elif self.plugin_args.destination_url:
            output_urn = rdfvalue.URN(self.plugin_args.destination_url)

        if (output_urn.Parse().scheme == "file" and
                not self.plugin_args.destination[-1] in "/\\"):
            # Destination looks like a filename - go through the renderer to
            # create the file.
            with self.session.GetRenderer().open(
                    filename=self.plugin_args.destination,
                    mode="a+b") as out_fd:
                output_urn = rdfvalue.URN.FromFileName(out_fd.name)
                for x in self._collect_acquisition(output_urn=output_urn):
                    yield x
        else:
            # Just pass the URL to the AFF4 library.
            for x in self._collect_acquisition(output_urn=output_urn):
                yield x

    def _collect_acquisition(self, output_urn):
        with data_store.MemoryDataStore() as resolver:
            mode = "truncate"
            if self.plugin_args.append:
                mode = "append"
                # Appending means we read the volume first, then add new
                # members to it.

            resolver.Set(output_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString(mode))

            phys_as = self.session.physical_address_space
            with self.credential_manager, self._get_aff4_volume(
                    resolver, output_urn) as volume:
                # We allow acquiring memory from a non volatile physical
                # address space as a way of converting an image from another
                # format to AFF4.
                if phys_as:
                    if self.plugin_args.also_memory:
                        # Get the physical memory.
                        for x in self.copy_physical_address_space(
                                resolver, volume):
                            yield x

                    # We only copy files if we are running on a raw device
                    # and we're not targetting a VM.
                    if phys_as.volatile and not phys_as.virtualized:
                        if self.plugin_args.also_pagefile:
                            for x in self.copy_page_file(resolver, volume):
                                yield x

                        if self.plugin_args.also_mapped_files:
                            for x in self.copy_mapped_files(resolver, volume):
                                yield x

                        # Always include the minimum file globs
                        # required to support the given OS.
                        file_globs = (self.plugin_args.files +
                                      self._default_file_globs())

                        for x in self.copy_files(
                                resolver, volume, file_globs):
                            yield x

                    elif any([self.plugin_args.also_pagefile,
                              self.plugin_args.also_mapped_files,
                              self.plugin_args.files]):
                        raise RuntimeError(
                            "Imaging options require access to live memory "
                            "but the physical address space is not "
                            "volatile. Did you mean to specify the --live "
                            "option?")

                elif self.memory_access_options:
                    raise RuntimeError(
                        "Imaging options require access to memory but no "
                        "suitable address space was defined. Did you mean "
                        "to specify the --live option?")

                # User can request to just acquire regular files but only if
                # no physical_address_space is also specified.
                elif self.plugin_args.files:
                    for x in self.copy_files(resolver, volume, self.files):
                        yield x


# We can not check the file hash because AFF4 files contain UUID which will
# change each time.
class TestAFF4Acquire(testlib.SimpleTestCase):
    PARAMETERS = dict(commandline="aff4acquire %(tempdir)s/output_image.aff4")

    def filter(self, output):
        result = []
        for line in output:
            # Remove progress lines.
            if "Reading" in line:
                continue

            result.append(re.sub("aff4:/+[^/]+/", "aff4:/XXXX/", line))
        return result

    def testCase(self):
        """AFF4 uses GUIDs which vary all the time."""
        previous = self.filter(self.baseline['output'])
        current = self.filter(self.current['output'])

        # Compare the entire table
        self.assertEqual(previous, current)


class AFF4Ls(AbstractAFF4Plugin):
    """List the content of an AFF4 file."""

    name = "aff4ls"

    __args = [
        dict(name="long", type="Boolean",
             help="Include additional information about each stream."),

        dict(name="regex", default=".", type="RegEx",
             help="Regex of filenames to dump."),

        dict(name="volume", required=True, positional=True,
             help="Volume to list."),
    ]

    namespaces = {
        lexicon.AFF4_NAMESPACE: "aff4:",
        lexicon.XSD_NAMESPACE: "xsd:",
        lexicon.RDF_NAMESPACE: "rdf:",
        lexicon.AFF4_MEMORY_NAMESPACE: "memory:",
        lexicon.AFF4_DISK_NAMESPACE: "disk:",
        "http://www.google.com#": "google:",
    }

    table_header = [
        dict(name="Size", width=10, align="r"),
        dict(name="Type", width=15),
        dict(name="Original Name", width=50),
        dict(name="URN"),
    ]

    def __init__(self, *args, **kwargs):
        super(AFF4Ls, self).__init__(*args, **kwargs)
        self.resolver = data_store.MemoryDataStore()

    def _shorten_URN(self, urn):
        if not isinstance(urn, rdfvalue.URN):
            return urn

        urn = unicode(urn)

        for k, v in self.namespaces.iteritems():
            if urn.startswith(k):
                return "%s%s" % (v, urn[len(k):])

        return urn

    def collect(self):
        """Render a detailed description of the contents of an AFF4 volume."""
        volume_urn = rdfvalue.URN(self.plugin_args.volume)

        with self.credential_manager, self._get_aff4_volume(
                self.resolver, volume_urn, "Reading") as volume:
            if self.plugin_args.long:
                subjects = self.resolver.QuerySubject(self.plugin_args.regex)
            else:
                subjects = self.interesting_streams(volume)

            for subject in sorted(subjects):
                urn = unicode(subject)
                filename = None
                if (self.resolver.Get(subject, lexicon.AFF4_CATEGORY) ==
                        lexicon.AFF4_MEMORY_PHYSICAL):
                    filename = "Physical Memory"
                else:
                    filename = self.resolver.Get(
                        subject, lexicon.AFF4_STREAM_ORIGINAL_FILENAME)

                if not filename:
                    filename = volume.urn.RelativePath(urn)

                type = str(self.resolver.Get(
                    subject, lexicon.AFF4_TYPE)).split("#")[-1]

                size = self.resolver.Get(subject, lexicon.AFF4_STREAM_SIZE)
                if size is None and filename == "Physical Memory":
                    with self.resolver.AFF4FactoryOpen(urn) as fd:
                        last_range = fd.GetRanges()[-1]
                        size = last_range.map_offset + last_range.length

                yield (size, type, filename, urn)

    AFF4IMAGE_FILTER_REGEX = re.compile("/[0-9a-f]+8(/index)?$")

    def interesting_streams(self, volume):
        """Returns the interesting URNs and their filenames."""
        urns = {}

        for (subject, _, value) in self.resolver.QueryPredicate(
                lexicon.AFF4_STREAM_ORIGINAL_FILENAME):
            # Normalize the filename for case insensitive filesysyems.
            urn = unicode(subject)
            urns[urn] = unicode(value)

        for (subject, _, value) in self.resolver.QueryPredicate(
                lexicon.AFF4_CATEGORY):
            urn = unicode(subject)
            if value == lexicon.AFF4_MEMORY_PHYSICAL:
                urns[urn] = "Physical Memory"

        # Add metadata files.
        for subject in self.resolver.QuerySubject(
                re.compile(".+(yaml|turtle)")):
            urn = unicode(subject)
            urns[urn] = volume.urn.RelativePath(urn)

        return urns

class AFF4Dump(AFF4Ls):
    """Dump the entire resolver contents for an AFF4 volume."""

    name = "aff4dump"

    table_header = [
        dict(name="URN", width=60),
        dict(name="Attribute", width=30),
        dict(name="Value"),
    ]

    def collect(self):
        """Render a detailed description of the contents of an AFF4 volume."""
        volume_urn = rdfvalue.URN(self.plugin_args.volume)
        with self.credential_manager, self._get_aff4_volume(
                self.resolver, volume_urn, "Reading") as volume:
            if self.plugin_args.long:
                subjects = self.resolver.QuerySubject(self.plugin_args.regex)
            else:
                subjects = self.interesting_streams(volume)

            for subject in sorted(subjects):
                for pred, value in self.resolver.QueryPredicatesBySubject(
                        subject):

                    yield (volume.urn.RelativePath(subject),
                           self._shorten_URN(rdfvalue.URN(pred)),
                           self._shorten_URN(value))


class AFF4Export(core.DirectoryDumperMixin, AbstractAFF4Plugin):
    """Exports all the streams in an AFF4 Volume."""
    dump_dir_optional = False
    default_dump_dir = None

    BUFFERSIZE = 1024 * 1024

    name = "aff4export"

    __args = [
        dict(name="regex", default=".", type="RegEx",
             help="Regex of filenames to dump."),

        dict(name="volume", required=True, positional=True,
             help="Volume to list."),
    ]

    def _sanitize_filename(self, filename):
        filename = filename.replace("\\", "/")
        filename = filename.strip("/")
        result = []
        for x in filename:
            if x == "/":
                result.append("_")
            elif x.isalnum() or x in "_-=.,; ":
                result.append(x)
            else:
                result.append("%" + x.encode("hex"))

        return "".join(result)

    def copy_stream(self, in_fd, out_fd, length=2**64):
        total = 0
        while 1:
            available_to_read = min(length - total, self.BUFFERSIZE)
            data = in_fd.read(available_to_read)
            if not data:
                break

            out_fd.write(data)
            total += len(data)
            self.session.report_progress("Reading %s @ %#x", in_fd.urn, total)

    def copy_map(self, in_fd, out_fd):
        for range in in_fd.GetRanges():
            self.session.logging.info("Range %s", range)
            out_fd.seek(range.map_offset)
            in_fd.seek(range.map_offset)
            self.copy_stream(in_fd, out_fd, range.length)

    def render(self, renderer):
        aff4ls = self.session.plugins.aff4ls(volume=self.plugin_args.volume)
        self.resolver = aff4ls.resolver

        volume_urn = rdfvalue.URN().FromFileName(self.plugin_args.volume)
        with zip.ZipFile.NewZipFile(self.resolver, volume_urn) as volume:
            for urn, filename in aff4ls.interesting_streams(
                    volume).items():
                if self.plugin_args.regex.match(filename):
                    # Force the file to be under the dumpdir.
                    filename = self._sanitize_filename(filename)
                    self.session.logging.info("Dumping %s", filename)

                    with renderer.open(directory=self.plugin_args.dump_dir,
                                       filename=filename,
                                       mode="wb") as out_fd:
                        with self.resolver.AFF4FactoryOpen(urn) as in_fd:
                            if isinstance(in_fd, aff4_map.AFF4Map):
                                self.copy_map(in_fd, out_fd)
                            else:
                                self.copy_stream(in_fd, out_fd)
