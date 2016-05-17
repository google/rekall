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

from rekall import constants
from rekall import plugin
from rekall import testlib
from rekall import utils
from rekall import yaml_utils
from rekall.plugins import core

from pyaff4 import aff4
from pyaff4 import data_store
from pyaff4 import aff4_image
from pyaff4 import aff4_map
from pyaff4 import zip
from pyaff4 import lexicon
from pyaff4 import rdfvalue

from pyaff4 import plugins  # pylint: disable=unused-import


class AddressSpaceWrapper(aff4.AFF4Stream):
    """A wrapper around an address space."""
    def __init__(self, *args, **kwargs):
        self.address_space = kwargs.pop("address_space")
        super(AddressSpaceWrapper, self).__init__(*args, **kwargs)

    def Read(self, length):
        res = self.address_space.read(self.readptr, length)
        return res


class AFF4Acquire(plugin.ProfileCommand):
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

    @classmethod
    def args(cls, parser):
        super(AFF4Acquire, cls).args(parser)

        parser.add_argument(
            "destination", default="output.aff4", required=False,
            help="The destination file to create. "
            "If not specified we write output.aff4 in current directory.")

        parser.add_argument(
            "-c", "--compression", default=None, required=False,
            choices=["snappy", "stored", "zlib"],
            help="The compression to use.")

        parser.add_argument(
            "--append", default=False, type="Boolean",
            help="Append to the current volume..")

        parser.add_argument(
            "--also_memory", default=None, type="Boolean",
            help="Also acquire physical memory. If not specified we acquire "
            "physical memory only when no other operation is specified.")

        parser.add_argument(
            "--also_mapped_files", default=False, type="Boolean",
            help="Also get mapped or opened files (requires a profile)")

        parser.add_argument(
            "--also_pagefile", default=False, type="Boolean",
            help="Also get the pagefile/swap partition (requires a profile)")

        parser.add_argument(
            "files", default=[], type="ArrayStringParser", required=False,
            help="Also acquire files matching the following globs.")

    def __init__(self, destination=None, compression=None,
                 append=False, also_memory=None,
                 also_mapped_files=False, also_pagefile=False,
                 max_file_size=100*1024*1024, files=None,
                 **kwargs):
        super(AFF4Acquire, self).__init__(**kwargs)

        # If compression is not specified we prefer snappy but if that is not
        # available we use zlib which should always be there.
        if compression is None:
            if aff4_image.snappy:
                compression = "snappy"
            else:
                compression = "zlib"

        self.destination = destination or "output.aff4"
        if compression == "snappy":
            compression = lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY
        elif compression == "stored":
            compression = lexicon.AFF4_IMAGE_COMPRESSION_STORED
        elif compression == "zlib":
            compression = lexicon.AFF4_IMAGE_COMPRESSION_ZLIB
        else:
            raise plugin.PluginError(
                "Compression scheme not supported.")

        self.compression = compression
        self.append = append

        # Do not acquire memory if we are told to do something else as well,
        # unless specifically asked to.
        if also_memory is None:
            if any((also_mapped_files, also_pagefile, files)):
                also_memory = False
            else:
                also_memory = True

        self.also_memory = also_memory
        self.also_mapped_files = also_mapped_files
        self.also_pagefile = also_pagefile
        self.max_file_size = max_file_size
        self.files = files or []

    def _default_file_globs(self):
        if platform.system() == "Windows":
            # In Windows we need to collect at least the kernel and all the
            # kernel drivers.
            return [r"C:\Windows\System32\ntoskrnl.exe",
                    r"C:\Windows\System32\*.sys"]

        elif platform.system() == "Linux":
            return ["/proc/kallsyms", "/boot/*"]

        return []

    def copy_physical_address_space(self, renderer, resolver, volume):
        """Copies the physical address space to the output volume.

        The result is a map object.
        """
        image_urn = volume.urn.Append("PhysicalMemory")
        source = self.session.physical_address_space

        # Mark the stream as a physical memory stream.
        resolver.Set(image_urn, lexicon.AFF4_CATEGORY,
                     rdfvalue.URN(lexicon.AFF4_MEMORY_PHYSICAL))

        if self.compression:
            storage_urn = image_urn.Append("data")
            resolver.Set(storage_urn, lexicon.AFF4_IMAGE_COMPRESSION,
                         rdfvalue.URN(self.compression))

        with volume.CreateMember(
                image_urn.Append("information.yaml")) as metadata_fd:
            metadata_fd.Write(
                yaml_utils.encode(self.create_metadata(source)))

        renderer.format("Imaging Physical Memory:\n")
        with aff4_map.AFF4Map.NewAFF4Map(
                resolver, image_urn, volume.urn) as image_stream:
            total_length = self._WriteToTarget(resolver, source, image_stream)

        renderer.format("Wrote {0} mb of Physical Memory to {1}\n",
                        total_length/1024/1024, image_stream.urn)

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

            progress = aff4.ProgressContext(length=total_length)
            image_stream.WriteStream(helper_map, progress=progress)

        return total_length

    def _copy_address_space_to_image(self, renderer, resolver, volume,
                                     image_urn, source):
        """Copy address space into a linear image, padding if needed."""
        if self.compression:
            resolver.Set(image_urn, lexicon.AFF4_IMAGE_COMPRESSION,
                         rdfvalue.URN(self.compression))

        with aff4_image.AFF4Image.NewAFF4Image(
                resolver, image_urn, volume.urn) as image_stream:
            total_length = self._WriteToTarget(resolver, source, image_stream)

        renderer.format("Wrote {0} ({1} mb)\n", source.name,
                        total_length/1024/1024)

    def linux_copy_mapped_files(self, renderer, resolver, volume):
        """Copy all the mapped or opened files to the volume."""
        # Build a set of all files.
        vma_files = set()
        filenames = set()

        self._copy_file_to_image(renderer, resolver, volume, "/proc/kallsyms")

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
                    if stat_entry.st_size <= self.max_file_size:
                        filenames.add(filename)
                        vma_files.add(vm_file_offset)

                        self._copy_file_to_image(
                            renderer, resolver, volume, filename, stat_entry)
                    else:
                        self.session.logging.info(
                            "Skipping %s: Size larger than %s",
                            filename, self.max_file_size)


    def _copy_file_to_image(self, renderer, resolver, volume, filename,
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
                renderer.format("Adding file {0}\n", filename)
                resolver.Set(
                    image_urn, lexicon.AFF4_STREAM_ORIGINAL_FILENAME,
                    rdfvalue.XSDString(os.path.abspath(filename)))

                progress = aff4.ProgressContext(length=stat_entry.st_size)

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
                if self.profile.metadata("os") == "windows":
                    self.session.logging.debug(
                        "Unable to read %s. Attempting raw access.", filename)

                    # We can not just read this file, parse it from the NTFS.
                    self._copy_raw_file_to_image(
                        renderer, resolver, volume, filename)
            except IOError:
                self.session.logging.warn(
                    "Unable to read %s. Skipping.", filename)


        finally:
            if out_fd:
                resolver.Close(out_fd)

    def _copy_raw_file_to_image(self, renderer, resolver, volume, filename):
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

        self._copy_address_space_to_image(renderer, resolver, volume, image_urn,
                                          data_as)

        resolver.Set(image_urn, lexicon.AFF4_STREAM_ORIGINAL_FILENAME,
                     rdfvalue.XSDString(os.path.abspath(filename)))

    def windows_copy_mapped_files(self, renderer, resolver, volume):
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
                self._copy_file_to_image(renderer, resolver, volume, file_name)

        object_tree_plugin = self.session.plugins.object_tree()
        for module in self.session.plugins.modules().lsmod():
            try:
                path = object_tree_plugin.FileNameWithDrive(
                    module.FullDllName.v())

                self._copy_file_to_image(renderer, resolver, volume, path)
            except IOError:
                self.session.logging.debug(
                    "Unable to read %s. Skipping.", path)


    def copy_mapped_files(self, renderer, resolver, volume):
        # Forces profile autodetection if needed.
        profile = self.session.profile

        os_name = profile.metadata("os")
        if os_name == "windows":
            self.windows_copy_mapped_files(renderer, resolver, volume)
        elif os_name == "linux":
            self.linux_copy_mapped_files(renderer, resolver, volume)

    def copy_files(self, renderer, resolver, volume, globs):
        """Copy all the globs into the volume."""
        for glob_expression in globs:
            for path in glob.glob(glob_expression):
                path = os.path.abspath(path)
                self._copy_file_to_image(renderer, resolver, volume, path)

    def copy_page_file(self, renderer, resolver, volume):
        pagefiles = self.session.GetParameter("pagefiles")
        for filename, _ in pagefiles.values():
            renderer.format("Imaging pagefile {0}\n", filename)
            self._copy_raw_file_to_image(
                renderer, resolver, volume, filename)

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

    def render(self, renderer):
        if self.compression:
            renderer.format("Will use compression: {0}\n", self.compression)

        # Did the user select any actions which require access to memory?
        self.memory_access_options = any(
            (self.also_memory, self.also_pagefile, self.also_mapped_files))

        # Do we need to access memory?
        if self.memory_access_options:
            # If no address space is specified we try to operate in live mode.
            if self.session.plugins.load_as().GetPhysicalAddressSpace() == None:
                renderer.format(
                    "Will load physical address space from live plugin.")

                live = self.session.plugins.live()
                try:
                    live.live()
                    self.render_acquisition(renderer)
                finally:
                    live.close()
            else:
                self.render_acquisition(renderer)

    def render_acquisition(self, renderer):
        """Do the actual acquisition."""
        with renderer.open(filename=self.destination, mode="a+b") as out_fd:
            with data_store.MemoryDataStore() as resolver:
                output_urn = rdfvalue.URN.FromFileName(out_fd.name)
                mode = "truncate"
                if self.append:
                    mode = "append"
                    # Appending means we read the volume first, then add new
                    # members to it.

                resolver.Set(output_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                             rdfvalue.XSDString(mode))

                phys_as = self.session.physical_address_space
                with zip.ZipFile.NewZipFile(resolver, output_urn) as volume:
                    # We allow acquiring memory from a non volatile physical
                    # address space as a way of converting an image from another
                    # format to AFF4.
                    if phys_as:
                        if self.also_memory:
                            # Get the physical memory.
                            self.copy_physical_address_space(
                                renderer, resolver, volume)

                        # We only copy files if we are running on a raw device
                        # and we're not targetting a VM.
                        if phys_as.volatile and not phys_as.virtualized:
                            if self.also_pagefile:
                                self.copy_page_file(
                                    renderer, resolver, volume)

                            if self.also_mapped_files:
                                self.copy_mapped_files(
                                    renderer, resolver, volume)

                            # If a physical_address_space is specified, then
                            # we only allow copying files if it is volatile.
                            if self.files:
                                self.copy_files(renderer, resolver, volume,
                                                self.files)
                        elif any([self.also_pagefile, self.also_mapped_files,
                                  self.files]):
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
                    elif self.files:
                        self.copy_files(renderer, resolver, volume,
                                        self.files)


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


class AFF4Ls(plugin.VerbosityMixIn, plugin.Command):
    """List the content of an AFF4 file."""

    name = "aff4ls"

    @classmethod
    def args(cls, parser):
        super(AFF4Ls, cls).args(parser)

        parser.add_argument(
            "-l", "--long", default=False, type="Boolean",
            help="Include additional information about each stream.")

        parser.add_argument(
            "--regex", default=".",
            help="Regex of filenames to dump.")

        parser.add_argument(
            "volume", default=None, required=False,
            help="Volume to list.")

    def __init__(self, long=False, regex=".", volume=None, **kwargs):
        super(AFF4Ls, self).__init__(**kwargs)
        self.long = long
        self.volume_path = volume
        self.resolver = data_store.MemoryDataStore()
        self.regex = re.compile(regex)
        self.namespaces = {
            lexicon.AFF4_NAMESPACE: "aff4:",
            lexicon.XSD_NAMESPACE: "xsd:",
            lexicon.RDF_NAMESPACE: "rdf:",
            lexicon.AFF4_MEMORY_NAMESPACE: "memory:",
            lexicon.AFF4_DISK_NAMESPACE: "disk:"
        }

    def _shorten_URN(self, urn):
        if not isinstance(urn, rdfvalue.URN):
            return urn

        urn = unicode(urn)

        for k, v in self.namespaces.iteritems():
            if urn.startswith(k):
                return "%s%s" % (v, urn[len(k):])

        return urn

    def render_long(self, renderer, volume):
        """Render a detailed description of the contents of an AFF4 volume."""
        renderer.table_header([
            dict(name="Size", width=10, align="r"),
            dict(name="Type", width=15),
            dict(name="Original Name", width=50),
            dict(name="URN"),
        ])

        for subject in sorted(self.resolver.QuerySubject(self.regex)):
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

            renderer.table_row(size, type, filename, urn)

    def render_verbose(self, renderer, volume):
        """Render a detailed description of the contents of an AFF4 volume."""
        renderer.table_header([
            dict(name="URN", width=60),
            dict(name="Attribute", width=30),
            dict(name="Value"),
        ])

        if self.long:
            subjects = self.resolver.QuerySubject(self.regex)
        else:
            subjects = self.interesting_streams(volume)

        for subject in sorted(subjects):
            for pred, value in self.resolver.QueryPredicatesBySubject(subject):
                renderer.table_row(volume.urn.RelativePath(subject),
                                   self._shorten_URN(rdfvalue.URN(pred)),
                                   self._shorten_URN(value))

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

    def render_short(self, renderer, volume):
        """Render a concise description of the contents of an AFF4 volume."""
        renderer.table_header([
            dict(name="Size", width=10, align="r"),
            dict(name="Original Name", width=50),
            dict(name="URN"),
        ])

        for urn, filename in sorted(
                self.interesting_streams(volume).iteritems()):
            if not self.regex.match(urn):
                continue

            size = self.resolver.Get(urn, lexicon.AFF4_STREAM_SIZE)
            if size is None and filename == "Physical Memory":
                with self.resolver.AFF4FactoryOpen(urn) as fd:
                    last_range = fd.GetRanges()[-1]
                    size = last_range.map_offset + last_range.length

            renderer.table_row(size, filename, urn)

    def render(self, renderer):
        if self.volume_path is None:
            self.volume_path = self.session.GetParameter("filename")

        volume_urn = rdfvalue.URN().FromFileName(self.volume_path)
        if not volume_urn:
            raise plugin.PluginError("No Volume specified.")

        with zip.ZipFile.NewZipFile(self.resolver, volume_urn) as volume:
            if self.plugin_args.verbosity > 1:
                self.render_verbose(renderer, volume)
            elif self.long:
                self.render_long(renderer, volume)
            else:
                self.render_short(renderer, volume)


class AFF4Export(core.DirectoryDumperMixin, plugin.Command):
    """Exports all the streams in an AFF4 Volume."""
    dump_dir_optional = False
    default_dump_dir = None

    BUFFERSIZE = 1024 * 1024

    name = "aff4export"

    @classmethod
    def args(cls, parser):
        super(AFF4Export, cls).args(parser)

        parser.add_argument(
            "volume", default=None, required=True,
            help="Volume to list.")

        parser.add_argument(
            "regex", default=[".+"], type="ArrayStringParser",
            help="One or more Regex of filenames to dump.")

    def __init__(self, volume=None, regex=None, **kwargs):
        super(AFF4Export, self).__init__(**kwargs)
        self.volume_path = volume
        if not regex:
            regex = [".+"]

        self.regex = [re.compile(x) for x in regex]
        self.aff4ls = self.session.plugins.aff4ls()
        self.resolver = self.aff4ls.resolver

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
        volume_urn = rdfvalue.URN().FromFileName(self.volume_path)
        with zip.ZipFile.NewZipFile(self.resolver, volume_urn) as volume:
            for urn, filename in self.aff4ls.interesting_streams(
                    volume).items():
                if any(x.match(filename) for x in self.regex):
                    # Force the file to be under the dumpdir.
                    filename = self._sanitize_filename(filename)
                    self.session.logging.info("Dumping %s", filename)

                    with renderer.open(directory=self.dump_dir,
                                       filename=filename,
                                       mode="wb") as out_fd:
                        with self.resolver.AFF4FactoryOpen(urn) as in_fd:
                            if isinstance(in_fd, aff4_map.AFF4Map):
                                self.copy_map(in_fd, out_fd)
                            else:
                                self.copy_stream(in_fd, out_fd)
