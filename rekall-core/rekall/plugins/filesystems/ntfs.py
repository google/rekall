# Rekall Memory Forensics
# Copyright 2014 Google Inc. All Rights Reserved.
#
# Author: Michael Cohen scudette@google.com.
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

"""This file implements support for parsing NTFS filesystem in Rekall.

Simply select the ntfs profile with an ntfs image - you might need to also
specify the --file_offset (or -o) parameter.

$ rekal -v --profile ntfs -f ~/images/ntfs1-gen2.E01

[1] Default session 13:56:54> fls
 MFT   Seq           Created                  File Mod                   MFT Mod                   Access              Size    Filename
----- ----- ------------------------- ------------------------- ------------------------- ------------------------- ---------- --------
    4     4 2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000       36000 $AttrDef
    8     8 2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000           0 $BadClus
    6     6 2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000      126112 $Bitmap
    7     7 2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000        8192 $Boot
   11    11 2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000           0 $Extend
    2     2 2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000     4685824 $LogFile
    0     1 2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000  2008-12-31 22:44:02+0000       65536 $MFT
...

"""

import array
import logging
import re
import struct

from rekall import addrspace
from rekall import kb
from rekall import plugin
from rekall import obj
from rekall import testlib
from rekall import utils
from rekall.plugins import core
from rekall.plugins import guess_profile
from rekall.plugins.filesystems import lznt1
from rekall.plugins.overlays import basic


class Error(Exception):
    pass


class ParseError(Error):
    pass


class NTFSParseError(ParseError):
    pass


class NTFSDetector(guess_profile.DetectionMethod):
    name = "ntfs"

    def Offsets(self):
        return [0]

    def DetectFromHit(self, hit, _, address_space):
        ntfs_profile = self.session.LoadProfile("ntfs")
        try:
            ntfs = NTFS(address_space=address_space, session=self.session)
            self.session.SetCache("ntfs", ntfs, volatile=False)

            return ntfs_profile
        except NTFSParseError:
            return


FILE_FLAGS = dict(
    READ_ONLY=0x0001,
    HIDDEN=0x0002,
    SYSTEM=0x0004,
    ARCHIVE=0x0020,
    DEVICE=0x0040,
    NORMAL=0x0080,
    TEMPORARY=0x0100,
    SPARSE=0x0200,
    REPARSE_POINT=0x0400,
    COMPRESSED=0x0800,
    OFFLINE=0x1000,
    NOT_INDEXED=0x2000,
    ENCRYPTED=0x4000
    )

ntfs_vtypes = {
    'NTFS_BOOT_SECTOR': [512, {
        "oemname": [3, ["String", dict(length=8)]],
        "sector_size": [11, ["unsigned short"]],

        "_cluster_size": [13, ["unsigned char"]],

        # The cluster_size in bytes.
        "cluster_size": lambda x: x.m("_cluster_size") * x.sector_size,

        # The total number of clusters in the volume
        "block_count": lambda x: x.m("_volume_size") / x.cluster_size,

        "_volume_size":   [40, ["unsigned long"]],
        "_mft_cluster":   [48, ["unsigned long"]],
        "_mirror_mft_cluster":   [56, ["unsigned long"]],
        "_mft_record_size": [64, ["signed byte"]],
        "index_record_size": [68, ["unsigned char"]],
        "serial": [72, ["String", dict(length=8)]],

        # Should be 0xAA55
        "magic": [510, ["unsigned short"]],

        # The MFT can actually be fragmented so this does not have to be the
        # complete MFT.

        "MFT": [lambda x: x.m("_mft_cluster") * x.cluster_size,
                ["Array", dict(
                    target="MFT_ENTRY",
                    target_size=lambda x: x.mft_record_size)
                ]],
    }],

    "MFT_ENTRY": [None, {
        "magic": [0, ["String", dict(length=4)]],
        "fixup_offset": [4, ["unsigned short"]],
        "fixup_count":  [6, ["unsigned short"]],
        "logfile_sequence_number": [8, ["unsigned long long"]],
        "sequence_value": [16, ["unsigned short"]],
        "link_count": [18, ["unsigned short"]],
        "attribute_offset": [20, ["unsigned short"]],
        "flags": [22, ["Flags", dict(
            target="unsigned short",
            bitmap=dict(
                ALLOCATED=0,
                DIRECTORY=1)
        )]],
        "mft_entry_size": [24, ["unsigned short"]],
        "mft_entry_allocated": [28, ["unsigned short"]],
        "base_record_reference": [32, ["unsigned long long"]],
        "next_attribute_id": [40, ["unsigned short"]],
        "record_number": [44, ["unsigned long"]],

        # These are fixups.
        "fixup_magic": [lambda x: x.obj_offset + x.fixup_offset,
                        ["String", dict(length=2, term=None)]],

        "fixup_table": [lambda x: x.obj_offset + x.fixup_offset + 2,
                        ["Array", dict(
                            target="String",
                            target_args=dict(length=2, term=None),
                            count=lambda x: x.fixup_count-1)]],

        # Attributes are a list of NTFS_ATTRIBUTE objects, starting from the
        # attribute_offset member.
        "_attributes": [lambda x: x.obj_offset + x.attribute_offset,
                        ["ListArray",
                         dict(target="NTFS_ATTRIBUTE",
                              maximum_size=lambda x: x.mft_entry_size)]],
    }],

    "NTFS_ATTRIBUTE": [lambda x: x.length, {
        "type": [0, [
            "Enumeration", dict(
                target="unsigned int",

                # The actual mapping between types and type names is
                # given by the $AttrDef file. At some point we parse
                # this file and store it in the session.
                choices=lambda x: x.obj_profile.get_constant(
                    "ATTRIBUTE_NAMES")
            )]],
        "length": [4, ["unsigned int"]],
        "resident": [8, ["Enumeration", dict(
            target="unsigned char",
            choices={
                0: "RESIDENT",
                1: "NON-RESIDENT",
            }
        )]],

        # A Quick check for resident attributes.
        "is_resident": lambda x: x.resident == 0,
        "name_length": [9, ["unsigned char"]],
        "name_offset": [10, ["unsigned short"]],
        "flags": [12, ["Flags", dict(
            target="unsigned short",
            maskmap={
                "COMPRESSED" : 0x0001,
                "ENCRYPTED": 0x4000,
                "SPARSE": 0x8000,
            }
        )]],
        "attribute_id": [14, ["unsigned short"]],

        "name": [lambda x: x.obj_offset + x.name_offset,
                 ["UnicodeString", dict(
                     length=lambda x: x.name_length * 2)]],

        # The following are only valid if the attribute is resident.
        "content_size": [16, ["unsigned int"]],
        "content_offset": [20, ["unsigned short"]],

        # The following are valid if the attribute is non-resident.
        "runlist_vcn_start": [16, ["unsigned long long"]],
        "runlist_vcn_end": [24, ["unsigned long long"]],
        "runlist_offset": [32, ["unsigned short"]],
        "compression_unit_size": [34, ["unsigned short"]],
        "allocated_size": [40, ["unsigned long long"]],
        "actual_size": [48, ["unsigned long long"]],
        "initialized_size": [56, ["unsigned long long"]],
    }],

    "STANDARD_INFORMATION": [None, {
        "create_time": [0, ["WinFileTime"]],
        "file_altered_time": [8, ["WinFileTime"]],
        "mft_altered_time": [16, ["WinFileTime"]],
        "file_accessed_time": [24, ["WinFileTime"]],
        "flags": [32, ["Flags", dict(
            target="unsigned int",
            maskmap=FILE_FLAGS)]],
        "max_versions": [36, ["unsigned int"]],
        "version": [40, ["unsigned int"]],
        "class_id": [44, ["unsigned int"]],
        "owner_id": [48, ["unsigned int"]],
        "sid": [52, ["unsigned int"]],
        "quota": [56, ["unsigned long long"]],
        "usn": [64, ["unsigned int"]],
    }],

    "FILE_NAME": [None, {
        "mftReference": [0, ["BitField", dict(
            target="unsigned long long",
            start_bit=0,
            end_bit=48)]],
        "seq_num": [6, ["short int"]],
        "created": [8, ["WinFileTime"]],
        "file_modified": [16, ["WinFileTime"]],
        "mft_modified": [24, ["WinFileTime"]],
        "file_accessed": [32, ["WinFileTime"]],
        "allocated_size": [40, ["unsigned long long"]],
        "size": [48, ["unsigned long long"]],
        "flags": [56, ["Flags", dict(
            target="unsigned int",
            bitmap=FILE_FLAGS)]],
        "reparse_value": [60, ["unsigned int"]],
        "_length_of_name": [64, ["byte"]],
        "name_type": [65, ["Enumeration", dict(
            target="byte",
            choices={
                0: "POSIX",
                1: "Win32",
                2: "DOS",
                3: "DOS+Win32"
            })]],
        "name": [66, ["UnicodeString", dict(
            length=lambda x: x.m("_length_of_name") * 2)]],
    }],

    "STANDARD_INDEX_HEADER": [42, {
        "magicNumber": [0, ["Signature", dict(
            value="INDX",
        )]],

        "fixup_offset": [4, ["unsigned short"]],
        "fixup_count": [6, ["unsigned short"]],
        "logFileSeqNum": [8, ["unsigned long long"]],
        "vcnOfINDX": [16, ["unsigned long long"]],
        "node": [24, ["INDEX_NODE_HEADER"]],

        # These are fixups.
        "fixup_magic": [lambda x: x.obj_offset + x.fixup_offset,
                        ["String", dict(length=2, term=None)]],

        "fixup_table": [lambda x: x.obj_offset + x.fixup_offset + 2,
                        ["Array", dict(
                            target="String",
                            target_args=dict(length=2, term=None),
                            count=lambda x: x.fixup_count-1)]],
    }],

    "INDEX_RECORD_ENTRY": [lambda x: x.sizeOfIndexEntry.v(), {
        "mftReference": [0, ["BitField", dict(
            target="unsigned long long",
            start_bit=0,
            end_bit=48)]],
        "seq_num": [6, ["short int"]],
        "sizeOfIndexEntry": [8, ["unsigned short"]],
        "filenameOffset": [10, ["unsigned short"]],
        "flags": [12, ["unsigned int"]],
        "file": [16, ["FILE_NAME"]],
    }],

    "INDEX_ROOT": [None, {
        "type": [0, [
            "Enumeration", dict(
                target="unsigned int",

                # The actual mapping between types and type names is
                # given by the $AttrDef file. At some point we parse
                # this file and store it in the session.
                choices=lambda x: x.obj_profile.get_constant(
                    "ATTRIBUTE_NAMES")
            )]],

        "collation_rule": [4, ["unsigned int"]],
        "idxalloc_size_b": [8, ["unsigned int"]],
        "idx_size_c": [12, ["unsigned int"]],
        "node": [16, ["INDEX_NODE_HEADER"]],
    }],

    "INDEX_NODE_HEADER": [0x10, {
        "offset_to_index_entry": [0, ["unsigned int"]],
        "offset_to_end_index_entry": [4, ["unsigned int"]],
    }],

    "ATTRIBUTE_LIST_ENTRY": [lambda x: x.length, {
        "type": [0, [
            "Enumeration", dict(
                target="unsigned int",
                choices=lambda x: x.obj_profile.get_constant(
                    "ATTRIBUTE_NAMES")
            )]],
        "length": [4, ["unsigned short int"]],
        "name_length": [6, ["byte"]],
        "offset_to_name": [7, ["byte"]],
        "starting_vcn": [8, ["unsigned long long"]],
        "mftReference": [16, ["BitField", dict(
            target="unsigned long long",
            start_bit=0,
            end_bit=48)]],

        "attribute_id": [24, ["byte"]],

        # Automatically retrieve the target attribute from the MFT.
        "attribute": lambda x: x.obj_context["mft"][
            x.mftReference].get_attribute(
                x.type, x.attribute_id)
    }],
}


class INDEX_NODE_HEADER(obj.Struct):
    def Entries(self):
        result = self.obj_profile.ListArray(
            offset=self.offset_to_index_entry + self.obj_offset,
            vm=self.obj_vm,
            maximum_offset=self.offset_to_end_index_entry + self.obj_offset - 1,
            target="INDEX_RECORD_ENTRY", context=self.obj_context,
        )

        for x in result:
            if x.flags > 0:
                break
            yield x


class FixupAddressSpace(addrspace.BaseAddressSpace):
    """An address space to implement record fixup."""

    def __init__(self, fixup_magic, fixup_table, base_offset, length, **kwargs):
        super(FixupAddressSpace, self).__init__(**kwargs)
        self.as_assert(self.base is not None, "Address space must be stacked.")
        self.base_offset = base_offset
        self.fixup_table = fixup_table
        self.fixup_magic = fixup_magic

        # We read the entire region into a mutable buffer then apply the fixups.
        self.buffer = array.array("c", self.base.read(base_offset, length))
        for i, fixup_value in enumerate(fixup_table):
            fixup_offset = (i+1) * 512 - 2
            if (self.buffer[fixup_offset:fixup_offset+2].tostring() !=
                    fixup_magic.v()):
                raise NTFSParseError("Fixup error")

            self.buffer[fixup_offset:fixup_offset+2] = array.array(
                "c", fixup_value.v())

    def read(self, address, length):
        buffer_offset = address - self.base_offset
        return self.buffer[buffer_offset:buffer_offset+length].tostring()


class RunListAddressSpace(addrspace.RunBasedAddressSpace):
    """An address space which is initialized from a runlist."""

    def __init__(self, run_list, cluster_size=None, size=0, name="", **kwargs):
        super(RunListAddressSpace, self).__init__(**kwargs)
        self.PAGE_SIZE = cluster_size or self.session.cluster_size
        self.compression_unit_size = 16 * self.PAGE_SIZE
        self._end = size
        self.name = name

        # In clusters.
        file_offset = 0
        for range_start, range_length in run_list:
            if size == 0:
                self._end += range_length * self.PAGE_SIZE

            # A range_start of None represents a sparse range (i.e. should be
            # filled with 0).
            if range_start is None:
                file_offset += range_length

                # Identify a compressed range if the current range is sparse and
                # the last range's length is smaller than a compression unit.
                try:
                    run = self.runs[-1][2]
                    if run.length < self.compression_unit_size:
                        run.data["compression"] = True

                except (ValueError, IndexError):
                    pass

                continue

            # To support compression, we divide the range into complete 16
            # cluster runs, and a remainder. The remainder is possibly
            # compressed.
            compressed_subrange = range_length % 16
            uncompressed_range_length = range_length - compressed_subrange
            if uncompressed_range_length:
                self._store_run(
                    file_offset, range_start, uncompressed_range_length)

            file_offset += uncompressed_range_length
            range_start += uncompressed_range_length

            if compressed_subrange:
                self._store_run(file_offset, range_start, compressed_subrange)

            file_offset += compressed_subrange

    def _store_run(self, file_offset, range_start, length):
        """Store a new run with all items given in self.PAGE_SIZE."""
        # The runs contain a list of:
        # file_offset - the byte offset in the file where the run starts.
        #
        # range_start - the byte offset in the image where the range starts.
        #
        # length - the length of the run in bytes.
        #
        # compressed - A flag to indicate if this run is compressed. Note that
        #     we dont decide it is compressed until we see it followed by a
        #     sparse run which adds us to compression_unit_size.
        self.add_run(file_offset * self.PAGE_SIZE,
                     range_start * self.PAGE_SIZE,
                     length * self.PAGE_SIZE,
                     data=dict(compression=False))

    def _read_chunk(self, addr, length):
        addr = int(addr)
        start, end, run = self.runs.get_containing_range(addr)

        # addr is not in any range, pad to the next range.
        if start is None:
            end = self.runs.get_next_range_start(addr)
            if end is None:
                end = addr + length

            return "\x00" * min(end - addr, length)

        if run.data.get("compression"):
            block_data = lznt1.decompress_data(
                self.base.read(run.file_offset, run.length) + "\x00" * 10,
                logger=self.session.logging.getChild("ntfs"))

            available_length = (self.compression_unit_size - (addr - run.start))

            block_offset = addr - run.start

            result = block_data[
                block_offset:
                block_offset + min(length, available_length)]

            # Decompression went wrong - just zero pad.
            if len(result) < length:
                result += "\x00" * (length - len(result))

            return result

        available_length = run.length - (addr - run.start)
        block_offset = addr - run.start + run.file_offset

        if available_length > 0:
            return self.base.read(
                block_offset, min(length, available_length))

    def get_mappings(self, start=0, end=2**64):
        for run in super(RunListAddressSpace, self).get_mappings(
                start=start, end=end):
            if start > run.end:
                continue

            length = run.length
            # When the run is compressed it really contains an entire
            # compression unit.
            if run.data.get("compression"):
                length = self.compression_unit_size

            length = min(run.length, self.end() - run.start)
            if length > 0:
                yield addrspace.Run(start=run.start,
                                    end=run.start + length,
                                    address_space=run.address_space,
                                    file_offset=run.file_offset)

    def __unicode__(self):
        return utils.SmartUnicode(self.name or self.__class__.__name__)

    def end(self):
        return self._end


class MFT_ENTRY(obj.Struct):
    """An MFT Entry.

    Note that MFT entries behave as either files or directories depending on the
    attributes they have. This object wraps this behavior with convenience
    methods. Hence callers do not need to manipulate attributes directly.
    """

    def __init__(self, **kwargs):
        super(MFT_ENTRY, self).__init__(**kwargs)

        # We implement fixup by wrapping the base address space with a fixed
        # one:
        if self.obj_context.get("ApplyFixup", True):
            self.obj_vm = FixupAddressSpace(fixup_magic=self.fixup_magic,
                                            fixup_table=self.fixup_table,
                                            base_offset=self.obj_offset,
                                            length=self.mft_entry_allocated,
                                            base=self.obj_vm)
        self.logging = self.obj_session.logging.getChild("ntfs")
        # Change to DEBUG to turn on module level debugging.
        self.logging.setLevel(logging.ERROR)

    @utils.safe_property
    def mft_entry(self):
        return self.obj_context.get("index", self.record_number.v())

    @utils.safe_property
    def attributes(self):
        seen = set()

        for attribute in self._attributes:
            if attribute.type == 0xFFFFFFFF:
                break

            if attribute in seen:
                continue

            seen.add(attribute)
            yield attribute

            if attribute.type == "$ATTRIBUTE_LIST":
                for sub_attr in attribute.DecodeAttribute():
                    if sub_attr.mftReference == self.mft_entry:
                        continue

                    result = sub_attr.attribute
                    if result in seen:
                        continue

                    yield result

    def get_attribute(self, type=None, id=None):
        for attribute in self.attributes:
            if type is not None and attribute.type != type:
                continue

            if id is not None and attribute.attribute_id != id:
                continue

            return attribute

        return obj.NoneObject("Attribute not found")

    def is_directory(self):
        """Does this MFT entry behave as a directory?"""
        for attribute in self.attributes:
            if (attribute.type in ("$INDEX_ALLOCATION", "$INDEX_ROOT") and
                    attribute.name == "$I30"):
                return True
        return False

    def list_files(self):
        """List the files contained in this directory.

        Note that any file can contain other files (i.e. be a directory) if it
        has an $I30 stream. Thats is directories may also contain data and
        behave as files!

        Returns:
          An iterator over all INDEX_RECORD_ENTRY.
        """
        for attribute in self.attributes:
            if (attribute.type in ("$INDEX_ALLOCATION", "$INDEX_ROOT") and
                    attribute.name == "$I30"):
                for index_header in attribute.DecodeAttribute():
                    for x in index_header.node.Entries():
                        yield x

    def open_file(self):
        """Returns an address space which maps the content of the file's data.

        If this MFT does not contain any $DATA streams, returns a NoneObject().

        The returned address space is formed by joining all $DATA streams' run
        lists in this MFT into a contiguous mapping.
        """
        runlists = []
        data_size = 0

        # Combine the runlists from all the $DATA attributes into one
        # big runlist.
        for attribute in self.attributes:
            if attribute.type == "$DATA":
                if attribute.is_resident:
                    return attribute.data

                if data_size == 0:
                    data_size = attribute.size

                # Some sanity checking. The runlist should agree with the VCN
                # fields.
                run_length = (attribute.runlist_vcn_end -
                              attribute.runlist_vcn_start + 1)
                run_list = list(attribute.RunList())

                if sum(x[1] for x in run_list) != run_length:
                    self.logging.error(
                        "NTFS_ATTRIBUTE %s-%s: Not all runs found!",
                        self.mft_entry, attribute)

                runlists.extend(attribute.RunList())

        if runlists:
            return RunListAddressSpace(
                run_list=runlists,
                base=self.obj_session.physical_address_space,
                session=self.obj_session,
                name=self.full_path,
                size=data_size)

        return obj.NoneObject("No data")

    @utils.safe_property
    def filename(self):
        dos_name = obj.NoneObject()
        for attribute in self.attributes:
            if attribute.type == "$FILE_NAME":
                attribute = attribute.DecodeAttribute()

                # Prefer to return the win32 names.
                if "Win32" in str(attribute.name_type):
                    return attribute

                dos_name = attribute

        # If only the dos name exists, fall back to it.
        return dos_name

    @utils.safe_property
    def full_path(self):
        """Returns the full path of this MFT to the root."""
        result = []
        mft = self.obj_context["mft"]
        mft_entry = self
        depth = 0
        while depth < 10:
            filename_record = mft_entry.filename
            filename = unicode(filename_record.name)
            if filename == ".":
                break

            result.append(filename)
            mft_entry = mft[filename_record.mftReference]
            if mft_entry == None:
                break

            depth += 1

        result.reverse()
        return "/".join(result)

    @utils.safe_property
    def data_size(self):
        """Search all the $DATA attributes for the allocated size."""
        for attribute in self.attributes:
            if attribute.type == "$DATA" and attribute.size > 0:
                return attribute.size

        return 0


class NTFS_BOOT_SECTOR(obj.Struct):
    """A class to parse and access the NTFS boot sector."""

    # The mft_record_size in bytes
    mft_record_size = 0

    def __init__(self, **kwargs):
        """Parse the boot sector and calculate offsets."""
        super(NTFS_BOOT_SECTOR, self).__init__(**kwargs)
        if self._mft_record_size > 0:
            self.mft_record_size = self._mft_record_size * self.cluster_size
        else:
            self.mft_record_size = 1 << -self._mft_record_size

    def Validate(self):
        """Verify the boot sector for sanity."""

        if self.magic != 0xAA55:
            raise NTFSParseError("Magic not correct.")

        if self.cluster_size not in [
                0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
            raise NTFSParseError("Invalid cluster_size")

        if self.sector_size == 0 or self.sector_size % 512:
            raise NTFSParseError("invalid sector_size")

        if self.block_count == 0:
            raise NTFSParseError("Volume size is 0")


class NTFS_ATTRIBUTE(obj.Struct):
    """The NTFS attribute."""

    # A quick lookup to decode the runlist. Key is the byte size, value is a
    # mask to use.
    MASK = {
        0: 0,
        1: 0xFF,
        2: 0xFFFF,
        3: 0xFFFFFF,
        4: 0xFFFFFFFF,
        5: 0xFFFFFFFFFF,
        6: 0xFFFFFFFFFFFF,
        7: 0xFFFFFFFFFFFFFF,
        8: 0xFFFFFFFFFFFFFFFF,
        }

    # Helps to sign extend the run offset. Key is the number of bytes in the
    # offset, value is the sign bit.
    SIGN_BIT = {
        0: 0,
        1: 1 << (1 * 8 - 1),
        2: 1 << (2 * 8 - 1),
        3: 1 << (3 * 8 - 1),
        4: 1 << (4 * 8 - 1),
        5: 1 << (5 * 8 - 1),
        6: 1 << (6 * 8 - 1),
        7: 1 << (7 * 8 - 1),
        8: 1 << (8 * 8 - 1),
        }

    def sign_extend(self, x, b):
        """Sign extend a value based on the number of bytes it should take."""
        m = self.SIGN_BIT[b]
        x = x & self.MASK[b]
        return (x ^ m) - m

    @utils.safe_property
    def data(self):
        """Returns an address space representing the data of this attribute."""
        if self.is_resident:
            return addrspace.BufferAddressSpace(
                data=self.obj_vm.read(
                    self.obj_offset + self.content_offset,
                    self.content_size),
                session=self.obj_session)
        else:
            run_list = list(self.RunList())

            # Create an address space.
            address_space = RunListAddressSpace(
                run_list=run_list,
                base=self.obj_session.physical_address_space,
                session=self.obj_session, size=self.size)

            return address_space

    def DecodeAttribute(self):
        if self.type == "$STANDARD_INFORMATION":
            return self.obj_profile.STANDARD_INFORMATION(
                offset=0, vm=self.data, context=self.obj_context)

        elif self.type == "$FILE_NAME":
            return self.obj_profile.FILE_NAME(
                offset=0, vm=self.data, context=self.obj_context)

        elif self.type == "$DATA":
            return list(self.RunList())

        elif self.type == "$INDEX_ALLOCATION":
            result = []
            for i in xrange(0, self.size, 0x1000):
                result.append(
                    self.obj_profile.STANDARD_INDEX_HEADER(
                        offset=i, vm=self.data, context=self.obj_context))

            return result

        elif self.type == "$INDEX_ROOT":
            return [self.obj_profile.INDEX_ROOT(
                offset=0, vm=self.data, context=self.obj_context)]

        elif self.type == "$ATTRIBUTE_LIST":
            result = self.obj_profile.ListArray(
                offset=0, vm=self.data,
                target="ATTRIBUTE_LIST_ENTRY",
                maximum_size=self.content_size,
                context=self.obj_context
            )

            return result

    def RunList(self):
        """Decodes the runlist for this attribute."""
        if self.is_resident:
            return

        offset = self.obj_offset + self.runlist_offset
        run_offset = 0

        while 1:
            idx = ord(self.obj_vm.read(offset, 1))
            if idx == 0:
                return

            length_size = idx & 0xF
            run_offset_size = idx >> 4
            offset += 1

            run_length = struct.unpack("<Q", self.obj_vm.read(offset, 8))[0]
            run_length &= self.MASK[length_size]
            offset += length_size

            relative_run_offset = struct.unpack(
                "<Q", self.obj_vm.read(offset, 8))[0]

            relative_run_offset = self.sign_extend(relative_run_offset,
                                                   run_offset_size)

            run_offset += relative_run_offset
            offset += run_offset_size

            # This represents a sparse run.
            if relative_run_offset == 0:
                yield None, run_length
            else:
                yield run_offset, run_length

    @utils.safe_property
    def indices(self):
        return self.type, self.attribute_id

    @utils.safe_property
    def owner_MFT(self):
        """The MFT entry containing this entry."""
        # Note that our offset is expressed in terms of the MFT already.
        return self.obj_offset / 0x400

    @utils.safe_property
    def size(self):
        """The size of this attribute's data."""
        if self.is_resident:
            return self.content_size

        # The first $DATA attribute will return the size of the entire file
        # here.
        return self.actual_size


class STANDARD_INDEX_HEADER(obj.Struct):
    """The index header must manage its own fixups."""

    def __init__(self, **kwargs):
        super(STANDARD_INDEX_HEADER, self).__init__(**kwargs)

        # We implement fixup by wrapping the base address space with a fixed
        # one:
        if self.obj_context.get("ApplyFixup", True):
            self.obj_vm = FixupAddressSpace(fixup_magic=self.fixup_magic,
                                            fixup_table=self.fixup_table,
                                            base_offset=self.obj_offset,
                                            length=self.fixup_count * 512,
                                            base=self.obj_vm)



class NTFSProfile(basic.ProfileLLP64, basic.BasicClasses):
    """A profile for the NTFS."""

    def __init__(self, **kwargs):
        super(NTFSProfile, self).__init__(**kwargs)
        self.add_overlay(ntfs_vtypes)
        self.add_classes(dict(
            NTFS_BOOT_SECTOR=NTFS_BOOT_SECTOR,
            MFT_ENTRY=MFT_ENTRY,
            NTFS_ATTRIBUTE=NTFS_ATTRIBUTE,
            INDEX_NODE_HEADER=INDEX_NODE_HEADER,
            STANDARD_INDEX_HEADER=STANDARD_INDEX_HEADER,
        ))

        # We start off with a constant mapping of attribute types. This may
        # later be updated when parsing the $AttrDef file.
        self.add_constants(dict(ATTRIBUTE_NAMES={
            16: "$STANDARD_INFORMATION",
            32: "$ATTRIBUTE_LIST",
            48: "$FILE_NAME",
            64: "$OBJECT_ID",
            80: "$SECURITY_DESCRIPTOR",
            96: "$VOLUME_NAME",
            112: "$VOLUME_INFORMATION",
            128: "$DATA",
            144: "$INDEX_ROOT",
            160: "$INDEX_ALLOCATION",
            176: "$BITMAP",
            192: "$REPARSE_POINT",
            256: "$LOGGED_UTILITY_STREAM",
        }))


class NTFS(object):
    """A class to manage the NTFS filesystem parser."""

    def __init__(self, address_space, session=None):
        self.profile = NTFSProfile(session=session)
        self.bs = self.profile.NTFS_BOOT_SECTOR(vm=address_space)

        # Check for validity of boot sector.
        self.bs.is_valid()

        session.cluster_size = self.bs.cluster_size

        # Now we search for the $DATA attribute of the $MFT file so we can
        # defragment the MFT.
        mft = self.bs.MFT[0]

        self.address_space = None

        for attribute in mft.attributes:
            if attribute.type == "$DATA":
                run_list = list(attribute.RunList())
                self.address_space = RunListAddressSpace(
                    run_list=run_list, base=address_space, session=session)
                break

        if self.address_space is None:
            raise NTFSParseError("Unable to locate the $MFT.")

        # The MFT is constructed over the RunListAddressSpace to reassemble the
        # fragmentation.
        self.mft = self.profile.Array(offset=0, vm=self.address_space,
                                      target="MFT_ENTRY",
                                      target_size=self.bs.mft_record_size,
                                     )

        # Add a reference to the mft to all sub-objects..
        self.mft.obj_context["mft"] = self.mft

    def MFTEntryByName(self, path):
        """Return the MFT entry by traversing the path.

        We support both / and \\ as path separators. Path matching is case
        insensitive.

        Raises IOError if path is not found.

        Returns:
          a tuple of (path, MFT_ENTRY) where path is the case corrected path.

        """
        components = filter(None, re.split(r"[\\/]", path))
        return_path = []

        # Always start from the root of the filesystem.
        directory = self.mft[5]
        for component in components:
            component = component.lower()

            for record in directory.list_files():
                filename = record.file.name.v()
                if filename.lower() == component.lower():
                    directory = self.mft[record.mftReference]
                    return_path.append(filename)
                    break
            else:
                raise IOError("Path %s component not found." % component)

        directory.obj_context["path"] = "/".join(return_path)

        return directory


class NTFSPlugins(plugin.PhysicalASMixin, plugin.TypedProfileCommand,
                  plugin.ProfileCommand):
    """Base class for ntfs plugins."""
    __abstract = True

    mode = "mode_ntfs"

    def __init__(self, *args, **kwargs):
        super(NTFSPlugins, self).__init__(*args, **kwargs)
        self.ntfs = self.session.GetParameter("ntfs")
        if self.ntfs == None:
            self.ntfs = NTFS(self.session.physical_address_space,
                             session=self.session)
            self.session.SetCache("ntfs", self.ntfs, volatile=False)
            self.session.ntfs = self.ntfs


class FileBaseCommandMixin(object):
    """Mixin for commands which take filenames- delegate to inode commands."""
    delegate = ""

    __args = [
        dict(name="path", default="/", positional=True,
             help="Path to print stats for."),
    ]

    def render(self, renderer):
        mft = self.ntfs.MFTEntryByName(self.plugin_args.path)
        delegate = getattr(self.session.plugins, self.delegate)(
            mfts=[mft.mft_entry])
        delegate.render(renderer)


class MFTPluginsMixin(object):
    """A mixin for plugins which work on mft entries."""

    __args = [
        dict(name="mfts", type="ArrayIntParser", default=[5],
             required=False, positional=True,
             help="MFT entries to list.")
    ]


class FStat(FileBaseCommandMixin, NTFSPlugins):
    """Print information by filename."""
    name = "fstat"
    delegate = "istat"


class IStat(MFTPluginsMixin, NTFSPlugins):
    """Print information related to an MFT entry."""
    name = "istat"

    def render_standard_info(self, renderer, mft_entry):
        for attribute in mft_entry.attributes:
            if attribute.type == "$STANDARD_INFORMATION":
                decoded_attribute = attribute.DecodeAttribute()

                renderer.format("$STANDARD_INFORMATION Attribute Values:\n")

                renderer.table_header([
                    ("Key", "key", "30"),
                    ("Value", "value", "30")], suppress_headers=True)

                renderer.table_row("Flags", decoded_attribute.flags)
                renderer.table_row("Owner ID", decoded_attribute.owner_id)
                renderer.table_row("SID", decoded_attribute.sid)
                renderer.table_row("Created", decoded_attribute.create_time)
                renderer.table_row("File Modified",
                                   decoded_attribute.file_altered_time)
                renderer.table_row("MFT Modified",
                                   decoded_attribute.mft_altered_time)

                renderer.table_row("Accessed",
                                   decoded_attribute.file_accessed_time)

    def render_block_allocation(self, renderer, mft_entry):
        for attribute in mft_entry.attributes:
            if attribute.type == "$DATA":
                if attribute.is_resident:
                    return

                renderer.format("\nClusters ({0:d}-{1:d}):\n",
                                attribute.type, attribute.attribute_id)
                renderer.table_header([
                    ("c%s" % x, "c%s" % x, "25") for x in range(4)
                ], suppress_headers=True, nowrap=True)

                blocks = attribute.DecodeAttribute()
                for i in range(0, len(blocks), 8):
                    ranges = []
                    for (start, length) in blocks[i:i+8]:
                        if start is None:
                            ranges.append("Sparse(%s)" % length)
                        else:
                            ranges.append("%s-%s(%s)" % (
                                start, start + length, length))

                    renderer.table_row(*ranges)

    def comment(self, attribute):
        if attribute.type == "$FILE_NAME":
            return attribute.DecodeAttribute().name

        if attribute.type == "$DATA" and not attribute.is_resident:
            return "VCN: %s-%s" % (attribute.runlist_vcn_start,
                                   attribute.runlist_vcn_end)

        return ""

    def render_i30(self, renderer, mft_entry):
        if mft_entry.is_directory():
            renderer.format("\n$I30 Analysis:\n")
            renderer.table_header([
                ("MFT", "mft", ">10"),
                ("Seq", "seq", ">5"),
                ("Created", "created", "25"),
                ("File Mod", "file_mod", "25"),
                ("MFT Mod", "mft_mod", "25"),
                ("Access", "accessed", "25"),
                ("Size", "size", ">10"),
                ("Filename", "filename", ""),
            ])

            for record in mft_entry.list_files():
                file_record = record.file

                renderer.table_row(
                    record.mftReference,
                    record.seq_num,
                    file_record.created,
                    file_record.file_modified,
                    file_record.mft_modified,
                    file_record.file_accessed,
                    file_record.size,
                    file_record.name)

    def render(self, renderer):
        for mft in self.plugin_args.mfts:
            mft_entry = self.ntfs.mft[mft]

            renderer.format("MFT Entry Header Values:\n")
            renderer.format("Entry: {0:d}        Sequence: {1:d}\n",
                            mft, mft_entry.sequence_value)

            renderer.format("$LogFile Sequence Number: {0:d}\n",
                            mft_entry.logfile_sequence_number)
            renderer.format("Links: {0:d}\n\n", mft_entry.link_count)

            self.render_standard_info(renderer, mft_entry)

            renderer.format("\nAttributes:\n")
            renderer.table_header([
                ("Inode", "inode", ">15"),
                ("Type", "type", "30"),
                ("Name", "name", "10"),
                ("Res", "resident", "5"),
                ("Size", "size", ">10"),
                ("Comment", "comment", "")])

            for attribute in mft_entry.attributes:
                renderer.table_row(
                    "%d-%d-%d" % (attribute.owner_MFT, attribute.type,
                                  attribute.attribute_id),
                    attribute.type,
                    attribute.name,
                    attribute.is_resident,
                    attribute.size, self.comment(attribute))

            self.render_block_allocation(renderer, mft_entry)
            self.render_i30(renderer, mft_entry)


class FLS(FileBaseCommandMixin, NTFSPlugins):
    name = "fls"
    delegate = "ils"


class ILS(MFTPluginsMixin, NTFSPlugins):
    """List files in an NTFS image."""

    name = "ils"

    def render(self, renderer):
        for mft in self.plugin_args.mfts:
            directory = self.ntfs.mft[mft]

            # List all files inside this directory.
            renderer.table_header([
                ("MFT", "mft", ">10"),
                ("Seq", "seq", ">5"),
                ("Created", "created", "25"),
                ("File Mod", "file_mod", "25"),
                ("MFT Mod", "mft_mod", "25"),
                ("Access", "accessed", "25"),
                ("Size", "size", ">10"),
                ("Filename", "filename", ""),
            ])

            for record in directory.list_files():
                file_record = record.file

                renderer.table_row(
                    record.mftReference,
                    record.seq_num,
                    file_record.created,
                    file_record.file_modified,
                    file_record.mft_modified,
                    file_record.file_accessed,
                    file_record.size,
                    file_record.name)


class IDump(NTFSPlugins):
    """Dump a part of an MFT file."""
    name = "idump"

    __args = [
        dict(name="mft", type="IntParser", default=5,
             required=True, positional=True,
             help="MFT entry to dump."),

        dict(name="type", type="IntParser", default=128,
             required=False, positional=True,
             help="Attribute type to dump."),

        dict(name="id", type="IntParser", default=None,
             required=False, positional=True,
             help="Id of attribute to dump."),
    ]

    # Dump offset within the file.
    offset = 0

    def render(self, renderer):
        mft_entry = self.ntfs.mft[self.plugin_args.mft]
        attribute = mft_entry.get_attribute(
            self.plugin_args.type, self.plugin_args.id)
        data = attribute.data

        if data:
            dump_plugin = self.session.plugins.dump(
                offset=self.offset, address_space=data)
            dump_plugin.render(renderer)
            self.offset = dump_plugin.offset


class IExport(core.DirectoryDumperMixin, IDump):
    """Extracts files from NTFS.

    For each specified MFT entry, dump the file to the specified dump
    directory. The filename is taken as the longest filename of this MFT entry.
    """

    name = "iexport"

    def render(self, renderer):
        mft_entry = self.ntfs.mft[self.plugin_args.mft]
        filename = mft_entry.full_path or ("MFT_%s" % self.plugin_args.mft)
        attribute = mft_entry.get_attribute(self.plugin_args.type,
                                            self.plugin_args.id)

        in_as = attribute.data
        if in_as:
            renderer.format(
                "Writing MFT Entry {0} as {1}\n",
                self.plugin_args.mft, filename)

            with renderer.open(directory=self.dump_dir,
                               filename=filename, mode="wb") as out_fd:
                utils.CopyAStoFD(
                    in_as, out_fd, cb=lambda x, _: renderer.RenderProgress(
                        "Wrote %s bytes" % x))


class TestIExport(testlib.HashChecker):
    PARAMETERS = dict(
        commandline="iexport %(mfts)s --dump_dir %(tempdir)s"
    )


class TestIStat(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="istat %(mfts)s"
    )


class TestFStat(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="fstat %(path)s"
    )

class TestIDump(testlib.HashChecker):
    PARAMETERS = dict(
        commandline="idump %(mft)s %(type)s %(id)s",
        type=128,
        id=1
    )
