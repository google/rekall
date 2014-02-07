# Overlays for parsing NTFS structures.
import array
import struct

from rekall import addrspace
from rekall import config
from rekall import plugin
from rekall import obj
from rekall.plugins.overlays import basic


class Error(Exception):
    pass


class ParseError(Error):
    pass


class NTFSParseError(ParseError):
    pass


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
            "_mft_record_size": [64, ["unsigned char"]],
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
                        bitmap=FILE_FLAGS)]],
            "max_versions": [36, ["unsigned int"]],
            "version": [40, ["unsigned int"]],
            "class_id": [44, ["unsigned int"]],
            "owner_id": [48, ["unsigned int"]],
            "sid": [52, ["unsigned int"]],
            "quota": [56, ["unsigned long long"]],
            "usn": [64, ["unsigned int"]],
            }],

    "FILE_NAME": [None, {
            "parent_mft": [0, ["unsigned long long"]],
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
    }


class FixupAddressSpace(addrspace.BaseAddressSpace):
    """An address space to implement record fixup."""

    def __init__(self, fixup_magic, fixup_table, base_offset, length, **kwargs):
        super(FixupAddressSpace, self).__init__(**kwargs)
        self.as_assert(self.base is not None, "Address space must be stacked.")
        self.base_offset = base_offset

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


class RunListAddressSpace(addrspace.PagedReader):
    """An address space which is initialized from a runlist."""

    def __init__(self, run_list, cluster_size=None, **kwargs):
        super(RunListAddressSpace, self).__init__(**kwargs)
        self.PAGE_SIZE = cluster_size or self.session.cluster_size
        self.run_list = run_list

    def vtop(self, vaddr):
        """Convert from virtual linear address to the physical offset."""
        cluster_offset = vaddr % self.PAGE_SIZE
        cluster_number = vaddr / self.PAGE_SIZE
        return (self.run_list[cluster_number] * self.PAGE_SIZE +
                cluster_offset)



class MFT_ENTRY(obj.Struct):
    """An MFT Entry."""

    def __init__(self, **kwargs):
        super(MFT_ENTRY, self).__init__(**kwargs)

        # We implement fixup by wrapping the base address space with a fixed
        # one:
        self.obj_vm = FixupAddressSpace(fixup_magic=self.fixup_magic,
                                        fixup_table=self.fixup_table,
                                        base_offset=self.obj_offset,
                                        length=self.mft_entry_allocated,
                                        base=self.obj_vm)

    @property
    def attributes(self):
        for attribute in self._attributes:
            if attribute.type == 0xFFFFFFFF:
                break

            yield attribute


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

    @property
    def data(self):
        """Returns an address space representing the data of this attribute."""
        if self.resident:
            return addrspace.BufferAddressSpace(
                data=self.obj_vm.read(
                    self.obj_offset + self.content_offset,
                    self.content_size))
        else:
            # Create a defragmented address space.
            address_space = RunListAddressSpace(
                run_list=list(self.RunList()),
                base=self.session.physical_address_space,
                session=self.session)

            return address_space

    def DecodeAttribute(self):
        if self.type == "$STANDARD_INFORMATION":
            return self.obj_profile.STANDARD_INFORMATION(
                offset=0, vm=self.data)

        elif self.type == "$FILE_NAME":
            return self.obj_profile.FILE_NAME(
                offset=0, vm=self.data)

        elif self.type == "$DATA":
            return list(self.RunList())

    def RunList(self):
        """Decodes the runlist for this attribute."""
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

            for i in range(run_offset, run_offset + run_length):
                yield i


class NTFSProfile(basic.ProfileLLP64, basic.BasicClasses):
    """A profile for the NTFS."""

    def __init__(self, **kwargs):
        super(NTFSProfile, self).__init__(**kwargs)
        self.add_overlay(ntfs_vtypes)
        self.add_classes(dict(
                NTFS_BOOT_SECTOR=NTFS_BOOT_SECTOR,
                MFT_ENTRY=MFT_ENTRY,
                NTFS_ATTRIBUTE=NTFS_ATTRIBUTE,
                ))

        # We start off with a constant mapping of attribute types. This may
        # later be updated when parsing the $AttrDef file.
        self.add_constants(ATTRIBUTE_NAMES={
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
                })


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
                print run_list

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



class FLS(plugin.Command):
    """List files in an NTFS image."""

    __name = "fls"

    @classmethod
    def args(cls, parser):
        super(FLS, cls).args(parser)
        parser.add_argument(
            "mfts", action=config.ArrayIntParser, nargs="+",
            help="MFT entries to list.")

    def __init__(self, mfts=None, **kwargs):
        super(FLS, self).__init__(**kwargs)
        self.mfts = mfts

    @classmethod
    def is_active(cls, session):
        return isinstance(session.profile, NTFSProfile)

    def render(self, renderer):
        ntfs = NTFS(self.session.physical_address_space,
                    session=self.session)

        for mft in self.mfts:
            for attribute in ntfs.mft[mft].attributes:
                print attribute

                decoded_attribute = attribute.DecodeAttribute()
                if decoded_attribute:
                    print decoded_attribute

