from __future__ import print_function
# Rekall Memory Forensics
#
# Copyright (C) 2012 Nir Izraeli (nirizr at gmail dot com)
# Copyright 2012 Sebastien Bourdon-Richard
# Copyright 2013 Google Inc. All Rights Reserved.

# Authors:
# Sebastien Bourdon-Richard, Nir Izraeli
# Adapted for Rekall by Michael Cohen <scudette@google.com>.
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

from builtins import zip
from rekall import addrspace
from rekall import obj
from rekall.plugins.addrspaces import standard
from rekall.plugins.overlays import basic
from rekall_lib import utils

# pylint: disable=protected-access


class VMemAddressSpace(addrspace.RunBasedAddressSpace):
    __image = True

    def __init__(self, base=None, **kwargs):
        """Currently this AS only supports files with the .vmem extension."""
        self.as_assert(base != None, "No base address space provided")
        self.as_assert(
            getattr(base, "fname", "").endswith("vmem"),
            "Only VMEM files supported.")

        super(VMemAddressSpace, self).__init__(base=base, **kwargs)

        vmss_location = base.fname[:-4] + "vmss"
        try:
            vmss_as = standard.FileAddressSpace(
                filename=vmss_location, session=self.session)
        except IOError:
            # If we fail to open the vmss file it is not a proper vmem file.
            raise addrspace.ASAssertionError

        vmss_profile = VMWareProfile(session=self.session)
        self.header = vmss_profile._VMWARE_HEADER(vm=vmss_as)
        self.as_assert(
            self.header.Magic in [
                0xbed2bed0, 0xbad1bad1, 0xbed2bed2, 0xbed3bed3],
            "Invalid VMware signature: {0:#x}".format(self.header.Magic))

        # Fill in the runs list from the header.
        virtual_offsets = self.header.GetTags("memory", "regionPPN")
        file_offsets = self.header.GetTags("memory", "regionPageNum")
        lengths = self.header.GetTags("memory", "regionSize")

        for v, p, l in zip(virtual_offsets, file_offsets, lengths):
            self.add_run(v.Data * 0x1000, p.Data * 0x1000, l.Data * 0x1000)


class VMSSAddressSpace(addrspace.RunBasedAddressSpace):
    """Support ESX .vmsn file format.

    The VMSN file format contains a set of metadata in the form of tags, grouped
    by groups at the header. There is a lot of metadata but the most interesting
    metadata for us is the metadata in the "memory" group.

    The file includes a "memory.Memory" data blob which contains the entire
    memory snapshot of the running machine. The memory blob is serialized into
    the file as a single large blob but contains physical memory runs stored
    back to back inside it.

    The following tags are used:

    - memory.regionsCount: Stores the total number of regions.

    - memory.regionPPN: In an array of physical addresses for each physical
      memory regions in the virtual machine (in pages).

    - memory.regionSize: Is the size of each physical memory region (in pages).

    - memory.regionPageNum: Is the offset into the memory.Memory blob for each
      region (in pages). This may be omitted if there is only one region.
    """
    __image = True

    def __init__(self, base=None, **kwargs):
        self.as_assert(base != None, "No base address space provided")
        super(VMSSAddressSpace, self).__init__(base=base, **kwargs)

        vmss_profile = VMWareProfile(session=self.session)

        self.header = vmss_profile._VMWARE_HEADER(vm=self.base)
        self.as_assert(
            self.header.Magic in [
                0xbed2bed0, 0xbad1bad1, 0xbed2bed2, 0xbed3bed3],
            "Invalid VMware signature: {0:#x}".format(self.header.Magic))

        region_count = self.header.GetTagsData("memory", "regionsCount")[0]

        # Fill in the runs list from the header.
        virtual_offsets = self.header.GetTagsData("memory", "regionPPN")
        lengths = self.header.GetTagsData("memory", "regionSize")

        # This represents a single memory blob stored in the output file. The
        # regions are marked relative to this single blob.
        memory = self.header.GetTagsData("memory", "Memory")[0]
        mem_regions = self.header.GetTagsData("memory", "regionPageNum") or [0]

        for v, l, m in zip(virtual_offsets, lengths, mem_regions):
            self.add_run(
                v * 0x1000, m * 0x1000 + memory.obj_offset, l * 0x1000)

        # We should have enough regions here.
        if region_count != len(list(self.runs)):
            self.session.logging.error(
                "VMSN file has incorrect number of runs %s, "
                "should be %s", region_count, len(list(self.runs)))


class _VMWARE_HEADER(obj.Struct):
    """Add convenience methods to the header."""

    def __init__(self, **kwargs):
        super(_VMWARE_HEADER, self).__init__(**kwargs)
        self.obj_context["version"] = self.Version

    def PrintAllTags(self):
        for group in self.Groups:
            for tag in group.Tags:
                print("%s.%s: %r" % (group.Name, tag.Name, tag.Data))

    def GetTags(self, group_name, tag_name):
        result = []
        for group in self.Groups:
            if group.Name != group_name:
                continue

            for tag in group.Tags:
                if tag.Name != tag_name:
                    continue

                result.append(tag)

        return result

    def GetTagsData(self, group_name, tag_name):
        return [x.Data for x in self.GetTags(group_name, tag_name)]


class _VMWARE_GROUP(obj.Struct):

    @utils.safe_property
    def Tags(self):
        tag = self.TagsPointer.deref()
        while tag.NameLength > 0:
            yield tag

            tag = tag.Next()


class _VMWARE_TAG(obj.Struct):

    DATA_MAP = {
        1: "unsigned char",
        2: "unsigned short",
        4: "unsigned int",
        8: "unsigned long long",
        }

    @utils.safe_property
    def Data(self):
        """The data immediately follows the TagIndices array.

        The size and type of the data is specified by the DataSize member. If
        the DataSize takes on the special values 62 or 63, then the data is
        described by an extended data descriptor (We call it
        _VMWARE_EXTENDED_DATA64).
        """
        # The data immediately follows the TagIndices array.
        data_offset = self.TagIndices.obj_end
        data_size = self.DataSize

        # The Data member is described by an extended struct.
        if data_size in (62, 63):
            # Depending on the version, the extended struct changes.
            if self.obj_context.get("Version") == 0:
                return self.obj_profile._VMWARE_EXTENDED_DATA32(
                    data_offset, vm=self.obj_vm).Data
            else:
                return self.obj_profile._VMWARE_EXTENDED_DATA64(
                    data_offset, vm=self.obj_vm).Data

        # Is the data member a simple type?
        data_type = self.DATA_MAP.get(data_size)
        if data_type:
            return self.obj_profile.Object(
                data_type, offset=data_offset, vm=self.obj_vm)

        # If the size is odd, we just return the data as a string.
        return self.obj_profile.String(
            offset=self.TagIndices.obj_end, term=None, length=data_size,
            vm=self.obj_vm)

    def Next(self):
        """The next tag is immediately after this tag."""
        return self.obj_profile._VMWARE_TAG(
            self.Data.obj_end, vm=self.obj_vm, context=self.obj_context)


class VMWareProfile(basic.BasicClasses):
    """A profile for parsing VMWare structures."""
    @classmethod
    def Initialize(cls, profile):
        super(VMWareProfile, cls).Initialize(profile)
        basic.ProfileLLP64.Initialize(profile)

        profile.add_overlay({
            '_VMWARE_HEADER': [12, {
                'Magic': [0, ['unsigned int']],

                'Version': [0, ["BitField", dict(
                    start_bit=0,
                    end_bit=4,
                    target="unsigned int")]],

                'GroupCount': [8, ['unsigned int']],
                'Groups': [12, ['Array', dict(
                    count=lambda x: x.GroupCount,
                    target='_VMWARE_GROUP',
                    )]],
                }],

            '_VMWARE_GROUP': [80, {
                'Name': [0, ['UnicodeString', dict(
                    length=64,
                    encoding='utf8')]],

                # A pointer to a back to back list of tags within this
                # group. Note tags are variable length - to get the next tag use
                # _VMWARE_TAG.Next(), or simply use the _VMWARE_GROUP.Tags()
                # iterator as a convenience.
                'TagsPointer': [64, ['Pointer', dict(
                    target="_VMWARE_TAG"
                    )]],
                }],

            # This struct is used to denote data objects with a length 62 bytes
            # or greater.
            '_VMWARE_EXTENDED_DATA64': [None, {
                'DataDiskSize': [0, ['unsigned long long']],
                'DataMemSize': [8, ['unsigned long long']],

                # A padding string is specified as a short before the actual
                # data.
                'PaddingLen': [16, ['unsigned short']],
                'Padding': [18, ['String', dict(
                    length=lambda x: x.PaddingLen,
                    term=None,
                    )]],

                # The data follows the padding string. Its length is specified
                # by DataDiskSize.
                'Data': [lambda x: x.Padding.obj_end, ["String", dict(
                    term=None,
                    length=lambda x: x.DataDiskSize,
                    )]],
                }],

            # This is the old struct only used with Version 0. It is the same as
            # _VMWARE_EXTENDED_DATA64 except uses 32 bit sizes.
            '_VMWARE_EXTENDED_DATA32': [None, {
                'DataDiskSize': [0, ['unsigned long']],
                'DataMemSize': [4, ['unsigned long']],
                'PaddingLen': [8, ['unsigned short']],
                'Padding': [10, ['String', dict(
                    length=lambda x: x.PaddingLen,
                    term=None,
                    )]],
                'Data': [lambda x: x.Padding.obj_end, ["String", dict(
                    term=None,
                    length=lambda x: x.DataDiskSize
                    )]],
                }],

            '_VMWARE_TAG': [None, {
                'TagIndicesCount': [0, ['BitField', dict(
                    start_bit=6,
                    end_bit=9,
                    target="unsigned char")]],

                'DataSize': [0, ['BitField', dict(
                    start_bit=0,
                    end_bit=6,
                    target="unsigned char")]],

                # The name of this tag. Tags exist within the group (which also
                # has a name).
                'NameLength': [1, ['unsigned char']],
                'Name': [2, ['UnicodeString', dict(
                    length=lambda x: x.NameLength,
                    encoding='utf8')]],

                # The TagIndices immediately follow the Name field (Which has
                # variable length).
                'TagIndices': [lambda x: x.Name.obj_end,
                               ['Array', dict(
                                   count=lambda x: x.TagIndicesCount,
                                   target='unsigned int')]],

                }],
            })

        profile.add_classes(
            _VMWARE_TAG=_VMWARE_TAG,
            _VMWARE_GROUP=_VMWARE_GROUP,
            _VMWARE_HEADER=_VMWARE_HEADER,
            )
