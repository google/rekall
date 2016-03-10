# Rekall Memory Forensics
# Copyright (c) 2012 Michael Cohen <scudette@gmail.com>
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
# Copyright 2013 Google Inc. All Rights Reserved.
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

"""This is the registry parser.

We parse registry structures from files or memory.
"""
__author__ = ("Michael Cohen <scudette@gmail.com> based on original code "
              "by Brendan Dolan-Gavitt")

# pylint: disable=protected-access

import ntpath
import re
import struct

from rekall import addrspace
from rekall import obj
from rekall import utils

from rekall.plugins.windows import common


registry_overlays = {
    '_CM_KEY_NODE': [None, {
        'Parent': [None, ['Pointer32', dict(
            target='_CM_KEY_NODE'
            )]],
        'Flags': [None, ['Flags', dict(bitmap={
            "KEY_IS_VOLATILE": 0,
            "KEY_HIVE_EXIT": 1,
            "KEY_HIVE_ENTRY": 2,
            "KEY_NO_DELETE": 3,
            "KEY_SYM_LINK": 4,
            "KEY_COMP_NAME": 5,
            "KEY_PREFEF_HANDLE": 6,
            "KEY_VIRT_MIRRORED": 7,
            "KEY_VIRT_TARGET": 8,
            "KEY_VIRTUAL_STORE": 9,
            })]],

        'Signature' : [None, ['String', dict(length=2)]],
        'LastWriteTime' : [None, ['WinFileTime', {}]],
        'Name' : [None, ['String', dict(length=lambda x: x.NameLength)]],
        }],

    '_CM_KEY_VALUE': [None, {
        'Signature' : [None, ['String', dict(length=2)]],
        'Name' : [None, ['String', dict(length=lambda x: x.NameLength)]],

        'Type': [None, ['Enumeration', dict(choices={
            0: "REG_NONE",
            1: "REG_SZ",
            2: "REG_EXPAND_SZ",
            3: "REG_BINARY",
            4: "REG_DWORD",
            5: "REG_DWORD_BIG_ENDIAN",
            6: "REG_LINK",
            7: "REG_MULTI_SZ",
            8: "REG_RESOURCE_LIST",
            9: "REG_FULL_RESOURCE_DESCRIPTOR",
            10: "REG_RESOURCE_REQUIREMENTS_LIST",
            11: "REG_QWORD",
            })]]
        }],

    '_CM_NAME_CONTROL_BLOCK' : [None, {
        'Name' : [None, ['String', dict(length=lambda x: x.NameLength)]],
        }],

    '_CHILD_LIST' : [None, {
        'List' : [None, ['Pointer32', dict(
            target="Array",
            target_args=dict(
                count=lambda x: x.Count,
                target="Pointer32",
                target_args=dict(
                    target="_CM_KEY_VALUE"
                    )
                )
            )]],
        }],

    '_CM_KEY_INDEX' : [None, {
        'Signature' : [None, ['String', dict(length=2)]],
        'List' : [None, ["Array", dict(
            count=lambda x: x.Count.v() * 2,
            target="Pointer32",
            target_args=dict(
                target='_CM_KEY_NODE'
                )
            )]],
        }],
    }

class _HMAP_ENTRY(obj.Struct):
    """Windows uses this to track registry HBIN cells mapped into memory."""

    @utils.safe_property
    def BlockAddress(self):
        """Compatibility field for Windows 7 and Windows 10."""
        if "BlockAddress" in self.members:
            return self.m("BlockAddress")

        # Windows 10 uses a different field.
        return self.PermanentBinAddress & 0xfffffffffff0


class HiveBaseAddressSpace(addrspace.PagedReader):
    __abstract = True
    BLOCK_SIZE = PAGE_SIZE = 0x1000


class HiveFileAddressSpace(HiveBaseAddressSpace):
    """Translate between hive addresses and a flat file address space.

    This is suitable for reading regular registry files. It should be
    stacked over the FileAddressSpace.
    """
    def __init__(self, **kwargs):
        super(HiveFileAddressSpace, self).__init__(**kwargs)
        self.as_assert(self.base, "Must stack on top of a file.")
        self.as_assert(self.base.read(0, 4) == "regf", "File does not look "
                       "like a registry file.")

    def vtop(self, vaddr):
        return vaddr + self.PAGE_SIZE + 4

    @utils.safe_property
    def Name(self):
        return self.base


class HiveAddressSpace(HiveBaseAddressSpace):
    CI_TYPE_MASK = 0x80000000
    CI_TYPE_SHIFT = 0x1F
    CI_TABLE_MASK = 0x7FE00000
    CI_TABLE_SHIFT = 0x15
    CI_BLOCK_MASK = 0x1FF000
    CI_BLOCK_SHIFT = 0x0C
    CI_OFF_MASK = 0x0FFF
    CI_OFF_SHIFT = 0x0

    def __init__(self, hive_addr=None, profile=None, **kwargs):
        """Translate between hive addresses and virtual memory addresses.

        This must be constructed over the kernel virtual memory.
        Args:
           hive_addr: The virtual address of the _CMHIVE object.
           profile: A profile which holds registry symbols.
        """
        super(HiveAddressSpace, self).__init__(**kwargs)

        self.as_assert(hive_addr, "Hive offset not provided.")
        self.as_assert(self.base, "Must be layered on kernel address space.")
        self.profile = RekallRegisteryImplementation(
            profile or self.session.profile)

        self.hive = self.profile._CMHIVE(offset=hive_addr, vm=self.base)
        self.baseblock = self.hive.Hive.BaseBlock.v()
        self.flat = self.hive.Hive.Flat.v() > 0
        self.storage = self.hive.Hive.Storage

        # This is a quick lookup for blocks.
        self.block_cache = utils.FastStore(max_size=1000)

        self.logging = self.session.logging.getChild("addrspace.hive")

    def vtop(self, vaddr):
        vaddr = int(vaddr)

        # If the hive is listed as "flat", it is all contiguous in memory
        # so we can just calculate it relative to the base block.
        if self.flat:
            return self.baseblock + vaddr + self.BLOCK_SIZE + 4

        ci_type = (vaddr & self.CI_TYPE_MASK) >> self.CI_TYPE_SHIFT
        ci_table = (vaddr & self.CI_TABLE_MASK) >> self.CI_TABLE_SHIFT
        ci_block = (vaddr & self.CI_BLOCK_MASK) >> self.CI_BLOCK_SHIFT
        ci_off = (vaddr & self.CI_OFF_MASK) >> self.CI_OFF_SHIFT

        try:
            block = self.block_cache.Get((ci_type, ci_table, ci_block))
        except KeyError:
            block = self.storage[ci_type].Map.Directory[ci_table].Table[
                ci_block].BlockAddress

            self.block_cache.Put((ci_type, ci_table, ci_block), block)

        return block + ci_off + 4

    def save(self):
        """A generator of registry data in linear form.

        This can be used to write a registry file.

        Yields:
           blocks of data in order.
        """
        baseblock = self.base.read(self.baseblock, self.BLOCK_SIZE)
        if baseblock:
            yield baseblock
        else:
            yield "\0" * self.BLOCK_SIZE

        length = self.hive.Hive.Storage[0].Length.v()
        for i in xrange(0, length, self.BLOCK_SIZE):
            paddr = self.vtop(i)
            if not paddr:
                self.logging.warn("No mapping found for index {0:x}, "
                             "filling with NULLs".format(i))
                data = '\0' * self.BLOCK_SIZE
            else:
                paddr = paddr - 4
                data = self.base.read(paddr, self.BLOCK_SIZE)
                if not data:
                    self.logging.warn("Physical layer returned None for index "
                                 "{0:x}, filling with NULL".format(i))
                    data = '\0' * self.BLOCK_SIZE

            yield data

    def stats(self, stable=True):
        if stable:
            stor = 0
            ci = lambda x: x
        else:
            stor = 1
            ci = lambda x: x | 0x80000000

        length = self.hive.Hive.Storage[stor].Length.v()
        total_blocks = length / self.BLOCK_SIZE
        bad_blocks_reg = 0
        bad_blocks_mem = 0
        for i in xrange(0, length, self.BLOCK_SIZE):
            i = ci(i)
            data = None
            paddr = self.vtop(i) - 4

            if paddr:
                data = self.base.read(paddr, self.BLOCK_SIZE)
            else:
                bad_blocks_reg += 1
                continue

            if not data:
                bad_blocks_mem += 1

        print("{0} bytes in hive.".format(length))
        print(("{0} blocks not loaded by CM, {1} blocks "
               "paged out, {2} total blocks.".format(
                   bad_blocks_reg, bad_blocks_mem, total_blocks)))

        if total_blocks:
            print("Total of {0:.2f}% of hive unreadable.".format(
                ((bad_blocks_reg + bad_blocks_mem) / float(total_blocks)
                ) * 100))

        return (bad_blocks_reg, bad_blocks_mem, total_blocks)

    @utils.safe_property
    def Name(self):
        return self.hive.Name


class _CMHIVE(obj.Struct):
    @utils.safe_property
    def Name(self):
        name = "[no name]"
        try:
            name = (self.FileFullPath.v() or self.FileUserName.v() or
                    self.HiveRootPath.v())
        except AttributeError:
            pass

        object_tree_plugin = self.obj_session.plugins.object_tree()

        return u"{0} @ {1:#010x}".format(
            object_tree_plugin.FileNameWithDrive(name) or "Unnamed",
            self.obj_offset)


class _CM_KEY_NODE(obj.Struct):
    """A registry key."""
    NK_SIG = "nk"
    VK_SIG = "vk"

    def open_subkey(self, subkey_name):
        """Opens our direct child."""
        for subkey in self.subkeys():
            if unicode(subkey.Name).lower() == subkey_name.lower():
                return subkey

        return obj.NoneObject("Couldn't find subkey {0} of {1}",
                              subkey_name, self.Name)

    def open_value(self, value_name):
        """Opens our direct child."""
        for value in self.values():
            if value.Name == value_name:
                return value

        return obj.NoneObject("Couldn't find subkey {0} of {1}",
                              value_name, self.Name)

    def subkeys(self):
        """Enumeate all subkeys of this key.

        How are subkeys stored in each key record?

        There are usually two subkey lists - these are pointers to _CM_KEY_INDEX
        which are just a list of pointers to other subkeys.
        """
        # There are multiple lists of subkeys:
        sk_lists = self.SubKeyLists
        for list_index, count in enumerate(self.SubKeyCounts):
            if count > 0:
                sk_offset = sk_lists[list_index]
                for subkey in self.obj_profile._CM_KEY_INDEX(
                        offset=sk_offset, vm=self.obj_vm, parent=self):
                    yield subkey

    def values(self):
        """Enumerate all the values of the key."""
        for value_ptr in self.ValueList.List.dereference():
            value = value_ptr.dereference()
            if value.Signature == self.VK_SIG:
                yield value

    @utils.safe_property
    def Path(self):
        """Traverse our parent objects to print the full path of this key."""
        path = []
        key = self
        while key:
            try:
                path.append(unicode(key.Name))
            except AttributeError:
                pass
            key = key.obj_parent

        return "/".join(reversed(path))

    @utils.safe_property
    def Name(self):
        """The name of the key is actually a unicode object.
        This is encoded either in ascii or utf16 according to the Flags.
        """
        if self.Flags.KEY_COMP_NAME:
            return self.obj_profile.String(
                vm=self.obj_vm, offset=self.obj_profile.get_obj_offset(
                    self.obj_type, "Name") + self.obj_offset,
                length=self.NameLength)
        else:
            return self.obj_profile.UnicodeString(
                vm=self.obj_vm, offset=self.obj_profile.get_obj_offset(
                    self.obj_type, "Name") + self.obj_offset,
                length=self.NameLength, encoding="utf-16")



class _CM_KEY_INDEX(obj.Struct):
    """This is a list of pointers to key nodes.

    This work different depending on the Signature.
    """
    LH_SIG = "lh"
    LF_SIG = "lf"
    RI_SIG = "ri"
    LI_SIG = "li"
    NK_SIG = "nk"

    def __iter__(self):
        """Iterate over all the keys in the index.

        Depending on our type (from the Signature) we use different methods."""
        if self.Signature == self.LH_SIG or self.Signature == self.LF_SIG:
            # The List contains alternating pointers/hash elements here. We do
            # not care about the hash at all, so we skip every other entry. See
            # http://www.sentinelchicken.com/data/TheWindowsNTRegistryFileFormat.pdf
            key_list = self.List
            for i in xrange(self.Count * 2):
                nk = key_list[i]
                if nk.Signature == self.NK_SIG:
                    yield nk

        elif self.Signature == self.RI_SIG:
            for i in xrange(self.Count):
                # This is a pointer to another _CM_KEY_INDEX
                for subkey in self.obj_profile.Object(
                        "Pointer32", offset=self.List[i].v(),
                        vm=self.obj_vm, parent=self.obj_parent,
                        target="_CM_KEY_INDEX"):
                    if subkey.Signature == self.NK_SIG:
                        yield subkey

        elif self.Signature == self.LI_SIG:
            key_list = self.List
            for i in xrange(self.Count):
                nk = key_list[i]
                if nk.Signature == self.NK_SIG:
                    yield nk


class _CM_KEY_VALUE(obj.Struct):
    """A registry value."""

    value_formats = {"REG_DWORD": "<L",
                     "REG_DWORD_BIG_ENDIAN": ">L",
                     "REG_QWORD": "<Q"}

    @utils.safe_property
    def DecodedData(self):
        """Returns the data for this key decoded according to the type."""
        # When the data length is 0x80000000, the value is stored in the type
        # (as a REG_DWORD).
        if self.DataLength == 0x80000000:
            return self.Type.v()

        # If the high bit is set, the data is stored inline
        elif self.DataLength & 0x80000000:
            return self._decode_data(self.obj_vm.read(
                self.m("Data").obj_offset, self.DataLength & 0x7FFFFFFF))

        elif self.DataLength > 0x4000:
            return obj.NoneObject("Big data not supported.")

            big_data = self.obj_profile._CM_BIG_DATA(
                self.Data, vm=self.obj_vm)

            return self._decode_data(big_data.Data)

        else:
            return self._decode_data(self.obj_vm.read(
                int(self.m("Data")), self.DataLength))

    def _decode_data(self, data):
        """Decode the data according to our type."""
        valtype = str(self.Type)

        if valtype in ["REG_DWORD", "REG_DWORD_BIG_ENDIAN", "REG_QWORD"]:
            if len(data) != struct.calcsize(self.value_formats[valtype]):
                return obj.NoneObject(
                    "Value data did not match the expected data "
                    "size for a {0}".format(valtype))

        if valtype in ["REG_SZ", "REG_EXPAND_SZ", "REG_LINK"]:
            data = data.decode('utf-16-le', "ignore")

        elif valtype == "REG_MULTI_SZ":
            data = data.decode('utf-16-le', "ignore").split('\0')

        elif valtype in ["REG_DWORD", "REG_DWORD_BIG_ENDIAN", "REG_QWORD"]:
            data = struct.unpack(self.value_formats[valtype], data)[0]

        return data


def RekallRegisteryImplementation(profile):
    """The standard rekall registry parsing subsystem."""
    profile.add_classes(dict(
        _CM_KEY_NODE=_CM_KEY_NODE, _CM_KEY_INDEX=_CM_KEY_INDEX,
        _CM_KEY_VALUE=_CM_KEY_VALUE, _CMHIVE=_CMHIVE,
        _HMAP_ENTRY=_HMAP_ENTRY,
        ))

    profile.add_overlay(registry_overlays)
    return profile


class Registry(object):
    """A High level class to abstract access to the registry hive."""
    ROOT_INDEX = 0x20
    VK_SIG = "vk"

    BIG_DATA_MAGIC = 0x3fd8

    def __init__(self, session=None, profile=None, address_space=None,
                 filename=None, stable=True):
        """Abstract a registry hive.

        Args:
           session: An optional session object.
           profile: A profile to operate on. If not provided we use
             session.profile.
           address_space: An instance of the HiveBaseAddressSpace.
           filename: If the registry exists in a file, specify the filename to
             save instantiating the address_space.
           stable: Should we try to open the unstable registry area?
        """
        self.session = session
        self.profile = RekallRegisteryImplementation(
            profile or session.profile)

        if filename is not None:
            base_as = HiveFileAddressSpace.classes['FileAddressSpace'](
                filename=filename, session=session)
            address_space = HiveFileAddressSpace(base=base_as)

        self.address_space = address_space

        root_index = self.ROOT_INDEX
        if not stable:
            root_index = self.ROOT_INDEX | 0x80000000

        self.root = self.profile.Object(
            "_CM_KEY_NODE", offset=root_index, vm=address_space)

    @utils.safe_property
    def Name(self):
        """Return the name of the registry."""
        return self.address_space.Name

    def open_key(self, key=""):
        """Opens a key.

        Args:
           key: A string path to the key (separated with / or \\) or a list of
              path components (useful if the keyname contains /).
        """
        if isinstance(key, basestring):
            # / can be part of the key name...
            key = filter(None, re.split(r"[\\/]", key))

        result = self.root
        for component in key:
            result = result.open_subkey(component)

        return result

    def open_value(self, path):
        key = self.open_key(ntpath.dirname(path))

        return key.open_value(ntpath.basename(path))

    def CurrentControlSet(self):
        """Return the key for the CurrentControlSet."""
        current = self.open_value("Select/Current").DecodedData
        if not current:
            current = 1

        return self.open_key("ControlSet00%s" % current)


class RegistryHive(Registry):
    def __init__(self, hive_offset=None, kernel_address_space=None,
                 profile=None,
                 session=None, **kwargs):
        """A Registry hive instantiated from the hive offsets.

        Args:
          hive_offset: The virtual offset of the hive.
          kernel_address_space: The kernel address space.
        """
        if session:
            profile = profile or session.profile
            kernel_address_space = (kernel_address_space or
                                    session.kernel_address_space)

        hive_address_space = HiveAddressSpace(base=kernel_address_space,
                                              hive_addr=hive_offset,
                                              profile=profile,
                                              session=session)

        super(RegistryHive, self).__init__(
            session=session, profile=profile, address_space=hive_address_space,
            **kwargs)


class RegistryPlugin(common.WindowsCommandPlugin):
    """A generic registry plugin."""

    __abstract = True

    @classmethod
    def args(cls, parser):
        super(RegistryPlugin, cls).args(parser)

        parser.add_argument(
            "--hive-offsets", default=None, type="ArrayIntParser",
            help="A list of hive offsets as found by hivelist. "
            "If not provided we call hivelist ourselves and list "
            "the keys on all hives.")

        parser.add_argument("--hive_regex", default=None,
                            help="A regex to filter hive names."
                            "If not provided we use all hives.")


    def __init__(self, hive_offsets=None, hive_regex=None, **kwargs):
        """Operate on in memory registry hives.

        Args:
          hive_offset: A list of hive offsets as found by hivelist (virtual
            address). If not provided we call hivescan ourselves and list the
            key on all hives.
        """
        super(RegistryPlugin, self).__init__(**kwargs)

        # Install our specific implementation of registry support.
        RekallRegisteryImplementation(self.profile)

        self.hive_offsets = hive_offsets
        if not self.hive_offsets:
            self.hive_offsets = list(self.list_hives())

        if hive_regex is not None:
            hive_offsets = []
            for hive in self.hive_offsets:
                m = re.search(hive_regex, utils.SmartUnicode(hive.Name), re.I)
                if m:
                    hive_offsets.append(hive)

            self.hive_offsets = hive_offsets

    def list_hives(self):
        hive_list = self.profile.get_constant_object(
            "CmpHiveListHead", "_LIST_ENTRY")

        return hive_list.list_of_type("_CMHIVE", "HiveList")


class Hives(RegistryPlugin):
    """List all the registry hives on the system."""

    name = "hives"

    def render(self, renderer):
        renderer.table_header([("Offset", "offset", "[addrpad]"),
                               ("Name", "name", "")])

        for hive in self.list_hives():
            renderer.table_row(hive, hive.Name)
