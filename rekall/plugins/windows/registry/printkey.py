# Rekall Memory Forensics
# Copyright (C) 2012 Michael Cohen <scudette@gmail.com>
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

"""
@author:       Michael Cohen <scudette@gmail.com>
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""
import re

from rekall import addrspace
from rekall import utils
from rekall.plugins import core
from rekall.plugins.windows.registry import registry
from rekall.plugins.overlays import basic


class PrintKey(registry.RegistryPlugin):
    """Print a registry key, and its subkeys and values"""
    __name = "printkey"

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(PrintKey, cls).args(parser)

        parser.add_argument("-k", "--key", default="",
                            help="Registry key to print.")

        parser.add_argument("-r", "--recursive", default=False,
                            type="Boolean",
                            help='If set print the entire subtree.')


    def __init__(self, key="", recursive=False, **kwargs):
        """Print all keys and values contained by a registry key.

        Args:
          key: The key name to list. If not provided we list the root key in the
            hive.

          recursive: If set print the entire subtree.
        """
        super(PrintKey, self).__init__(**kwargs)
        self.key = key
        self.recursive = recursive

    def _list_keys(self, key=None):
        yield key

        if self.recursive:
            for subkey in key.subkeys():
                for subkey in self._list_keys(subkey):
                    yield subkey

    def list_keys(self):
        """Return the keys that match."""
        seen = set()
        for hive_offset in self.hive_offsets:
            reg = registry.RegistryHive(
                profile=self.profile, session=self.session,
                kernel_address_space=self.kernel_address_space,
                hive_offset=hive_offset)

            key = reg.open_key(self.key)
            for subkey in self._list_keys(key):
                if subkey in seen:
                    break

                seen.add(subkey)

                yield reg, subkey

    def voltext(self, key):
        """Returns a string representing (S)table or (V)olatile keys."""
        return "(V)" if key.obj_offset & 0x80000000 else "(S)"

    def render(self, renderer):
        renderer.format("Legend: (S) = Stable   (V) = Volatile\n\n")
        for reg, key in self.list_keys():
            self.session.report_progress(
                "Printing %s", lambda key=key: key.Path)

            if key:
                renderer.format("----------------------------\n")
                renderer.format("Registry: {0}\n", reg.Name)
                renderer.format("Key name: {0} {1} @ {2:addrpad}\n", key.Name,
                                self.voltext(key), key.obj_vm.vtop(int(key)))

                renderer.format("Last updated: {0}\n", key.LastWriteTime)
                renderer.format("\n")
                renderer.format("Subkeys:\n")

                for subkey in key.subkeys():
                    if not subkey.Name:
                        renderer.format(
                            "  Unknown subkey: {0}\n", subkey.Name.reason)
                    else:
                        renderer.format(u"  {1} {0}\n",
                                        subkey.Name, self.voltext(subkey))

                renderer.format("\n")
                renderer.format("Values:\n")
                for value in key.values():
                    renderer.format("{0:addrpad} ", value.obj_vm.vtop(value))
                    if value.Type == 'REG_BINARY':
                        data = value.DecodedData
                        if isinstance(data, basestring):
                            renderer.format(
                                u"{0:width=13} {1:width=15} : {2}\n",
                                value.Type, value.Name, self.voltext(value))
                            utils.WriteHexdump(renderer, value.DecodedData)
                    else:
                        renderer.format(
                            u"{0:width=13} {1:width=15} : {2} {3}\n",
                            value.Type, value.Name, self.voltext(value),
                            utils.SmartUnicode(value.DecodedData).strip())


class RegDump(core.DirectoryDumperMixin, registry.RegistryPlugin):
    """Dump all registry hives from memory into a dump directory."""

    __name = 'regdump'

    def dump_hive(self, hive_offset=None, reg=None, fd=None):
        """Write the hive into the fd.

        Args:
          hive_offset: The virtual offset where the hive is located.
          reg: Optionally an instance of registry.Registry helper. If provided
            hive_offset is ignored.
          fd: The file like object we write to.
        """
        if reg is None:
            reg = registry.RegistryHive(
                profile=self.profile,
                kernel_address_space=self.kernel_address_space,
                hive_offset=hive_offset)

        count = 0
        for data in reg.address_space.save():
            fd.write(data)
            count += len(data)
            self.session.report_progress(
                "Dumping {0}Mb".format(count/1024/1024))

    def render(self, renderer):
        # Get all the offsets if needed.
        for hive_offset in self.hive_offsets:
            reg = registry.RegistryHive(
                profile=self.profile, session=self.session,
                kernel_address_space=self.kernel_address_space,
                hive_offset=hive_offset)

            # Make up a filename for it, should be similar to the hive name.
            filename = reg.Name.rsplit("\\", 1).pop()

            # Sanitize it.
            filename = re.sub(r"[^a-zA-Z0-9_\-@ ]", "_", filename)

            # Make up the path.
            renderer.section()
            renderer.format("Dumping {0} into \"{1}\"\n", reg.Name, filename)

            with renderer.open(directory=self.dump_dir,
                               filename=filename,
                               mode="wb") as fd:
                self.dump_hive(reg=reg, fd=fd)
                renderer.format("Dumped {0} bytes\n", fd.tell())



class HiveDump(registry.RegistryPlugin):
    """Prints out a hive"""

    __name = "hivedump"

    def _key_iterator(self, key, seen):
        yield key

        if key in seen:
            return

        seen.add(key)

        for subkey in key.subkeys():
            for subsubkey in self._key_iterator(subkey, seen):
                yield subsubkey

    def render(self, renderer):
        seen = set()

        for hive_offset in self.hive_offsets:
            reg = registry.RegistryHive(
                hive_offset=hive_offset, session=self.session,
                kernel_address_space=self.kernel_address_space,
                profile=self.profile)

            renderer.section()
            renderer.format("Hive {0}\n\n", reg.Name)

            renderer.table_header([("Last Written", "timestamp", "<24"),
                                   ("Key", "key", "")])

            for key in self._key_iterator(reg.root, seen):
                renderer.table_row(key.LastWriteTime, key.Path)


# Special types to parse the SAM data structures.
sam_vtypes = {
    "UNICODE_STRING": [12, {
        "offset": [0, ["unsigned int"]],
        "len": [4, ["unsigned int"]],
        "Value": lambda x: x.obj_profile.UnicodeString(
            offset=x.offset+0xCC,
            length=x.len, vm=x.obj_vm),

        }],

    "Hash": [12, {
        "offset": [0, ["unsigned int"]],
        "len": [4, ["unsigned int"]],
        "Value": lambda x: x.obj_vm.read(
            x.offset+0xCC, x.len).encode("hex"),

        }],

    "V": [None, {
        "Type": [4, ["Enumeration", dict(
            choices={
                0xBC: "Default Admin User",
                0xd4: "Custom Limited Acct",
                0xb0: "Default Guest Acct"
                },
            target="unsigned int"
            )]],
        "UserName": [12, ['UNICODE_STRING']],
        "FullName": [24, ['UNICODE_STRING']],
        "Comment": [36, ['UNICODE_STRING']],
        "LanHash": [156, ['Hash']],
        "NTHash": [168, ['Hash']],
        }],

    "F": [None, {
        "LastLoginTime": [8, ['WinFileTime']],
        "PwdResetDate": [24, ["WinFileTime"]],
        "AccountExpiration": [32, ["WinFileTime"]],
        "PasswordFailedTime": [40, ["WinFileTime"]],
        "LoginCount": [66, ["unsigned short int"]],
        "FailedLoginCount": [64, ["unsigned short int"]],
        "Rid": [48, ["unsigned int"]],
        "Flags": [56, ["Flags", dict(
            maskmap=utils.Invert({
                0x0001: "Account Disabled",
                0x0002: "Home directory required",
                0x0004: "Password not required",
                0x0008: "Temporary duplicate account",
                0x0010: "Normal user account",
                0x0020: "MNS logon user account",
                0x0040: "Interdomain trust account",
                0x0080: "Workstation trust account",
                0x0100: "Server trust account",
                0x0200: "Password does not expire",
                0x0400: "Account auto locked"
                }),
            target="unsigned short int"
            )]],
        }],
    }



class SAMProfile(basic.Profile32Bits, basic.BasicClasses):
    """A profile to parse the SAM."""

    @classmethod
    def Initialize(cls, profile):
        super(SAMProfile, cls).Initialize(profile)

        profile.add_overlay(sam_vtypes)


class Users(registry.RegistryPlugin):
    """Enumerate all users of this system.

    Ref:
    samparse.pl from RegRipper.

    # copyright 2012 Quantum Analytics Research, LLC
    # Author: H. Carvey, keydet89@yahoo.com
    """
    name = "users"

    def GenerateUsers(self):
        """Generates User RID keys, V and F structs for all users."""
        sam_profile = SAMProfile(session=self.session)

        for hive_offset in self.hive_offsets:
            reg = registry.RegistryHive(
                hive_offset=hive_offset, session=self.session,
                kernel_address_space=self.kernel_address_space,
                profile=self.profile)

            users = reg.open_key("SAM/Domains/Account/Users")
            for user_rid in users.subkeys():
                # The V value holds the information we are after.
                v_data = user_rid.open_value("V")
                if not v_data:
                    continue

                v = sam_profile.V(vm=addrspace.BufferAddressSpace(
                    data=v_data.DecodedData, session=self.session))

                f_data = user_rid.open_value("F")
                f = sam_profile.F(vm=addrspace.BufferAddressSpace(
                    data=f_data.DecodedData, session=self.session))

                yield user_rid, v, f

    def render(self, renderer):
        for user_rid, v, f in self.GenerateUsers():
            renderer.section()
            renderer.format("Key {0} \n\n", user_rid.Path)
            renderer.table_header(
                columns=[("", "property", "20"),
                         ("", "value", "")],
                suppress_headers=True)

            for field in v.members:
                try:
                    renderer.table_row(field, getattr(v, field).Value)
                except AttributeError:
                    renderer.table_row(field, getattr(v, field))

            for field in f.members:
                renderer.table_row(field, getattr(f, field))


class Services(registry.RegistryPlugin):
    """Enumerate all services."""
    name = "services"

    # http://msdn.microsoft.com/en-us/library/windows/desktop/ms682450(v=vs.85).aspx
    # CreateService function.
    SERVICE_TYPE = {
        0x00000004: 'SERVICE_ADAPTER',
        0x00000002: 'SERVICE_FILE_SYSTEM_DRIVER',
        0x00000001: 'SERVICE_KERNEL_DRIVER',
        0x00000008: 'SERVICE_RECOGNIZER_DRIVER',
        0x00000010: 'SERVICE_WIN32_OWN_PROCESS',
        0x00000020: 'SERVICE_WIN32_SHARE_PROCESS'
        }

    START_TYPE = {
        0x00000002: 'SERVICE_AUTO_START',
        0x00000000: 'SERVICE_BOOT_START',
        0x00000003: 'SERVICE_DEMAND_START',
        0x00000004: 'SERVICE_DISABLED',
        0x00000001: 'SERVICE_SYSTEM_START'
        }

    ERROR_CONTROL = {
        0x00000003: 'SERVICE_ERROR_CRITICAL',
        0x00000000: 'SERVICE_ERROR_IGNORE',
        0x00000001: 'SERVICE_ERROR_NORMAL',
        0x00000002: 'SERVICE_ERROR_SEVERE'
        }

    def GenerateServices(self):
        for hive_offset in self.hive_offsets:
            reg = registry.RegistryHive(
                profile=self.profile, session=self.session,
                kernel_address_space=self.kernel_address_space,
                hive_offset=hive_offset)

            for service in reg.CurrentControlSet().open_subkey(
                "Services").subkeys():
                yield service

    def render(self, renderer):
        for service in self.GenerateServices():
            renderer.section(service.Name.v())
            renderer.table_header([("Key", "key", "20"),
                                   ("Value", "value", "[wrap:60]")],
                                  suppress_headers=True)

            for value in service.values():
                k = value.Name.v()
                v = value.DecodedData
                if value.Type == "REG_BINARY":
                    continue

                if isinstance(v, list):
                    v = ",".join([x for x in v if x])

                if k == "Type":
                    v = self.SERVICE_TYPE.get(v, v)

                if k == "Start":
                    v = self.START_TYPE.get(v, v)

                if k == "ErrorControl":
                    v = self.ERROR_CONTROL.get(v, v)

                renderer.table_row(k, v)
