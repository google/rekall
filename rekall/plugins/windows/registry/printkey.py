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
import os

from rekall import config
from rekall import utils
from rekall.plugins import core
from rekall.plugins.windows import common
from rekall.plugins.windows.registry import registry


class PrintKey(common.WindowsCommandPlugin):
    "Print a registry key, and its subkeys and values"
    # Declare meta information associated with this plugin

    __name = "printkey"

    meta_info = {}
    meta_info['author'] = 'Brendan Dolan-Gavitt'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt'
    meta_info['contact'] = 'bdolangavitt@wesleyan.edu'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(PrintKey, cls).args(parser)

        parser.add_argument("-k", "--key", default="",
                            help="Registry key to print.")

        parser.add_argument("-o", "--hive_offsets", default=None,
                            action=config.ArrayIntParser, nargs="+",
                            help='Hive offsets to search (virtual)')

        parser.add_argument("-r", "--recursive", default=False,
                            action="store_true",
                            help='If set print the entire subtree.')


    def __init__(self, hive_offsets=None, key="", recursive=False, **kwargs):
        """Print all keys and values contained by a registry key.

        Args:
          hive_offsets: A list of hive offsets as found by hivelist (virtual
            address). If not provided we call hivescan ourselves and list the
            key on all hives.

          key: The key name to list. If not provided we list the root key in the
            hive.

          recursive: If set print the entire subtree.
        """
        super(PrintKey, self).__init__(**kwargs)
        self.profile = registry.RekallRegisteryImplementation(self.profile)
        self.hive_offsets = hive_offsets
        self.key = key
        self.recursive = recursive

    def _list_keys(self, reg, key=None):
        yield reg, key

        if self.recursive:
            for subkey in key.subkeys():
                for reg, subkey in self._list_keys(reg, subkey):
                    yield reg, subkey

    def list_keys(self):
        """Return the keys that match."""
        seen = set()
        if not self.hive_offsets:
            self.hive_offsets = list(self.get_plugin("hivescan").list_hives())

        for hive_offset in self.hive_offsets:
            if hive_offset in seen:
                continue

            seen.add(hive_offset)

            reg = registry.RegistryHive(
                profile=self.profile, session=self.session,
                kernel_address_space=self.kernel_address_space,
                hive_offset=hive_offset)

            key = reg.open_key(self.key)
            for reg, subkey in self._list_keys(reg, key):
                yield reg, subkey

    def voltext(self, key):
        """Returns a string representing (S)table or (V)olatile keys."""
        return "(V)" if key.obj_offset & 0x80000000 else "(S)"

    def render(self, renderer):
        renderer.format("Legend: (S) = Stable   (V) = Volatile\n\n")
        for reg, key in self.list_keys():
            self.session.report_progress("Printing %s", lambda: key.Path)

            if key:
                renderer.format("----------------------------\n")
                renderer.format("Registry: {0}\n", reg.Name)
                renderer.format("Key name: {0} {1:3s}\n", key.Name,
                                self.voltext(key))

                renderer.format("Last updated: {0}\n", key.LastWriteTime)
                renderer.format("\n")
                renderer.format("Subkeys:\n")

                for subkey in key.subkeys():
                    if not subkey.Name:
                        renderer.format(
                            "  Unknown subkey: {0}\n", subkey.Name.reason)
                    else:
                        renderer.format(u"  {1:3s} {0}\n",
                                        subkey.Name, self.voltext(subkey))

                renderer.format("\n")
                renderer.format("Values:\n")
                for value in key.values():
                    if value.Type == 'REG_BINARY':
                        data = value.DecodedData
                        if isinstance(data, basestring):
                            utils.WriteHexdump(renderer, value.DecodedData)
                    else:
                        renderer.format(
                            u"{0:13} {1:15} : {3:3s} {2}\n",
                            value.Type, value.Name, value.DecodedData,
                            self.voltext(value))


class RegDump(core.DirectoryDumperMixin, common.WindowsCommandPlugin):
    """Dump all registry hives into a dump directory."""

    __name = 'regdump'

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(RegDump, cls).args(parser)
        parser.add_argument(
            "-o", "--hive_offsets", action=config.ArrayIntParser,
            nargs="+", help='Hive offsets to search (virtual)')


    def __init__(self, hive_offsets=None, **kwargs):
        """Dump the registry from memory.

        Args:
          hive_offset: A list of hive offsets as found by hivelist (virtual
            address). If not provided we call hivescan ourselves and dump all
            hives found.

          dump_dir: Directory in which to dump hive files.
        """
        super(RegDump, self).__init__(**kwargs)
        self.hive_offsets = hive_offsets

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
        if not self.hive_offsets:
            self.hive_offsets = list(self.get_plugin("hivescan").list_hives())

        seen = set()
        for hive_offset in self.hive_offsets:
            if hive_offset in seen:
                continue

            reg = registry.RegistryHive(
                profile=self.profile, session=self.session,
                kernel_address_space=self.kernel_address_space,
                hive_offset=hive_offset)

            # Make up a filename for it, should be similar to the hive name.
            filename = reg.Name.rsplit("\\", 1).pop()

            # Sanitize it.
            filename = re.sub(r"[^a-zA-Z0-9_\-@ ]", "_", filename)

            # Make up the path.
            path = os.path.join(self.dump_dir, filename)

            renderer.section()
            renderer.format("Dumping {0} into \"{1}\"\n", reg.Name, path)

            with open(path, "wb") as fd:
                self.dump_hive(reg=reg, fd=fd)
                renderer.format("Dumped {0} bytes\n", fd.tell())



class HiveDump(registry.RegistryPlugin):
    """Prints out a hive"""

    __name = "hivedump"

    def _key_iterator(self, key):
        for subkey in key.subkeys():
            yield subkey
            for subsubkey in self._key_iterator(subkey):
                yield subsubkey

    def render(self, renderer):
        seen = set()

        for hive_offset in self.hive_offsets:
            if hive_offset in seen:
                continue

            reg = registry.RegistryHive(
                hive_offset=hive_offset, session=self.session,
                kernel_address_space=self.kernel_address_space,
                profile=self.profile)

            renderer.section()
            renderer.format("Hive {0}\n\n", reg.Name)

            renderer.table_header([("Last Written", "timestamp", "<24"),
                                   ("Key", "key", "")])

            for key in self._key_iterator(reg.root):
                renderer.table_row(key.LastWriteTime, key.Path)
