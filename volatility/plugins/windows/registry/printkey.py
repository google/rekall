# Volatility
# Copyright (C) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

from volatility.plugins.windows import common
from volatility.plugins.windows.registry import registry


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

    def __init__(self, hive_offsets=None, key="", **kwargs):
        """Print all keys and values contained by a registry key.

        Args:
          hive_offset: A list of hive offsets as found by hivelist (virtual
            address). If not provided we call hivescan ourselves and list the
            key on all hives.

          key: The key name to list. If not provided we list the root key in the
            hive.
        """
        super(PrintKey, self).__init__(**kwargs)
        self.profile = registry.VolatilityRegisteryImplementation(self.profile)

        if hive_offsets is None:
            hive_offsets = []

        try:
            self.hive_offsets = list(hive_offsets)
        except TypeError:
            self.hive_offsets = [hive_offsets]

        self.key = key

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
                profile=self.profile, kernel_address_space=self.kernel_address_space,
                hive_offset=hive_offset)

            yield reg, reg.open_key(self.key)

    def voltext(self, key):
        """Returns a string representing (S)table or (V)olatile keys."""
        return "(V)" if key.obj_offset & 0x80000000 else "(S)"

    def render(self, outfd):
        outfd.write("Legend: (S) = Stable   (V) = Volatile\n\n")
        for reg, key in self.list_keys():
            if key:
                outfd.write("----------------------------\n")
                outfd.format("Registry: {0}\n", reg.Name)
                outfd.format("Key name: {0} {1:3s}\n", key.Name,
                             self.voltext(key))

                outfd.format("Last updated: {0}\n", key.LastWriteTime)
                outfd.write("\n")
                outfd.write("Subkeys:\n")

                for subkey in key.subkeys():
                    if not subkey.Name:
                        outfd.write("  Unknown subkey: " + subkey.Name.reason + "\n")
                    else:
                        outfd.format(u"  {1:3s} {0}\n",
                                     subkey.Name, self.voltext(subkey))

                outfd.write("\n")
                outfd.write("Values:\n")
                for value in key.values():
                    if value.Type == 'REG_BINARY':
                        utils.WriteHexdump(outfd, value.DecodedData)
                    else:
                        outfd.format(u"{0:13} {1:15} : {3:3s} {2}\n",
                                     value.Type, value.Name, value.DecodedData,
                                     self.voltext(value))
