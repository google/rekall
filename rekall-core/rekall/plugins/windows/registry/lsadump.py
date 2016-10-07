# Rekall Memory Forensics
# Copyright (C) 2008 Volatile Systems
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
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

from rekall import utils

from rekall.plugins.windows.registry import lsasecrets
from rekall.plugins.windows.registry import hashdump
from rekall.plugins.windows import common
from rekall.plugins.windows.registry import registry


class LSADump(common.WindowsCommandPlugin):
    """Dump (decrypted) LSA secrets from the registry"""
    # Declare meta information associated with this plugin

    name = "lsadump"
    mode = "mode_xp"

    def __init__(self, sys_offset=None, security_offset=None, **kwargs):
        """Dump (decrypted) LSA secrets from the registry.

        Args:
           sys_offset: The hive virtual offset to the system hive.
           security_offset: The hive virtual offset to the security hive.
        """
        super(LSADump, self).__init__(**kwargs)
        self.sys_offset = sys_offset
        self.security_offset = security_offset
        self.profile = registry.RekallRegisteryImplementation(self.profile)

    def calculate(self):
        sys_hive = registry.RegistryHive(
            profile=self.profile, hive_offset=self.sys_offset,
            kernel_address_space=self.kernel_address_space)

        security_hive = registry.RegistryHive(
            profile=self.profile, hive_offset=self.security_offset,
            kernel_address_space=self.kernel_address_space)

        return lsasecrets.get_secrets(sys_hive, security_hive)

    def render(self, outfd):
        for k, v in self.calculate():
            outfd.write(k + "\n")
            utils.WriteHexdump(outfd, v)
            outfd.write("\n")


class HashDump(LSADump):
    """Dumps passwords hashes (LM/NTLM) from memory"""

    __name = "hashdump"

    def __init__(self, sys_offset=None, sam_offset=None, **kwargs):
        """Dump (decrypted) LSA secrets from the registry.

        Args:
           sys_offset: The hive virtual offset to the system hive.
           sam_offset: The hive virtual offset to the sam hive.
        """
        super(HashDump, self).__init__(**kwargs)
        self.sys_offset = sys_offset
        self.sam_offset = sam_offset
        self.profile = registry.RekallRegisteryImplementation(self.profile)

    def calculate(self):
        sys_registry = registry.RegistryHive(
            profile=self.profile, hive_offset=self.sys_offset,
            kernel_address_space=self.kernel_address_space)

        sam_registry = registry.RegistryHive(
            profile=self.profile, hive_offset=self.sam_offset,
            kernel_address_space=self.kernel_address_space)

        return hashdump.dump_hashes(sys_registry, sam_registry)

    def render(self, outfd):
        for d in self.calculate():
            outfd.write(d + "\n")
