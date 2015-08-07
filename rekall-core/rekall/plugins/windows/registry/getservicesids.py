# Rekall Memory Forensics
# Copyright (C) 2011 Volatile Systems
# Copyright (C) 2011 Jamie Levy (Gleeda) <jamie.levy@gmail.com>
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
@author:       Jamie Levy (Gleeda)
@license:      GNU General Public License 2.0 or later
@contact:      jamie.levy@gmail.com
@organization: Volatile Systems
"""

from rekall import utils
from rekall.plugins.windows.registry import registry

import hashlib
import struct


class GetServiceSids(registry.RegistryPlugin):
    """Get the names of services in the Registry and return Calculated SID"""

    __name = "getservicesids"

    def createservicesid(self, service_name):
        """Calculate the Service SID."""

        # We depend on service name to be a unicode string here.
        service_name = utils.SmartUnicode(service_name)

        sha = hashlib.sha1(service_name.encode("utf-16-le").upper()).digest()
        return 'S-1-5-80-' + '-'.join(
            [str(n) for n in struct.unpack("<IIIII", sha)])

    def get_service_sids(self):
        # Search for the current_control_set in all hives.
        for hive_offset in self.hive_offsets:
            reg = registry.RegistryHive(
                hive_offset=hive_offset, session=self.session)

            current_control_set = reg.CurrentControlSet()

            # There is no CurrentControlSet in this hive.
            if not current_control_set:
                continue

            # Enumerate the services.
            for subkey in current_control_set.open_subkey("services").subkeys():
                sid = self.createservicesid(subkey.Name)

                yield sid, subkey.Name

    def render(self, renderer):
        """output to Service SIDs as a dictionary for future use."""
        renderer.table_header([("SID", "sid", "<70"),
                               ("Service Name", "name", "")])

        for sid, service in self.get_service_sids():
            renderer.table_row(sid, service)
