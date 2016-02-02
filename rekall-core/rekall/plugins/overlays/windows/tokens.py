# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
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

"""Classes around handling tokens, privileges etc."""

__author__ = "Michael Cohen <scudette@gmail.com>"

from rekall import obj


# In XP the privileges are simple arrays in the _TOKEN object.
xp_style_overlays = {
    "_TOKEN": [None, {
        'Privileges': [None, ['Pointer', dict(
            target='Array',
            target_args=dict(
                count=lambda x: x.PrivilegeCount,
                target='_LUID_AND_ATTRIBUTES'
            )
        )]],
    }],
}


class XP_TOKEN(obj.Struct):
    """XP Style privileges are just an array."""

    def GetPrivileges(self):
        """Enumerates all privileges in this token.

        Yields:
          value, flags
        """
        for privilege in self.Privileges:
            flags = ["Present"]
            if privilege.Attributes & 2:
                flags.append("Enabled")

            if privilege.Attributes & 1:
                flags.append("Default")

            yield privilege.Luid.v(), flags


class VISTA_TOKEN(obj.Struct):
    """A Vista Style _TOKEN object."""

    def GetPrivileges(self):
        """Enumerates all privileges in this token."""

        privilege_table = self.obj_session.GetParameter("privilege_table")
        present = self.Privileges.Present.v()
        enabled = self.Privileges.Enabled.v()
        default = self.Privileges.EnabledByDefault.v()

        for i in range(0, 64):
            if i not in privilege_table:
                continue

            mask = 1 << i

            flags = []
            if mask & present:
                flags.append("Present")
            if mask & enabled:
                flags.append("Enabled")

            if mask & default:
                flags.append("Default")

            yield i, flags


def InitializeTokenProfiles(profile):
    if profile.get_obj_offset("_TOKEN", "PrivilegeCount") != None:
        # Uses XP Style Privilege array.
        profile.add_overlay(xp_style_overlays)
        profile.add_classes(_TOKEN=XP_TOKEN)

    elif profile.get_obj_offset("_SEP_TOKEN_PRIVILEGES", "Present") != None:
        # Uses Vista style Present, Enabled, Default bitfields.
        profile.add_classes(_TOKEN=VISTA_TOKEN)
