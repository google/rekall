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

"""This module defines interpolators for the common OSs.

Globs and Artifacts may expand interpolations from the KnowledgeBase. This
module provides a live, on demand, KnowledgeBase.
"""

import platform

from rekall import registry


class KnowledgeBase(object):

    def expand(self, _):
        return []


class LinuxKnowledgeBase(KnowledgeBase):
    @registry.memoize
    def _get_users_homedir(self):
        homedirs = []

        for user in open("/etc/passwd"):
            user = user.strip()
            homedirs.append(user.split(":")[5])

        return homedirs

    def expand(self, variable):
        if variable == "%%users.homedir%%":
            return self._get_users_homedir()

        return []


if platform.system() == "Linux":
    KnowledgeBase = LinuxKnowledgeBase

KB = KnowledgeBase()
