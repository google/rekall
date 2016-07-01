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
import os
import re
import platform

from rekall import kb
from rekall import registry


class KnowledgeBase(object):

    def __init__(self, session):
        self.session = session

    def expand(self, variable):
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


class WindowsKnowledgeBase(KnowledgeBase):
    @registry.memoize
    def _get_sids(self):
        result = []
        for hit in self.session.plugins.glob(
                "HKEY_USERS\*", filesystem="Reg", root="\\",
                path_sep="\\").collect():
            path = hit["path"]
            m = re.search(
                "(S-(\d+-)+\d+)$", path.filename.name or "", re.I)
            if m:
                result.append(m.group(1))

        return result

    @registry.memoize
    def _get_homedirs(self):
        """On windows the homedirs are the paths of the user's profile."""
        result = []
        for artifact_hit in self.session.plugins.artifact_collector(
                "WindowsRegistryProfiles"):
            for hit_result in artifact_hit.get("result", []):
                profile_path = hit_result.get("value")
                if profile_path:
                    result.append(profile_path)

        return result

    def expand(self, variable):
        if variable == "%%users.sid%%":
            return self._get_sids()

        if variable == "%%users.homedir%%":
            return self._get_homedirs()

        if variable == "%%environ_systemroot%%":
            return [os.environ["systemroot"]]

        return []


class KnowledgeBaseHook(kb.ParameterHook):
    name = "knowledge_base"

    def calculate(self):
        if platform.system() == "Linux":
            return LinuxKnowledgeBase(self.session)
        elif platform.system() == "Windows":
            return WindowsKnowledgeBase(self.session)
