# Rekall Memory Forensics
#
# Copyright 2014 Google Inc. All Rights Reserved.
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
Darwin Session collectors.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall.entities import definitions

from rekall.plugins.collectors.darwin import common
from rekall.plugins.collectors.darwin import zones


class DarwinTerminalUserInferor3000(common.DarwinEntityCollector):
    outputs = ["User"]

    def collect(self, hint=None, ingest=None):
        # This is necessary because we need to have full files and permissions
        # collected. TODO: remove this once the manager is smart enough to
        # get complete results on deref.
        self.manager.collect_for("Permissions")
        for terminal in self.manager.find_by_component("Terminal"):
            owner = terminal["Terminal/file"]["Permissions/owner"]
            user = terminal["Terminal/session"]["Session/user"]

            # Now tell the manager that these two users are the same user.
            if owner and user:
                yield user.identity | owner.identity


class DarwinTTYZoneCollector(zones.DarwinZoneElementCollector):
    outputs = ["MemoryObject/type=tty"]
    zone_name = "ttys"
    type_name = "tty"

    def validate_element(self, tty):
        return tty.t_lock == tty


class DarwinTTYParser(common.DarwinEntityCollector):
    outputs = ["Terminal", "MemoryObject/type=vnode"]

    def collect(self, hint=None, ingest=None):
        for entity in self.manager.find_by_attribute(
                "MemoryObject/type", "tty"):
            tty = entity["MemoryObject/base_object"]
            session = tty.t_session
            vnode = session.s_ttyvp

            yield definitions.MemoryObject(
                base_object=vnode.deref(),
                type="vnode")

            yield [
                entity.identity,
                definitions.Terminal(
                    session=self.manager.identify({
                        "MemoryObject/base_object": session}),
                    file=self.manager.identify({
                        "MemoryObject/base_object": vnode}))]


class DarwinSessionParser(common.DarwinEntityCollector):
    """Collects session entities from the memory objects."""

    _name = "sessions"

    outputs = [
        "Session",
        "User",
        "MemoryObject/type=tty",
        "MemoryObject/type=proc"]

    def collect(self, hint=None, ingest=None):
        for entity in self.manager.find_by_attribute(
                "MemoryObject/type", "session"):
            session = entity["MemoryObject/base_object"]

            # Have to sanitize the usernames to prevent issues when comparing
            # them later.
            username = str(session.s_login).replace("\x00", "")
            if username:
                user_identity = self.manager.identify({
                    "User/username": username})
                yield [
                    user_identity,
                    definitions.User(
                        username=username)]
            else:
                user_identity = None

            sid = session.s_sid
            session_identity = self.manager.identify({
                "Session/sid": sid}) | entity.identity

            if session.s_ttyp:
                yield definitions.MemoryObject(
                    base_object=session.s_ttyp,
                    type="tty")

            yield definitions.MemoryObject(
                base_object=session.s_leader.deref(),
                type="proc")

            yield [
                session_identity,
                definitions.Session(
                    user=user_identity,
                    sid=sid)]


class DarwinSessionZoneCollector(zones.DarwinZoneElementCollector):
    """Collects sessions from the sessions allocation zone."""

    outputs = ["MemoryObject/type=session"]
    zone_name = "session"
    type_name = "session"

    def validate_element(self, session):
        return session.s_count > 0 and session.s_leader.p_argc > 0


class DarwinSessionCollector(common.DarwinEntityCollector):
    """Collects sessions."""

    outputs = ["MemoryObject/type=session"]

    def collect(self, hint=None, ingest=None):
        session_hash_table_size = self.profile.get_constant_object(
            "_sesshash", "unsigned long")

        # The hashtable is an array to session list heads.
        session_hash_table = self.profile.get_constant_object(
            "_sesshashtbl",
            target="Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    target="sesshashhead",
                    count=session_hash_table_size.v())))

        for sesshashhead in session_hash_table:
            for session in sesshashhead.lh_first.walk_list("s_hash.le_next"):
                yield definitions.MemoryObject(
                    base_object=session,
                    type="session")
