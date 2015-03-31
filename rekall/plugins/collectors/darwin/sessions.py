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
    """Infers the relationship between usernames and UIDs using tty sessions."""

    outputs = ["User"]

    collect_args = dict(
        terminals=("Terminal/file matches (has component Permissions) and "
                   "Terminal/session"))

    complete_input = True

    def collect(self, hint, terminals):
        for terminal in terminals:
            owner = terminal["Terminal/file"]["Permissions/owner"]
            user = terminal["Terminal/session"]["Session/user"]
            # Now tell the manager that these two users are the same user.
            if owner and user:
                yield user.identity | owner.identity


class DarwinTTYZoneCollector(zones.DarwinZoneElementCollector):
    outputs = ["Struct/type=tty"]
    zone_name = "ttys"
    type_name = "tty"

    def validate_element(self, tty):
        return tty.t_lock == tty


class DarwinClistParser(common.DarwinEntityCollector):
    outputs = ["Buffer/purpose=terminal_input",
               "Buffer/purpose=terminal_output"]

    collect_args = dict(clists="Struct/type is 'clist'")

    def collect(self, hint, clists):
        for entity in clists:
            clist = entity["Struct/base"]
            yield [entity.identity,
                   definitions.Buffer(kind="ring",
                                      state="freed",
                                      contents=clist.recovered_contents,
                                      start=clist.c_cs,
                                      end=clist.c_ce,
                                      size=clist.c_cn)]


class DarwinTTYParser(common.DarwinEntityCollector):
    outputs = ["Terminal", "Struct/type=vnode", "Struct/type=clist",
               "Buffer/purpose=terminal_input",
               "Buffer/purpose=terminal_output"]
    collect_args = dict(ttys="Struct/type is 'tty'")

    def collect(self, hint, ttys):
        for entity in ttys:
            file_identity = None
            session_identity = None

            tty = entity["Struct/base"]
            session = tty.t_session.deref()
            vnode = session.s_ttyvp

            if session:
                session_identity = self.manager.identify({
                    "Struct/base": session})

            if vnode:
                # Look, it has a vnode!
                yield definitions.Struct(base=vnode,
                                         type="vnode")
                file_identity = self.manager.identify({
                    "Struct/base": vnode})

            # Yield just the stubs of the input and output ring buffers.
            # DarwinClistParser will grab these if it cares.
            yield [definitions.Struct(base=tty.t_rawq,
                                      type="clist"),
                   definitions.Buffer(purpose="terminal_input",
                                      context=entity.identity)]
            yield [definitions.Struct(base=tty.t_outq,
                                      type="clist"),
                   definitions.Buffer(purpose="terminal_output",
                                      context=entity.identity)]

            # Last, but not least, the Terminal itself.
            yield [entity.identity,
                   definitions.Terminal(
                       session=session_identity,
                       file=file_identity)]


class DarwinSessionParser(common.DarwinEntityCollector):
    """Collects session entities from the memory objects."""

    _name = "sessions"

    outputs = ["Session",
               "User",
               "Struct/type=tty",
               "Struct/type=proc"]

    collect_args = dict(sessions="Struct/type is 'session'")

    def collect(self, hint, sessions):
        for entity in sessions:
            session = entity["Struct/base"]

            # Have to sanitize the usernames to prevent issues when comparing
            # them later.
            username = str(session.s_login).replace("\x00", "")
            if username:
                user_identity = self.manager.identify({
                    "User/username": username})
                yield [user_identity,
                       definitions.User(
                           username=username)]
            else:
                user_identity = None

            sid = session.s_sid
            session_identity = self.manager.identify({
                "Session/sid": sid}) | entity.identity

            if session.s_ttyp:
                yield definitions.Struct(
                    base=session.s_ttyp,
                    type="tty")

            yield definitions.Struct(
                base=session.s_leader.deref(),
                type="proc")

            yield [session_identity,
                   definitions.Session(
                       user=user_identity,
                       sid=sid),
                   definitions.Named(
                       name="SID %d" % int(sid),
                       kind="Session")]


class DarwinSessionZoneCollector(zones.DarwinZoneElementCollector):
    """Collects sessions from the sessions allocation zone."""

    outputs = ["Struct/type=session"]
    zone_name = "session"
    type_name = "session"

    def validate_element(self, session):
        return session.s_count > 0 and session.s_leader.p_argc > 0


class DarwinSessionCollector(common.DarwinEntityCollector):
    """Collects sessions."""

    outputs = ["Struct/type=session"]

    def collect(self, hint):
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
                yield definitions.Struct(
                    base=session,
                    type="session")
