# Rekall Memory Forensics
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
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

# pylint: disable=protected-access

# References:
# http://volatility-labs.blogspot.ch/2012/09/movp-11-logon-sessions-processes-and.html
# Windows Internals 5th Edition. Chapter 9.

from rekall import obj
from rekall.ui import text
from rekall.plugins.windows import common


class Sessions(common.WinProcessFilter):
    """List details on _MM_SESSION_SPACE (user logon sessions).

    Windows uses sessions in order to separate processes. Sessions are used to
    separate the address spaces of windows processes.

    Note that this plugin traverses the ProcessList member of the session object
    to list the processes - yet another list _EPROCESS objects are on.
    """

    __name = "sessions"

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="session_id", hidden=True),
        dict(name="process", width=40),
        dict(name="image"),
    ]

    def session_spaces(self):
        """Generates unique _MM_SESSION_SPACE objects.

        Generates unique _MM_SESSION_SPACE objects referenced by active
        processes.

        Yields:
          _MM_SESSION_SPACE instantiated from the session space's address space.
        """
        # Dedup based on sessions.
        seen = set()
        for proc in self.filter_processes():
            ps_ad = proc.get_process_address_space()

            session = proc.Session
            # Session pointer is invalid (e.g. for System process).
            if not session:
                continue

            if session in seen:
                continue

            seen.add(session)

            yield proc.Session.deref(vm=ps_ad)

    def find_session_space(self, session_id):
        """Get a _MM_SESSION_SPACE object by its ID.

        Args:
          session_id: the session ID to find.

        Returns:
          _MM_SESSION_SPACE instantiated from the session space's address space.
        """
        for session in self.session_spaces():
            if session.SessionId == session_id:
                return session

        return obj.NoneObject("Cannot locate a session %s", session_id)

    def collect(self):
        for session in self.session_spaces():
            processes = list(session.ProcessList.list_of_type(
                "_EPROCESS", "SessionProcessLinks"))

            yield dict(divider=("_MM_SESSION_SPACE: {0:#x} ID: {1} "
                                "Processes: {2}".format(
                                    session.obj_offset,
                                    session.SessionId,
                                    len(processes))))

            for process in processes:
                yield dict(session_id=session.SessionId,
                           process=process)

            # Follow the undocumented _IMAGE_ENTRY_IN_SESSION list to find the
            # kernel modules loaded in this session.
            for image in session.ImageIterator:

                yield dict(
                    session_id=session.SessionId,
                    image=image)


class ImageInSessionTextObjectRenderer(text.TextObjectRenderer):
    renders_type = "_IMAGE_ENTRY_IN_SESSION"

    def render_row(self, target, **options):
        try:
            module_name = self.session.address_resolver.format_address(
                target.ImageBase)[0].split("!")[0]
        except IndexError:
            module_name = "?"

        return text.Cell(u"%s (%#x-%#x)" % (
            module_name,
            target.ImageBase, target.LastAddress.v()))
