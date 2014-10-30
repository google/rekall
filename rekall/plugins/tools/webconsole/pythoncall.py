#!/usr/bin/env python2

# Rekall Memory Forensics
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Author: Michael Cohen scudette@google.com
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

__author__ = "Mikhail Bushkov <realbushman@gmail.com>"


from manuskript import plugins as manuskript_plugins


class RekallPythonCall(manuskript_plugins.PythonCall):
    """PythonCall extension that inserts Rekall session into local context."""

    @classmethod
    def UpdatePythonShell(cls, app, shell):
        super(RekallPythonCall, cls).UpdatePythonShell(app, shell)

        rekall_session = app.config["rekall_session"]
        shell.local_context = rekall_session.locals # pylint: disable=protected-access
        shell.global_context["session"] = rekall_session
