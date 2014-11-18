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
The Rekall Memory Forensics entity layer.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

import datetime

from rekall.entities import definitions
from rekall.entities import collector


class BallastGenerator(collector.EntityCollector):
    """Generates ballast entities to stress-test the entity system."""

    outputs = ["Timestamps", "Named"]

    @classmethod
    def is_active(cls, session):
        return session.GetParameter("generate_ballast") > 0

    def collect(self, hint):
        for i in range(self.session.GetParameter("generate_ballast")):
            yield [
                definitions.Named(
                    name="Ballast entry #%d" % i,
                    kind="Ballast"),
                definitions.Timestamps(
                    created_at=datetime.datetime.fromtimestamp(0))]
