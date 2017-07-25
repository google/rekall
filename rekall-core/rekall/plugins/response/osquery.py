#!/usr/bin/env python2

# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
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

__author__ = "Michael Cohen <scudette@google.com>"

"""The OSQuery plugin can capture the result of osquery queries and store in
Rekall result collections.

Note that we do not actually process the query itself, we just relay
the query to osqueryi and then write its output in a collection to be
uploaded. We therefore need to have osqueryi installed somewhere on
the path.
"""
import json
import subprocess

from rekall.plugins.response import common


class OSQuery(common.AbstractIRCommandPlugin):
    """Runs the OSQuery query and emit the results.

    Note that the columns emitted depend on osquery itself so we can
    not predict in advance the table format.
    """
    name = "osquery"

    __args = [
        dict(name="query", positional=True,
             help="The OSQuery query to run."),
        dict(name="osquery_path", default=None,
             help="The path to the osquery binary (default osqueryi)."),
    ]

    table_header = []

    def render(self, renderer):
        osquery_path = self.plugin_args.osquery_path
        if osquery_path == None:
            osquery_path = self.session.GetParameter("osquery_path")
        if osquery_path == None:
            osquery_path = "osqueryi"

        self.json_result = json.loads(
            subprocess.check_output(
                [osquery_path, "--json", self.plugin_args.query]))

        if self.json_result:
            first_row = self.json_result[0]
            self.table_header = [dict(name=x) for x in first_row]

        super(OSQuery, self).render(renderer)

    def collect(self):
        return self.json_result
