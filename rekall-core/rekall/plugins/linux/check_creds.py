# Rekall Memory Forensics
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright 2013 Google Inc. All Rights Reserved.
#
# This file is part of Rekall Memory Forensics.
#
# Rekall Memory Forensics is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# Rekall Memory Forensics is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Rekall Memory Forensics.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization:
"""
from rekall.plugins.linux import common

class CheckCreds(common.LinProcessFilter):
    """Checks if any processes are sharing credential structures"""

    __name = "check_creds"

    table_header = [
        dict(name="task", width=40),
        dict(name="cred", style="address"),
    ]

    @classmethod
    def is_active(cls, config):
        if super(CheckCreds, cls).is_active(config):
            try:
                # This only exists if the task_struct has a cred member.
                config.profile.get_obj_offset("task_struct", "cred")
                return True

            except KeyError:
                return False

    def collect(self):
        creds = {}
        for task in self.filter_processes():
            creds.setdefault(task.cred, []).append(task)

        for cred, tasks in creds.iteritems():
            highlight = None
            if len(tasks) > 1:
                highlight = "important"

            for task in tasks:
                yield dict(cred=cred, task=task,
                           highlight=highlight)
