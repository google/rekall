# Rekall Memory Forensics
#
# Copyright 2015 Google Inc. All Rights Reserved.
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
Windows process collectors.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall.entities import definitions

from rekall.plugins.collectors.windows import common


class WindowsProcessParser(common.WindowsEntityCollector):
    _name = "proc"
    outputs = ["Process", "Named/kind=Process", "Timestamps"]
    collect_args = dict(procs="Struct/type is '_EPROCESS'")

    def collect(self, hint, procs):
        for entity in procs:
            eproc = entity["Struct/base"]
            yield [
                entity.identity | self.manager.identify({"Process/pid":
                                                         eproc.pid}),

                definitions.Process(pid=eproc.pid,
                                    parent=self.manager.identify({
                                        "Process/pid":
                                        eproc.InheritedFromUniqueProcessId}),
                                    command=eproc.name,
                                    is_64bit=eproc.IsWow64),

                definitions.Timestamps(
                    created_at=eproc.CreateTime.as_datetime(),
                    destroyed_at=eproc.ExitTime.as_datetime()),

                definitions.Named(name=eproc.name,
                                  kind="Process")]


class WindowsPsActiveProcessHeadCollector(common.WindowsEntityCollector):
    _name = "PsActiveProcessHead"
    outputs = ["Struct/type=_EPROCESS"]

    def collect(self, hint):
        phead = self.session.GetParameter("PsActiveProcessHead")
        for proc in phead.list_of_type("_EPROCESS", "ActiveProcessLinks"):
            yield definitions.Struct(type="_EPROCESS",
                                     base=proc)


class WindowsPspCidProcessCollector(common.WindowsEntityCollector):
    _name = "PspCidTable"
    outputs = ["Struct/type=_EPROCESS"]

    def collect(self, hint):
        PspCidTable = self.profile.get_constant_object(
            "PspCidTable",
            target="Pointer",
            target_args=dict(
                target="_PSP_CID_TABLE"))

        # Walk the handle table
        for handle in PspCidTable.handles():
            if handle.get_object_type() == "Process":
                yield definitions.Struct(
                    type="_EPROCESS",
                    base=handle.dereference_as("_EPROCESS"))
