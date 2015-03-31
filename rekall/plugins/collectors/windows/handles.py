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
Windows handles collectors.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall.entities import collector
from rekall.entities import definitions

from rekall.plugins.collectors.windows import common


class WindowsHandleCollector(common.WindowsEntityCollector):
    """Collects all kinds of things processes have handles on.

    This collector can yield further processes and will feed itself.
    """
    _name = "handles"
    outputs = ["Struct/type=_EPROCESS",
               "Struct/type=_FILE_OBJECT",
               "Struct/type=_ETHREAD",
               "Struct/type=_CM_KEY_BODY",
               "Handle"]

    collect_args = dict(eprocesses="Struct/type is '_EPROCESS'")

    run_cost = collector.CostEnum.VeryHighCost

    # The types that map to None will not be yielded. This is intentional,
    # until collectors can be written to support those types.
    TYPES_MAP = {
        "File": "_FILE_OBJECT",
        "Process": "_EPROCESS",
        "Thread": "_ETHREAD",
        "Key": "_CM_KEY_BODY",
        "Event": None,
        "Timer": None,
        "Directory": None,
        "EtwRegistration": None,
        "Semaphore": None,
        "ALPC Port": None,
        "Token": None,
        "Mutant": None,
        "IoCompletion": None,
        "Section": None}

    def collect(self, hint, eprocesses):
        for process in eprocesses:
            eproc = process["Struct/base"]
            for handle in eproc.ObjectTable.handles():
                resource_type = handle.get_object_type(eproc.obj_vm)
                vtype = self.TYPES_MAP.get(resource_type)

                if not vtype:
                    continue

                base = handle.dereference_as(vtype)
                base_id = self.manager.identify({"Struct/base": base})
                _, handle = self.prebuild(
                    components=[definitions.Handle(
                        process=process.identity,
                        resource=base_id,
                        fd=handle.HandleValue)],
                    keys=("Handle/process", "Handle/fd", "Handle/resource"))

                yield [base_id, definitions.Struct(base=base, type=vtype)]
                yield handle
