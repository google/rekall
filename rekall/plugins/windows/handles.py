# Rekall Memory Forensics
# Copyright (C) 2007-2011 Volatile Systems
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Additional Authors:
# Michael Ligh <michael.ligh@mnin.org>
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

from rekall import config
from rekall import utils
from rekall.plugins.windows import common


class Handles(common.WinProcessFilter):
    """Print list of open handles for each process"""

    __name = "handles"

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(Handles, cls).args(parser)
        parser.add_argument(
            "-t", "--object_types",
            action=config.ArrayStringParser, nargs="+",
            help="Types of objects to show.")


    def __init__(self, object_types=None, silent=None, **kwargs):
        """Lists the handles for processes.

        Args:
          object_types: Show these object types (An array of Object Types -
                        for example: object_types=["Process", "File"]).
          silent: Suppress less meaningful results
        """
        super(Handles, self).__init__(**kwargs)
        self.object_list = object_types
        self.silent = silent

    def full_key_name(self, handle):
        """Returns the full name of a registry key based on its CM_KEY_BODY handle"""
        output = []
        kcb = handle.KeyControlBlock
        while kcb.ParentKcb:
            if kcb.NameBlock.Name == None:
                break
            output.append(str(kcb.NameBlock.Name))
            kcb = kcb.ParentKcb
        return "\\".join(reversed(output))

    def enumerate_handles(self, task):
        if task.ObjectTable.HandleTableList:
            for handle in task.ObjectTable.handles():
                name = ""
                object_type = handle.get_object_type(self.kernel_address_space)
                if object_type == "File":
                    file_obj = handle.dereference_as("_FILE_OBJECT")
                    name = file_obj.file_name_with_device()
                elif object_type == "Key":
                    key_obj = handle.dereference_as("_CM_KEY_BODY")
                    name = key_obj.full_key_name()
                elif object_type == "Process":
                    proc_obj = handle.dereference_as("_EPROCESS")
                    name = u"{0}({1})".format(
                        utils.SmartUnicode(proc_obj.ImageFileName),
                        proc_obj.UniqueProcessId)

                elif object_type == "Thread":
                    thrd_obj = handle.dereference_as("_ETHREAD")
                    name = u"TID {0} PID {1}".format(
                        thrd_obj.Cid.UniqueThread,
                        thrd_obj.Cid.UniqueProcess)

                elif handle.NameInfo.Name == None:
                    name = ""
                else:
                    name = handle.NameInfo.Name

                yield handle, object_type, name

    def render(self, renderer):
        renderer.table_header([("Offset (V)", "offset_v", "[addrpad]"),
                               ("Pid", "pid", ">6"),
                               ("Handle", "handle", "[addr]"),
                               ("Access", "access", "[addr]"),
                               ("Type", "obj_type", "16"),
                               ("Details", "details", "")
                               ])

        for task in self.filter_processes():
            for count, (handle, object_type, name) in enumerate(
                self.enumerate_handles(task)):

                self.session.report_progress("%s: %s handles" % (
                        task.ImageFileName, count))

                if self.object_list and object_type not in self.object_list:
                    continue

                if self.silent:
                    if len(utils.SmartUnicode(name).replace("'", "")) == 0:
                        continue

                offset = handle.Body.obj_offset
                renderer.table_row(
                    offset,
                    task.UniqueProcessId,
                    handle.HandleValue,
                    handle.GrantedAccess,
                    object_type, name)

