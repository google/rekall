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
from rekall import testlib

from rekall import utils
from rekall.plugins.windows import common


class Handles(common.WinProcessFilter):
    """Print list of open handles for each process"""

    __name = "handles"

    __args = [
        dict(name="object_types", type="ArrayStringParser",
             help="Types of objects to show."),
        dict(name="named_only", type="Boolean",
             help="Output only handles with a name ."),
    ]

    table_header = [
        dict(name="_OBJECT_HEADER", cname="offset_v", style="address"),
        dict(name="_EPROCESS", type="_EPROCESS", cname="_EPROCESS"),
        dict(name="Handle", cname="handle", style="address"),
        dict(name="Access", cname="access", style="address"),
        dict(name="Type", cname="obj_type", width=16),
        dict(name="Details", cname="details")
    ]

    def enumerate_handles(self, task):
        if task.ObjectTable.HandleTableList:
            for handle in task.ObjectTable.handles():
                name = u""
                object_type = handle.get_object_type(self.kernel_address_space)

                if object_type == None:
                    continue

                if (self.plugin_args.object_types and
                        object_type not in self.plugin_args.object_types):
                    continue

                elif object_type == "File":
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
                    name = u""
                else:
                    name = handle.NameInfo.Name

                if not name and self.plugin_args.named_only:
                    continue

                yield handle, object_type, name

    def collect(self):
        for task in self.filter_processes():
            for count, (handle, object_type, name) in enumerate(
                    self.enumerate_handles(task)):

                self.session.report_progress("%s: %s handles" % (
                    task.ImageFileName, count))

                yield (handle,
                       task,
                       handle.HandleValue,
                       handle.GrantedAccess,
                       object_type, utils.SmartUnicode(name))


class TestHandles(testlib.SimpleTestCase):
    """Test the Handler module."""

    PARAMETERS = dict(commandline="handles %(pids)s")
