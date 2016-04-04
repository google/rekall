#!/usr/bin/python

# Rekall Memory Forensics
# Copyright (C) 2014 Michael Cohen <scudette@gmail.com>
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
"""This module discovers the kernel base address.

The profile provides kernel addresses relative to the kernel base address. This
varies each time, so we need a way to locate the kernel base address in the
kernel address space.
"""

__author__ = "Michael Cohen <scudette@google.com>"

from rekall import obj
from rekall import scan
from rekall.plugins import core
from rekall.plugins.windows import common
from rekall.plugins.overlays.windows import pe_vtypes


class ExportScanner(scan.BaseScanner):
    # We search for the name of a section present in the PE header.
    checks = [("MultiStringFinderCheck", dict(needles=[
        "INITKDBG", "MISYSPTE", "PAGEKD"]))]


class ObjectTreeHook(common.AbstractWindowsParameterHook):
    """Cache the object tree."""

    name = "object_tree"

    def BuildTree(self, result, root):
        for x in root:
            name = x.NameInfo.Name.v()
            if name == None:
                continue

            # We store the _OBJECT_HEADER offset and some metadata about the
            # types.
            object_type = x.get_object_type()
            entry = result[name] = dict(
                type=object_type,
                type_name="_OBJECT_HEADER",
                offset=x.obj_offset,
            )

            if object_type == "Directory":
                children = entry["Children"] = {}
                self.BuildTree(children, x.Object)

    @core.MethodWithAddressSpace()
    def calculate(self):
        root = self.session.profile.get_constant_object(
            "ObpRootDirectoryObject",
            target="Pointer",
            target_args=dict(
                target="_OBJECT_DIRECTORY"
            )
        )

        result = dict(
            type="Directory",
            type_name="_OBJECT_DIRECTORY",
            offset=root.deref().obj_offset,
            Children={})

        self.BuildTree(result["Children"], root)
        return result


class DriveLetterDeviceHook(common.AbstractWindowsParameterHook):
    """Maps device names to drive letters."""

    name = "drive_letter_device_map"

    @core.MethodWithAddressSpace()
    def calculate(self):
        result = {}
        obj_tree_plugin = self.session.plugins.object_tree()
        # The global path contains symlinks from the drive letter to the device
        # name.
        for global_obj in obj_tree_plugin.GetObjectByName(r"\GLOBAL??").Object:
            name = global_obj.NameInfo.Name.v()
            if (global_obj.get_object_type() == "SymbolicLink" and
                    len(name) > 1 and name[1] == ":"):
                target = global_obj.Object.LinkTarget.v()

                result[target] = name

        return result


class KernelBaseHook(common.AbstractWindowsParameterHook):
    """Finds the kernel base address."""

    name = "kernel_base"

    def calculate(self):
        address_space = self.session.kernel_address_space
        if not address_space:
            return

        scanner = ExportScanner(session=self.session,
                                address_space=address_space)

        # The kernel image is always loaded in the same range called the
        # "Initial Loader Mappings". Narrowing the possible range makes scanning
        # much faster. (See http://www.codemachine.com/article_x64kvas.html)
        if self.session.profile.metadata("arch") == "AMD64":
            kernel_boundary = 0xFFFFF80000000000
        else:
            kernel_boundary = 0x80000000

        maxlen = 0xFFFFF87FFFFFFFFF - kernel_boundary
        kernel_boundary = obj.Pointer.integer_to_address(kernel_boundary)
        for hit in scanner.scan(offset=kernel_boundary, maxlen=maxlen):

            # Search backwards for an MZ signature on the page boundary.
            page = hit & 0xFFFFFFFFFFFFF000
            for _ in range(10):
                if address_space.read(page, 2) == "MZ":
                    helper = pe_vtypes.PE(
                        address_space=address_space,
                        session=self.session, image_base=page)

                    if str(helper.RSDS.Filename) in common.KERNEL_NAMES:
                        self.session.logging.info(
                            "Detected kernel base at 0x%X", page)
                        return page
                else:
                    page -= 0x1000


class WindowsHighestUserAddress(common.AbstractWindowsParameterHook):
    """The highest address for user mode/kernel mode division."""

    name = "highest_usermode_address"

    def calculate(self):
        result = self.session.profile.get_constant_object(
            "MmHighestUserAddress", "Pointer").v()

        # Sometimes the pointer is not present, in that case we use hardcoded
        # values. I dont think these values will ever change, maybe we should
        # just hard code them anyway.
        if result == 0:
            if self.profile.metadata("arch") == "AMD64":
                result = 0x7fffffeffff
            result = 0x7ffeffff

        return result


class DTB2TaskMap(common.AbstractWindowsParameterHook):
    """Maps the DTB to the _EPROCESS structs."""

    name = "dtb2task"

    def calculate(self):
        result = {}
        for task in self.session.plugins.pslist().filter_processes():
            result[int(task.dtb)] = task.obj_offset

        return result
