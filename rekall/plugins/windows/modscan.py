# Rekall Memory Forensics
# Copyright (C) 2012 Michael Cohen <scudette@gmail.com>
# Copyright (C) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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

"""
This module implements the fast module scanning

@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""
# pylint: disable=protected-access

from rekall.plugins.windows import common
from rekall.plugins.windows import filescan


class PoolScanModuleFast(common.PoolScanner):
    def __init__(self, **kwargs):
        super(PoolScanModuleFast, self).__init__(**kwargs)
        self.checks = [
            # Must have the right pool tag.
            ('PoolTagCheck', dict(
                    tag=self.profile.get_constant("MODULE_POOLTAG"))),

            # Must be large enough for an _LDR_DATA_TABLE_ENTRY.
            ('CheckPoolSize', dict(min_size=self.profile.get_obj_size(
                        "_LDR_DATA_TABLE_ENTRY"))),

            ('CheckPoolType', dict(
                    paged=True, non_paged=True, free=True)),

            ('CheckPoolIndex', dict(value=0)),
            ]


class ModScan(filescan.FileScan):
    """Scan Physical memory for _LDR_DATA_TABLE_ENTRY objects."""

    __name = "modscan"

    def generate_hits(self):
        scanner = PoolScanModuleFast(profile=self.profile, session=self.session,
                                     address_space=self.address_space)

        for offset in scanner.scan():
            ldr_entry = self.profile._LDR_DATA_TABLE_ENTRY(
                vm=self.address_space, offset=offset.obj_offset + offset.size())

            yield ldr_entry

    def render(self, renderer):
        renderer.table_header([("Offset(P)", "offset", "[addrpad]"),
                               ('Name', "name", "20"),
                               ('Base', "base", "[addrpad]"),
                               ('Size', "size", "[addr]"),
                               ('File', "file", "")
                               ])
        for ldr_entry in self.generate_hits():
            renderer.table_row(
                ldr_entry.obj_offset,
                ldr_entry.BaseDllName.v(vm=self.kernel_address_space),
                ldr_entry.DllBase,
                ldr_entry.SizeOfImage,
                ldr_entry.FullDllName.v(vm=self.kernel_address_space))


class PoolScanThreadFast(common.PoolScanner):
    """ Carve out threat objects using the pool tag """
    def __init__(self, **kwargs):
        super(PoolScanThreadFast, self).__init__(**kwargs)
        self.checks = [
            ('PoolTagCheck', dict(
                    tag=self.profile.get_constant("THREAD_POOLTAG"))),

            ('CheckPoolSize', dict(min_size=self.profile.get_obj_size(
                        "_ETHREAD"))),

            ('CheckPoolType', dict(
                    paged=True, non_paged=True, free=True)),

            ('CheckPoolIndex', dict(value=0)),
            ]


class ThrdScan(ModScan):
    """Scan physical memory for _ETHREAD objects"""

    __name = "thrdscan"

    allocation = ['_POOL_HEADER', '_OBJECT_HEADER', "_ETHREAD"]

    def generate_hits(self):
        scanner = PoolScanThreadFast(profile=self.profile, session=self.session,
                                     address_space=self.address_space)

        for found in scanner.scan():
            thread = found.get_object("_ETHREAD", self.allocation)

            if (thread.Cid.UniqueProcess.v() != 0 and
                thread.StartAddress == 0):
                continue

            # Check the Semaphore Type.
            if thread.Tcb.SuspendSemaphore.Header.Type != 0x05:
                continue

            if thread.KeyedWaitSemaphore.Header.Type != 0x05:
                continue

            yield thread


    def render(self, renderer):
        renderer.table_header([("Offset(P)", "offset", "[addrpad]"),
                               ("PID", "pid", ">6"),
                               ("TID", "tid", ">6"),
                               ("Start Address", "start", "[addr]"),
                               ("Create Time", "create_time", "24"),
                               ("Exit Time", "exit_time", "24"),
                               ("Process", "name", ""),
                               ])

        for thread in self.generate_hits():
            # Resolve the thread back to an owning process if possible.
            task = thread.Tcb.ApcState.Process.dereference_as(
                "_EPROCESS", vm=self.session.kernel_address_space)

            renderer.table_row(thread.obj_offset,
                               thread.Cid.UniqueProcess,
                               thread.Cid.UniqueThread,
                               thread.StartAddress,
                               thread.CreateTime,
                               thread.ExitTime,
                               task.ImageFileName,
                               )
