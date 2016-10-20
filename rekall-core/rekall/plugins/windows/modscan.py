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
from rekall import utils
from rekall.plugins.windows import common


class PoolScanModuleFast(common.PoolScanner):
    def __init__(self, **kwargs):
        super(PoolScanModuleFast, self).__init__(**kwargs)
        self.checks = [
            # Must have the right pool tag.
            ('PoolTagCheck', dict(
                tag=self.profile.get_constant("MODULE_POOLTAG"))),

            # Must be large enough for an _LDR_DATA_TABLE_ENTRY. Windows 8 seems
            #  to not allocate the full structure here so this test does not
            #  always work. Disabled for now.

            # ('CheckPoolSize', dict(min_size=self.profile.get_obj_size(
            #  "_LDR_DATA_TABLE_ENTRY"))),

            ('CheckPoolType', dict(
                paged=True, non_paged=True, free=True)),

            ('CheckPoolIndex', dict(value=0)),
            ]


class ModScan(common.PoolScannerPlugin):
    """Scan Physical memory for _LDR_DATA_TABLE_ENTRY objects."""

    __name = "modscan"

    table_header = [
        dict(name="offset", style="address"),
        dict(name="name", width=20),
        dict(name="base", style="address"),
        dict(name="size", style="address"),
        dict(name="file")
    ]

    scanner_defaults = dict(
        scan_kernel_nonpaged_pool=True
    )

    def collect(self):
        for run in self.generate_memory_ranges():
            scanner = PoolScanModuleFast(profile=self.profile,
                                         session=self.session,
                                         address_space=run.address_space)

            for pool_obj in scanner.scan(run.start, run.length):
                if not pool_obj:
                    continue

                ldr_entry = self.profile._LDR_DATA_TABLE_ENTRY(
                    vm=run.address_space, offset=pool_obj.obj_end)

                # Must have a non zero size.
                if ldr_entry.SizeOfImage == 0:
                    continue

                # Must be page aligned.
                if ldr_entry.DllBase & 0xFFF:
                    continue

                yield (ldr_entry.obj_offset,
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


class ThrdScan(common.PoolScannerPlugin):
    """Scan physical memory for _ETHREAD objects"""

    __name = "thrdscan"

    table_header = [
        dict(name="offset", style="address"),
        dict(name="pid", width=6, align="r"),
        dict(name="tid", width=6, align="r"),
        dict(name="start", style="address"),
        dict(name="create_time", width=24),
        dict(name="exit_time", width=24),
        dict(name="name", width=16),
        dict(name="symbol"),
    ]

    scanner_defaults = dict(
        scan_kernel_nonpaged_pool=True
    )


    def collect(self):
        with self.session.plugins.cc() as cc:
            for run in self.generate_memory_ranges():
                scanner = PoolScanThreadFast(
                    profile=self.profile, session=self.session,
                    address_space=run.address_space)

                for pool_obj in scanner.scan(run.start, run.length):
                    thread = pool_obj.GetObject("Thread").Body.cast("_ETHREAD")
                    if not thread:
                        continue

                    if (thread.Cid.UniqueProcess.v() != 0 and
                            thread.StartAddress == 0):
                        continue

                    try:
                        # Check the Semaphore Type.
                        if thread.Tcb.SuspendSemaphore.Header.Type != 0x05:
                            continue

                        if thread.KeyedWaitSemaphore.Header.Type != 0x05:
                            continue
                    except AttributeError:
                        pass

                    # Resolve the thread back to an owning process if possible.
                    task = thread.Tcb.ApcState.Process.dereference_as(
                        "_EPROCESS", vm=self.session.kernel_address_space)

                    # Try to switch to the tasks address space in order to
                    # resolve symbols.
                    start_address = thread.Win32StartAddress.v()
                    if start_address < self.session.GetParameter(
                            "highest_usermode_address"):
                        if task != self.session.GetParameter("process_context"):
                            cc.SwitchProcessContext(task)

                    else:
                        cc.SwitchProcessContext()

                    yield (thread.obj_offset,
                           thread.Cid.UniqueProcess,
                           thread.Cid.UniqueThread,
                           thread.Win32StartAddress.v(),
                           thread.CreateTime,
                           thread.ExitTime,
                           task.ImageFileName,
                           utils.FormattedAddress(
                               self.session.address_resolver, start_address))
