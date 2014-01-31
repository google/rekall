#!/usr/bin/env python
#
#       fileobjscan.py
#       Copyright 2009 Andreas Schuster <a.schuster@yendor.net>
#       Copyright (C) 2009-2011 Volatile Systems
#
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#       MA 02110-1301, USA.

# pylint: disable=protected-access

"""
@author:       Andreas Schuster
@license:      GNU General Public License 2.0 or later
@contact:      a.schuster@forensikblog.de
@organization: http://computer.forensikblog.de/en/
"""

from rekall import obj
from rekall import scan
from rekall.plugins.windows import common


class PoolScanFile(common.PoolScanner):
    """PoolScanner for File objects"""
    def __init__(self, **kwargs):
        super(PoolScanFile, self).__init__(**kwargs)
        self.checks = [
            ('PoolTagCheck', dict(
                    tag=self.profile.get_constant("FILE_POOLTAG"))),

            ('CheckPoolSize', dict(
                    min_size=self.profile.get_obj_size("_FILE_OBJECT"))),

            ('CheckPoolType', dict(
                    paged=True, non_paged=True, free=True)),

            ('CheckPoolIndex', dict(value=0)),
            ]


class FileScan(common.PoolScannerPlugin):
    """ Scan Physical memory for _FILE_OBJECT pool allocations
    """
    __name = "filescan"

    allocation = ['_POOL_HEADER', '_OBJECT_HEADER', '_FILE_OBJECT']

    def generate_hits(self):
        """Generate possible hits."""
        scanner = PoolScanFile(profile=self.profile, session=self.session,
                               address_space=self.address_space)

        for pool_obj in scanner.scan():
            object_obj = pool_obj.get_object("_OBJECT_HEADER", self.allocation)

            if object_obj.get_object_type(self.kernel_address_space) != "File":
                continue

            ## If the string is not reachable we skip it
            file_obj = pool_obj.get_object("_FILE_OBJECT", self.allocation)
            if not file_obj.FileName.v(vm=self.kernel_address_space):
                continue

            yield (object_obj, file_obj)

    def render(self, renderer):
        """Print the output in a table."""

        renderer.table_header([('Offset', "offset_p", '[addrpad]'),
                               ('#Ptr', "ptr_count", '>3'),
                               ('#Hnd', "hnd_count", '>3'),
                               ('Access', "access", '6'),
                               ('Owner', "owner", '[addrpad]'),
                               ('Owner Pid', "owner_pid", '>4'),
                               ('Owner Name', "owner_name", '16'),
                               ('Name', "path", '')
                               ])

        for object_obj, file_obj in self.generate_hits():
            # The Process member in the object_obj sometimes points at the
            # _EPROCESS.
            try:
                # TODO: Currently this only works in Windows 7. Fix for XP.
                owner_process = object_obj.HandleInfo.SingleEntry.Process.dereference(
                    vm=self.kernel_address_space)
            except AttributeError:
                owner_process = obj.NoneObject("HandleInfo not found")

            renderer.table_row(
                file_obj.obj_offset,
                object_obj.PointerCount,
                object_obj.HandleCount,
                file_obj.AccessString,
                owner_process.obj_offset,
                owner_process.UniqueProcessId,
                owner_process.ImageFileName,
                file_obj.FileName.v(vm=self.kernel_address_space))


class PoolScanDriver(PoolScanFile):
    """ Scanner for _DRIVER_OBJECT """

    def __init__(self, **kwargs):
        super(PoolScanDriver, self).__init__(**kwargs)
        self.checks = [
            ('PoolTagCheck', dict(
                    tag=self.profile.get_constant("DRIVER_POOLTAG"))),

            # Must be large enough to hold the driver object.
            ('CheckPoolSize', dict(
                    condition=lambda x: x > self.profile.get_obj_size(
                        "_DRIVER_OBJECT"))),

            ('CheckPoolType', dict(
                    paged=True, non_paged=True, free=True)),

            ('CheckPoolIndex', dict(value=0)),
            ]

class DriverScan(FileScan):
    "Scan for driver objects _DRIVER_OBJECT "

    __name = "driverscan"


    allocation = ['_POOL_HEADER', '_OBJECT_HEADER', '_DRIVER_OBJECT',
                  '_DRIVER_EXTENSION']

    def generate_hits(self):
        """Generate possible hits."""
        scanner = PoolScanDriver(session=self.session,
                                 profile=self.profile,
                                 address_space=self.address_space)

        for pool_obj in scanner.scan():
            object_obj = pool_obj.get_object("_OBJECT_HEADER", self.allocation)
            if object_obj.get_object_type(
                self.kernel_address_space) != "Driver":
                continue

            object_name = object_obj.NameInfo.Name.v(
                vm=self.kernel_address_space)

            driver_obj = pool_obj.get_object("_DRIVER_OBJECT", self.allocation)
            extension_obj = pool_obj.get_object(
                "_DRIVER_EXTENSION", self.allocation)

            yield (object_obj, driver_obj, extension_obj, object_name)


    def render(self, renderer):
        """Renders the text-based output"""
        renderer.table_header([('Offset(P)', "offset_p", '[addrpad]'),
                               ('#Ptr', "ptr_count", '>4'),
                               ('#Hnd', "hnd_count", '>4'),
                               ('Start', "driver_start", '[addrpad]'),
                               ('Size', "driver_size", '[addr]'),
                               ('Service Key', "driver_servicekey", '20'),
                               ('Name', "driver_name", '12'),
                               ('Driver Name', "path", '')
                               ])

        for _ in self.generate_hits():
            object_obj, driver_obj, extension_obj, object_name = _
            renderer.table_row(
                driver_obj.obj_offset,
                object_obj.PointerCount,
                object_obj.HandleCount,
                driver_obj.DriverStart,
                driver_obj.DriverSize,
                extension_obj.ServiceKeyName.v(vm=self.kernel_address_space),
                object_name,
                driver_obj.DriverName.v(vm=self.kernel_address_space))


class PoolScanSymlink(PoolScanFile):
    """ Scanner for symbolic link objects """
    def __init__(self, **kwargs):
        super(PoolScanSymlink, self).__init__(**kwargs)
        self.checks = [
            ('PoolTagCheck', dict(
                    tag=self.profile.get_constant("SYMLINK_POOLTAG"))),

            ('CheckPoolSize', dict(
                    min_size=self.profile.get_obj_size(
                        "_OBJECT_SYMBOLIC_LINK"))),

            ('CheckPoolType', dict(paged=True, non_paged=True, free=True)),
            ]


class SymLinkScan(FileScan):
    "Scan for symbolic link objects "

    __name = "symlinkscan"

    allocation = ['_POOL_HEADER', '_OBJECT_HEADER', '_OBJECT_SYMBOLIC_LINK']

    def generate_hits(self):
        """Generate possible hits."""
        scanner = PoolScanSymlink(profile=self.profile, session=self.session,
                                  address_space=self.address_space)
        for pool_obj in scanner.scan():
            object_obj = pool_obj.get_object("_OBJECT_HEADER", self.allocation)
            if object_obj.get_object_type(
                self.kernel_address_space) != "SymbolicLink":
                continue

            object_name = object_obj.NameInfo.Name.v(
                vm=self.kernel_address_space)

            link_obj = pool_obj.get_object(
                "_OBJECT_SYMBOLIC_LINK", self.allocation)

            yield object_obj, link_obj, object_name

    def render(self, renderer):
        """ Renders text-based output """
        renderer.table_header([('Offset(P)', "offset_p", '[addrpad]'),
                               ('#Ptr', "ptr_count", '>6'),
                               ('#Hnd', "hnd_count", '>6'),
                               ('Creation time', "symlink_creation_time", '24'),
                               ('From', "symlink_from", ''),
                               ('To', "symlink_to", '60'),
                               ])


        for o, link, name in self.generate_hits():
            renderer.table_row(
                link.obj_offset,
                o.PointerCount,
                o.HandleCount,
                link.CreationTime or '',
                name,
                link.LinkTarget.v(vm=self.kernel_address_space))


class PoolScanMutant(PoolScanDriver):
    """ Scanner for Mutants _KMUTANT """
    def __init__(self, **kwargs):
        super(PoolScanMutant, self).__init__(**kwargs)
        self.checks = [
            ('PoolTagCheck', dict(tag=self.profile.get_constant(
                        "MUTANT_POOLTAG"))),

            ('CheckPoolSize', dict(
                    min_size=self.profile.get_obj_size("_KMUTANT"))),

            ('CheckPoolType', dict(
                    paged=True, non_paged=True, free=True)),

            ('CheckPoolIndex', dict(value=0)),
            ]


class MutantScan(FileScan):
    "Scan for mutant objects _KMUTANT "

    __name = "mutantscan"

    allocation = ['_POOL_HEADER', '_OBJECT_HEADER', '_KMUTANT']

    def __init__(self, silent=False, **kwargs):
        """Scan for mutant objects _KMUTANT.

        Args:
           silent: Suppress less meaningful results.
        """
        super(MutantScan, self).__init__(**kwargs)
        self.silent = silent

    def generate_hits(self):
        scanner = PoolScanMutant(profile=self.profile, session=self.session,
                                 address_space=self.address_space)

        for pool_obj in scanner.scan():
            object_obj = pool_obj.get_object("_OBJECT_HEADER", self.allocation)
            if object_obj.get_object_type(
                self.kernel_address_space) != "Mutant":
                continue

            object_name = object_obj.NameInfo.Name.v(
                vm=self.kernel_address_space)

            if self.silent and not object_name:
                continue

            mutant = pool_obj.get_object("_KMUTANT", self.allocation)
            yield (object_obj, mutant, object_name)

    def render(self, renderer):
        """Renders the output"""

        renderer.table_header([('Offset(P)', "offset_p", '[addrpad]'),
                               ('#Ptr', "ptr_count", '>4'),
                               ('#Hnd', "hnd_count", '>4'),
                               ('Signal', "mutant_signal", '4'),
                               ('Thread', "mutant_thread", '[addrpad]'),
                               ('CID', "cid", '>9'),
                               ('Name', "mutant_name", '')
                               ])

        for object_obj, mutant, _ in self.generate_hits():
            if mutant.OwnerThread > 0x80000000:
                thread = self.profile._ETHREAD(
                    offset=mutant.OwnerThread, vm=self.kernel_address_space)

                CID = "{0}:{1}".format(thread.Cid.UniqueProcess,
                                       thread.Cid.UniqueThread)
            else:
                CID = ""

            renderer.table_row(
                mutant.obj_offset,
                object_obj.PointerCount,
                object_obj.HandleCount,
                mutant.Header.SignalState,
                mutant.OwnerThread,
                CID,
                object_obj.NameInfo.Name.v(vm=self.kernel_address_space))


class CheckProcess(scan.ScannerCheck):
    """Check sanity of _EPROCESS."""
    kernel = 0x80000000

    def check(self, buffer_as, offset):
        """Check a possible _EPROCESS."""
        pool_obj = self.profile._POOL_HEADER(offset=offset, vm=buffer_as)

        eprocess = pool_obj.get_object(
            "_EPROCESS", PoolScanProcess.allocation)

        if eprocess.Pcb.DirectoryTableBase == 0:
            return False

        # The DTB is page aligned on AMD64 and I386 but aligned to 0x20 on PAE
        # kernels.
        if eprocess.Pcb.DirectoryTableBase % 0x20 != 0:
            return False

        list_head = eprocess.ThreadListHead

        # Pointers must point to the kernel part of the address space.
        if (list_head.Flink < self.kernel) or (list_head.Blink < self.kernel):
            return False

        return True


class PoolScanProcess(common.PoolScanner):
    """PoolScanner for File objects"""
    allocation = ['_POOL_HEADER', '_OBJECT_HEADER', '_EPROCESS']

    def __init__(self, **kwargs):
        super(PoolScanProcess, self).__init__(**kwargs)
        self.checks = [
            # Must have the right pool tag.
            ('PoolTagCheck', dict(
                    tag=self.profile.get_constant("EPROCESS_POOLTAG"))),

            # Must be large enough for an _EPROCESS.
            ('CheckPoolSize', dict(min_size=self.profile.get_obj_size(
                        "_EPROCESS"))),

            ('CheckPoolType', dict(
                    paged=True, non_paged=True, free=True)),

            ('CheckPoolIndex', dict(value=0)),
            ('CheckProcess', {}),
            ]

    def scan(self, **_):
        for pool_obj in super(PoolScanProcess, self).scan():
            eprocess = pool_obj.get_object("_EPROCESS", self.allocation)

            if eprocess.Pcb.DirectoryTableBase == 0:
                continue

            if eprocess.Pcb.DirectoryTableBase % 0x20 != 0:
                continue

            yield eprocess


class PSScan(common.KDBGMixin, common.PoolScannerPlugin):
    """Scan Physical memory for _EPROCESS pool allocations.

    Status flags:
      E: A known _EPROCESS address from pslist.
      P: A known pid from pslist.
    """

    __name = "psscan"

    def guess_eprocess_virtual_address(self, eprocess):
        """Try to guess the virtual address of the eprocess."""
        # This is the list entry of the ProcessListEntry reflected through the
        # next process in the list
        list_entry = eprocess.ThreadListHead.Flink.dereference_as(
            '_LIST_ENTRY', vm=self.kernel_address_space).Blink.dereference()

        # Take us back to the _EPROCESS offset
        list_entry_offset = self.profile.get_obj_offset(
            '_EPROCESS', 'ThreadListHead')

        # The virtual eprocess should be the same as the physical one
        kernel_eprocess_offset = list_entry.obj_offset - list_entry_offset

        return kernel_eprocess_offset

    def scan_processes(self):
        """Generate possible hits."""
        # Just grab the AS and scan it using our scanner
        scanner = PoolScanProcess(session=self.session,
                                  profile=self.profile,
                                  address_space=self.address_space)

        return scanner.scan()

    def render(self, renderer):
        """Render results in a table."""
        # Try to do a regular process listing so we can compare if the process
        # is known.
        pslist = self.session.plugins.pslist(kdbg=self.kdbg)

        # These are virtual addresses.
        known_eprocess = set()
        known_pids = set()
        for task in pslist.list_eprocess():
            known_eprocess.add(task.obj_offset)
            known_pids.add(task.UniqueProcessId)

        renderer.table_header([('Offset', "offset_p", '[addrpad]'),
                               ('Offset(V)', "offset_v", '[addrpad]'),
                               ('Name', "file_name", '16'),
                               ('PID', "pid", '>6'),
                               ('PPID', "ppid", '>6'),
                               ('PDB', "pdb", '[addrpad]'),
                               ('Stat', 'stat', "4"),
                               ('Time created', "process_create_time", '24'),
                               ('Time exited', "process_exit_time", '24')]
                               )

        for eprocess in self.scan_processes():

            # Try to guess the virtual address of the eprocess
            eprocess_virtual_address = self.guess_eprocess_virtual_address(
                eprocess)

            known = ""
            if eprocess_virtual_address in known_eprocess:
                known += "E"

            if eprocess.UniqueProcessId in known_pids:
                known += "P"

            renderer.table_row(eprocess.obj_offset,
                               eprocess_virtual_address,
                               eprocess.ImageFileName,
                               eprocess.UniqueProcessId,
                               eprocess.InheritedFromUniqueProcessId,
                               eprocess.Pcb.DirectoryTableBase,
                               known,
                               eprocess.CreateTime or '',
                               eprocess.ExitTime or '')
