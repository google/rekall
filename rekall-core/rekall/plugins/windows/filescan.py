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

    table_header = [
        dict(name='a', width=1),
        dict(name="offset", style="address"),
        dict(name="ptr_no", width=6, align="r"),
        dict(name="hnd_no", width=3, align="r"),
        dict(name="access", width=6),
        dict(name='Owner', type="_EPROCESS"),
        dict(name="path")
    ]

    scanner_defaults = dict(
        scan_kernel_nonpaged_pool=True
    )

    def collect(self):
        """Generate possible hits."""
        for run in self.generate_memory_ranges():
            scanner = PoolScanFile(profile=self.profile, session=self.session,
                                   address_space=run.address_space)

            for pool_obj in scanner.scan(run.start, run.length):
                for object_obj in pool_obj.IterObject("File", freed=True):
                    ## If the string is not reachable we skip it
                    file_obj = self.session.profile._FILE_OBJECT(
                        offset=object_obj.obj_end, vm=run.address_space)

                    if not file_obj.FileName.v(vm=self.kernel_address_space):
                        continue

                    # Real file objects have valid DeviceObject types.
                    device_obj = file_obj.DeviceObject.deref(
                        vm=self.session.kernel_address_space)

                    if not device_obj.DeviceType.is_valid():
                        continue

                    # The Process member in the HandleInfo sometimes points at
                    # the _EPROCESS owning the handle.
                    owner_process = (
                        object_obj.HandleInfo.SingleEntry.Process.deref(
                            vm=self.kernel_address_space))

                    filename = file_obj.file_name_with_drive(
                        vm=self.kernel_address_space)

                    yield dict(a='F' if pool_obj.FreePool else "",
                               offset=file_obj.obj_offset,
                               ptr_no=object_obj.PointerCount,
                               hnd_no=object_obj.HandleCount,
                               access=file_obj.AccessString,
                               Owner=owner_process,
                               path=filename)


class PoolScanDriver(common.PoolScanner):
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


class DriverScan(common.PoolScannerPlugin):
    "Scan for driver objects _DRIVER_OBJECT "

    __name = "driverscan"

    table_header = [
        dict(name='a', width=1),
        dict(name="offset", style="address"),
        dict(name="ptr_no", width=6, align="r"),
        dict(name="hnd_no", width=3, align="r"),
        dict(name="start", style="address"),
        dict(name="size", style="address"),
        dict(name="servicekey", width=20),
        dict(name="name", width=12),
        dict(name="path")
    ]

    scanner_defaults = dict(
        scan_kernel_nonpaged_pool=True
    )

    def collect(self):
        """Generate possible hits."""
        for run in self.generate_memory_ranges():
            scanner = PoolScanDriver(session=self.session,
                                     profile=self.profile,
                                     address_space=run.address_space)

            for pool_obj in scanner.scan(run.start, run.length):
                for object_obj in pool_obj.IterObject("Driver", freed=True):
                    object_name = object_obj.NameInfo.Name.v(
                        vm=self.kernel_address_space)

                    driver_obj = self.profile._DRIVER_OBJECT(
                        object_obj.obj_end, vm=run.address_space)

                    extension_obj = self.profile._DRIVER_EXTENSION(
                        driver_obj.obj_end, vm=run.address_space)

                    yield dict(a='F' if pool_obj.FreePool else "",
                               offset=driver_obj.obj_offset,
                               ptr_no=object_obj.PointerCount,
                               hnd_no=object_obj.HandleCount,
                               start=driver_obj.DriverStart,
                               size=driver_obj.DriverSize,
                               servicekey=extension_obj.ServiceKeyName.v(
                                   vm=self.kernel_address_space),
                               name=object_name,
                               path=driver_obj.DriverName.v(
                                   vm=self.kernel_address_space)
                    )


class PoolScanSymlink(common.PoolScanner):
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


class SymLinkScan(common.PoolScannerPlugin):
    "Scan for symbolic link objects "

    __name = "symlinkscan"

    table_header = [
        dict(name='a', width=1),
        dict(name="offset", style="address"),
        dict(name="ptr_no", width=6, align="r"),
        dict(name="hnd_no", width=3, align="r"),
        dict(name="creation_time", width=24),
        dict(name="from_link"),
        dict(name="to_link", width=60),
    ]

    scanner_defaults = dict(
        # According to pool_tracker plugin this always comes from paged pool.
        scan_kernel_paged_pool=True
    )

    def collect(self):
        """Generate possible hits."""
        for run in self.generate_memory_ranges():
            scanner = PoolScanSymlink(profile=self.profile,
                                      session=self.session,
                                      address_space=run.address_space)
            for pool_obj in scanner.scan(run.start, run.length):
                for object_obj in pool_obj.IterObject(
                        "SymbolicLink", freed=True):
                    object_name = object_obj.NameInfo.Name.v(
                        vm=self.kernel_address_space)

                    link_obj = self.profile._OBJECT_SYMBOLIC_LINK(
                        object_obj.obj_end, vm=run.address_space)

                    yield dict(a='F' if pool_obj.FreePool else "",
                               offset=link_obj.obj_offset,
                               ptr_no=object_obj.PointerCount,
                               hnd_no=object_obj.HandleCount,
                               creation_time=link_obj.CreationTime or '',
                               from_link=object_name,
                               to_link=link_obj.LinkTarget.v(
                                   vm=self.kernel_address_space))


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


class MutantScan(common.PoolScannerPlugin):
    "Scan for mutant objects _KMUTANT "

    __name = "mutantscan"

    table_header = [
        dict(name='a', width=1),
        dict(name="offset", style="address"),
        dict(name="ptr_no", width=6, align="r"),
        dict(name="hnd_no", width=3, align="r"),
        dict(name="signal", width=6),
        dict(name="thread", style="address"),
        dict(name="cid", width=9, align="r"),
        dict(name="name")
    ]

    scanner_defaults = dict(
        scan_kernel_nonpaged_pool=True,
    )

    def collect(self):
        for run in self.generate_memory_ranges():
            scanner = PoolScanMutant(profile=self.profile, session=self.session,
                                     address_space=run.address_space)

            for pool_obj in scanner.scan(run.start, run.length):
                for object_obj in pool_obj.IterObject("Mutant", freed=True):
                    object_name = object_obj.NameInfo.Name.v(
                        vm=self.kernel_address_space)

                    # By default we suppress non-named mutants because they are
                    # not very interesting.
                    if self.plugin_args.verbosity < 5 and not object_name:
                        continue

                    mutant = self.profile._KMUTANT(
                        object_obj.obj_end, vm=run.address_space)

                    if mutant.OwnerThread > 0x80000000:
                        thread = self.profile._ETHREAD(
                            offset=mutant.OwnerThread,
                            vm=self.kernel_address_space)

                        CID = "{0}:{1}".format(thread.Cid.UniqueProcess,
                                               thread.Cid.UniqueThread)
                    else:
                        CID = ""

                    yield dict(a='F' if pool_obj.FreePool else "",
                               offset=mutant.obj_offset,
                               ptr_no=object_obj.PointerCount,
                               hnd_no=object_obj.HandleCount,
                               signal=mutant.Header.SignalState,
                               thread=mutant.OwnerThread,
                               cid=CID,
                               name=object_obj.NameInfo.Name.v(
                                   vm=self.kernel_address_space))


class PoolScanProcess(common.PoolScanner):
    """PoolScanner for File objects"""

    # Kernel addresses are above this value.
    kernel = 0x80000000

    def __init__(self, **kwargs):
        super(PoolScanProcess, self).__init__(**kwargs)
        self.kernel = self.profile.get_constant_object(
            "MmSystemRangeStart", "Pointer").v() or 0x80000000

        self.checks = [
            # Must have the right pool tag.
            ('PoolTagCheck', dict(
                tag=self.profile.get_constant("EPROCESS_POOLTAG"))),

            # Must be large enough for an _EPROCESS.
            ('CheckPoolSize', dict(min_size=self.profile.get_obj_size(
                "_EPROCESS"))),

            # It seems that on old XP versions _EPROCESS was allocated from
            # paged pool but it's rare to see that.
            ('CheckPoolType', dict(
                paged=True, non_paged=True, free=True)),

            ('CheckPoolIndex', dict(value=0)),
        ]

        # The DTB is page aligned on AMD64 and I386 but aligned to 0x20
        # on PAE kernels.
        if self.session.kernel_address_space.metadata("pae"):
            self.dtb_alignment = 0x20
        else:
            self.dtb_alignment = 0x1000

    def scan(self, **kwargs):
        for pool_obj in super(PoolScanProcess, self).scan(**kwargs):
            # Also fetch freed objects.
            for object_header in pool_obj.IterObject("Process", freed=True):
                eprocess = object_header.Body.cast("_EPROCESS")

                if eprocess.Pcb.DirectoryTableBase == 0:
                    continue

                if eprocess.Pcb.DirectoryTableBase % self.dtb_alignment != 0:
                    continue

                # Pointers must point to the kernel part of the address space.
                list_head = eprocess.ActiveProcessLinks
                if (list_head.Flink < self.kernel or
                        list_head.Blink < self.kernel):
                    continue

                yield pool_obj, eprocess


class PSScan(common.WinScanner):
    """Scan Physical memory for _EPROCESS pool allocations.

    Status flags:
      E: A known _EPROCESS address from pslist.
      P: A known pid from pslist.
    """

    name = "psscan"

    table_header = [
        dict(name='a', width=1),
        dict(name="offset_p", type="_EPROCESS"),
        dict(name="offset_v", style="address"),
        dict(name="ppid", width=6, align="r"),
        dict(name="pdb", style="address"),
        dict(name='stat', width=4),
        dict(name="create_time", width=24),
        dict(name="exit_time", width=24),
    ]

    # Only bother to scan non paged pool by default.
    scanner_defaults = dict(
        scan_kernel_nonpaged_pool=True
    )

    def collect(self):
        """Render results in a table."""
        # Try to do a regular process listing so we can compare if the process
        # is known.
        pslist = self.session.plugins.pslist()

        # These are virtual addresses.
        known_eprocess = set()
        known_pids = set()
        for task in pslist.list_eprocess():
            known_eprocess.add(task)
            known_pids.add(task.UniqueProcessId)

        # Scan each requested run in turn.
        for run in self.generate_memory_ranges():
            # Just grab the AS and scan it using our scanner
            scanner = PoolScanProcess(session=self.session,
                                      profile=self.profile,
                                      address_space=run.address_space)

            for pool_obj, eprocess in scanner.scan(
                    offset=run.start, maxlen=run.length):
                if run.data["type"] == "PhysicalAS":
                    # Switch address space from physical to virtual.
                    virtual_eprocess = (
                        pslist.virtual_process_from_physical_offset(eprocess))
                else:
                    virtual_eprocess = eprocess

                known = ""
                if virtual_eprocess in known_eprocess:
                    known += "E"

                if eprocess.UniqueProcessId in known_pids:
                    known += "P"

                yield dict(a='F' if pool_obj.FreePool else "",
                           offset_p=eprocess,
                           offset_v=virtual_eprocess.obj_offset,
                           ppid=eprocess.InheritedFromUniqueProcessId,
                           pdb=eprocess.Pcb.DirectoryTableBase,
                           stat=known,
                           create_time=eprocess.CreateTime or '',
                           exit_time=eprocess.ExitTime or '')
