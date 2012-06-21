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

"""
@author:       Andreas Schuster
@license:      GNU General Public License 2.0 or later
@contact:      a.schuster@forensikblog.de
@organization: http://computer.forensikblog.de/en/
"""

from volatility import obj
from volatility import scan
from volatility import utils
from volatility.plugins.windows import common


class PoolScanFile(common.PoolScanner):
    """PoolScanner for File objects"""
    allocation = ['_POOL_HEADER', '_OBJECT_HEADER', '_FILE_OBJECT']

    checks = [ ('PoolTagCheck', dict(tag = "Fil\xe5")),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x98)),
               ('CheckPoolType', dict(paged = True, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]


class FileScan(common.PoolScannerPlugin):
    """ Scan Physical memory for _FILE_OBJECT pool allocations
    """
    # Declare meta information associated with this plugin
    meta_info = {}
    meta_info['author'] = 'Andreas Schuster'
    meta_info['copyright'] = 'Copyright (c) 2009 Andreas Schuster'
    meta_info['contact'] = 'a.schuster@forensikblog.de'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://computer.forensikblog.de/en/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '0.1'

    __name = "filescan"

    def generate_hits(self):
        """Generate possible hits."""
        scanner = PoolScanFile(profile=self.profile,
                               address_space=self.address_space)
        for offset in scanner.scan():
            object_obj = scanner.get_object(offset, "_OBJECT_HEADER")
            if object_obj.get_object_type(self.kernel_address_space) != "File":
                continue

            ## If the string is not reachable we skip it
            file_obj = scanner.get_object(offset, "_FILE_OBJECT")
            if not file_obj.FileName.v(vm=self.kernel_address_space):
                continue

            yield (object_obj, file_obj)

    def render(self, renderer):
        """Print the output in a table."""

        renderer.table_header([('Offset', '[addrpad]'),
                               ('#Ptr', '>3'),
                               ('#Hnd', '>3'),
                               ('Access', '6'),
                               ('Owner', '[addrpad]'),
                               ('Owner Pid', '>4'),
                               ('Owner Name', '16'),
                               ('Name', '')
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

            renderer.table_row(file_obj.obj_offset, object_obj.PointerCount,
                               object_obj.HandleCount, file_obj.AccessString,
                               owner_process.obj_offset,
                               owner_process.UniqueProcessId,
                               owner_process.ImageFileName,
                               file_obj.FileName.v(vm=self.kernel_address_space))


class PoolScanDriver(PoolScanFile):
    """ Scanner for _DRIVER_OBJECT """
    allocation = ['_POOL_HEADER', '_OBJECT_HEADER', '_DRIVER_OBJECT',
                  '_DRIVER_EXTENSION']
    checks = [ ('PoolTagCheck', dict(tag = "Dri\xf6")),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0xf8)),
               ('CheckPoolType', dict(paged = True, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class DriverScan(FileScan):
    "Scan for driver objects _DRIVER_OBJECT "

    __name = "driverscan"

    def generate_hits(self):
        """Generate possible hits."""
        scanner = PoolScanDriver(
            profile=self.profile, address_space=self.address_space)

        for offset in scanner.scan():
            object_obj = scanner.get_object(offset, "_OBJECT_HEADER")
            if object_obj.get_object_type(self.kernel_address_space) != "Driver":
                continue

            object_name = object_obj.NameInfo.Name.v(
                vm=self.kernel_address_space)

            driver_obj = scanner.get_object(offset, "_DRIVER_OBJECT")
            extension_obj = scanner.get_object(offset, "_DRIVER_EXTENSION")
            yield (object_obj, driver_obj, extension_obj, object_name)


    def render(self, renderer):
        """Renders the text-based output"""
        renderer.table_header([('Offset(P)', '[addrpad]'),
                               ('#Ptr', '>4'),
                               ('#Hnd', '>4'),
                               ('Start', '[addrpad]'),
                               ('Size', '[addr]'),
                               ('Service Key', '20'),
                               ('Name', '12'),
                               ('Driver Name', '')
                               ])

        for object_obj, driver_obj, extension_obj, object_name in self.generate_hits():
            renderer.table_row(driver_obj.obj_offset, object_obj.PointerCount,
                               object_obj.HandleCount,
                               driver_obj.DriverStart, driver_obj.DriverSize,
                               extension_obj.ServiceKeyName.v(vm=self.kernel_address_space),
                               object_name,
                               driver_obj.DriverName.v(vm=self.kernel_address_space))


class PoolScanSymlink(PoolScanFile):
    """ Scanner for symbolic link objects """
    allocation = ['_POOL_HEADER', '_OBJECT_HEADER', '_OBJECT_SYMBOLIC_LINK']
    checks = [ ('PoolTagCheck', dict(tag = "Sym\xe2")),
               # We use 0x48 as the lower bounds instead of 0x50 as described by Andreas
               # http://computer.forensikblog.de/en/2009/04/symbolic_link_objects.html.
               # This is because the _OBJECT_SYMBOLIC_LINK structure size is 2 bytes smaller
               # on Windows 7 (a field was removed) than on all other OS versions.
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x48)),
               ('CheckPoolType', dict(paged = True, non_paged = True, free = True)),
               ]

class SymLinkScan(FileScan):
    "Scan for symbolic link objects "

    __name = "symlinkscan"

    def generate_hits(self):
        """Generate possible hits."""
        scanner = PoolScanSymlink(profile=self.profile,
                                  address_space=self.address_space)
        for offset in scanner.scan():
            object_obj = scanner.get_object(offset, "_OBJECT_HEADER")
            if object_obj.get_object_type(self.kernel_address_space) != "SymbolicLink":
                continue

            object_name = object_obj.NameInfo.Name.v(vm=self.kernel_address_space)
            link_obj = scanner.get_object(offset, "_OBJECT_SYMBOLIC_LINK")
            yield object_obj, link_obj, object_name

    def render(self, renderer):
        """ Renders text-based output """
        renderer.table_header([('Offset(P)', '[addrpad]'),
                               ('#Ptr', '>6'),
                               ('#Hnd', '>6'),
                               ('Creation time', '24'),
                               ('From', '<20'),
                               ('To', '60'),
                               ])


        for o, link, name in self.generate_hits():
            renderer.table_row(link.obj_offset, o.PointerCount,
                               o.HandleCount, link.CreationTime or '',
                               name, link.LinkTarget.v(vm=self.kernel_address_space))


class PoolScanMutant(PoolScanDriver):
    """ Scanner for Mutants _KMUTANT """
    allocation = ['_POOL_HEADER', '_OBJECT_HEADER', '_KMUTANT']
    checks = [ ('PoolTagCheck', dict(tag = "Mut\xe1")),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x40)),
               ('CheckPoolType', dict(paged = True, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]


class MutantScan(FileScan):
    "Scan for mutant objects _KMUTANT "

    __name = "mutantscan"

    def __init__(self, silent=None, **kwargs):
        """Scan for mutant objects _KMUTANT.

        Args:
           silent: Suppress less meaningful results.
        """
        super(MutantScan, self).__init__(**kwargs)
        self.silent = silent

    def generate_hits(self):
        scanner = PoolScanMutant(profile=self.profile,
                                 address_space=self.address_space)
        for offset in scanner.scan():
            object_obj = scanner.get_object(offset, "_OBJECT_HEADER")
            if object_obj.get_object_type(self.kernel_address_space) != "Mutant":
                continue

            ## Skip unallocated objects
            ##if object_obj.Type == 0xbad0b0b0:
            ##   continue
            object_name = object_obj.NameInfo.Name.v(vm=self.kernel_address_space)

            if self.silent:
                if object_name.Length == 0:
                    continue

            mutant = scanner.get_object(offset, "_KMUTANT")
            yield (object_obj, mutant, object_name)

    def render(self, renderer):
        """Renders the output"""

        renderer.table_header([('Offset(P)', '[addrpad]'),
                               ('#Ptr', '>4'),
                               ('#Hnd', '>4'),
                               ('Signal', '4'),
                               ('Thread', '[addrpad]'),
                               ('CID', '>9'),
                               ('Name', '')
                               ])

        for object_obj, mutant, object_name in self.generate_hits():
            if mutant.OwnerThread > 0x80000000:
                thread = self.profile.Object("_ETHREAD", vm=self.kernel_address_space,
                                             offset=mutant.OwnerThread)
                CID = "{0}:{1}".format(thread.Cid.UniqueProcess, thread.Cid.UniqueThread)
            else:
                CID = ""

            renderer.table_row(mutant.obj_offset, object_obj.PointerCount,
                               object_obj.HandleCount, mutant.Header.SignalState,
                               mutant.OwnerThread, CID,
                               object_obj.NameInfo.Name.v(vm=self.kernel_address_space))

class CheckProcess(scan.ScannerCheck):
    """ Check sanity of _EPROCESS """
    kernel = 0x80000000

    def check(self, found):
        """Check a possible _EPROCESS."""
        ## The offset of the object is determined by subtracting the offset
        ## of the PoolTag member to get the start of Pool Object. This done
        ## because PoolScanners search for the PoolTag.
        pool_base = found - self.profile.get_obj_offset(
            '_POOL_HEADER', 'PoolTag')

        pool_obj = self.profile.Object("_POOL_HEADER", vm = self.address_space,
                                       offset = pool_base)
        pool_align = self.profile.constants['PoolAlignment']

        eprocess = self.profile.Object(
            "_EPROCESS", vm = self.address_space,
            offset = pool_base + pool_obj.BlockSize * pool_align - \
                self.profile.get_obj_size("_EPROCESS")
            )

        if (eprocess.Pcb.DirectoryTableBase == 0):
            return False

        if (eprocess.Pcb.DirectoryTableBase % 0x20 != 0):
            return False

        list_head = eprocess.ThreadListHead

        if (list_head.Flink < self.kernel) or (list_head.Blink < self.kernel):
            return False

        return True


class PoolScanProcess(common.PoolScanner):
    """PoolScanner for File objects"""
    allocation = ['_POOL_HEADER', '_OBJECT_HEADER', '_EPROCESS']
    checks = [ ('PoolTagCheck', dict(tag = '\x50\x72\x6F\xe3')),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x280)),
               ('CheckPoolType', dict(paged = True, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

    kernel = 0x80000000

    def scan(self, **kwargs):
        for offset in super(PoolScanProcess, self).scan():
            eprocess = self.get_object(offset, "_EPROCESS")

            if (eprocess.Pcb.DirectoryTableBase == 0):
                continue

            if (eprocess.Pcb.DirectoryTableBase % 0x20 != 0):
                continue

            list_head = eprocess.ThreadListHead

            if (list_head.Flink < self.kernel) or (list_head.Blink < self.kernel):
                continue

            yield eprocess


class PSScan(common.PoolScannerPlugin):
    """Scan Physical memory for _EPROCESS pool allocations."""
    # Declare meta information associated with this plugin
    meta_info = {}
    meta_info['author'] = 'AAron Walters'
    meta_info['copyright'] = 'Copyright (c) 2011 Volatile Systems'
    meta_info['contact'] = 'awalters@volatilesystems.com'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'https://www.volatilesystems.com/'
    meta_info['os'] = ['Win7SP0x86', 'WinXPSP3x86']
    meta_info['version'] = '0.1'

    __name = "psscan"

    def calculate(self):
        """Generate possible hits."""
        ## Just grab the AS and scan it using our scanner
        scanner =  PoolScanProcess(
            profile=self.profile, address_space=self.address_space)

        return scanner.scan()

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

        if self.kernel_address_space.vtop(kernel_eprocess_offset) == eprocess.obj_offset:
            return kernel_eprocess_offset

        return 0


    def render(self, renderer):
        """Render results in a table."""
        renderer.table_header([('Offset', '[addrpad]'),
                               ('Offset(V)', '[addrpad]'),
                               ('Name', '16'),
                               ('PID', '>6'),
                               ('PPID', '>6'),
                               ('PDB', '[addrpad]'),
                               ('Time created', '20'),
                               ('Time exited', '20')
                               ])

        for eprocess in self.calculate():
            # Try to guess the virtual address of the eprocess
            eprocess_virtual_address = self.guess_eprocess_virtual_address(eprocess)

            renderer.table_row(eprocess.obj_offset,
                               eprocess_virtual_address,
                               eprocess.ImageFileName,
                               eprocess.UniqueProcessId,
                               eprocess.InheritedFromUniqueProcessId,
                               eprocess.Pcb.DirectoryTableBase,
                               eprocess.CreateTime or '',
                               eprocess.ExitTime or '')
