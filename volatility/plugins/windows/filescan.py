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

import volatility.scan as scan
from volatility.plugins.windows import common
from volatility import utils


class PoolScanFile(scan.PoolScanner):
    """PoolScanner for File objects"""
    ## We dont want any preamble - the offsets should be those of the
    ## _POOL_HEADER directly.
    preamble = []
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

    def __init__(self, **kwargs):
        """Scan memory for _FILE_OBJECT pool allocations."""
        super(FileScan, self).__init__(**kwargs)
        self.pool_align = self.profile.constants['PoolAlignment']

    def get_rounded_size(self, object_name):
        """Returns the size of the object accounting for pool alignment."""
        size_of_obj = self.profile.get_obj_size(object_name)

        # Size is rounded to pool alignment
        extra = size_of_obj % self.pool_align
        if extra:
            size_of_obj += self.pool_align - extra

        return size_of_obj

    def generate_hits(self):
        """Generate possible hits."""
        address_space = self.physical_address_space

        for offset in PoolScanFile(profile=self.profile).scan(address_space):
            pool_obj = self.profile.Object("_POOL_HEADER", vm=address_space,
                                           offset=offset)

            ## We work out the _FILE_OBJECT from the end of the
            ## allocation (bottom up).
            file_obj = self.profile.Object(
                "_FILE_OBJECT", vm=address_space, offset = (
                    offset + pool_obj.BlockSize * self.pool_align -
                    self.get_rounded_size("_FILE_OBJECT"))
                )

            ## The _OBJECT_HEADER is immediately below the _FILE_OBJECT
            object_obj = self.profile.Object(
                "_OBJECT_HEADER", vm=address_space, offset=(
                    file_obj.obj_offset - self.profile.get_obj_offset(
                        '_OBJECT_HEADER', 'Body'))
                )

            if object_obj.get_object_type(self.kernel_address_space) != "File":
                continue

            ## If the string is not reachable we skip it
            if not file_obj.FileName.v(vm=self.kernel_address_space):
                continue

            yield (object_obj, file_obj)

    def render(self, outfd):
        """Print the output in a table."""
        outfd.write("{0:10} {1:4} {2:4} {3:6} {4}\n".format(
                     'Offset(P)', '#Ptr', '#Hnd', 'Access', 'Name'))

        for object_obj, file_obj in self.generate_hits():
            outfd.write(u"{0:#010x} {1:4} {2:4} {3:6} {4}\n".format(
                    file_obj.obj_offset, object_obj.PointerCount,
                    object_obj.HandleCount, file_obj.AccessString, 
                    file_obj.FileName.v(vm=self.kernel_address_space)))


class PoolScanDriver(PoolScanFile):
    """ Scanner for _DRIVER_OBJECT """
    ## No preamble
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
        address_space = self.physical_address_space
        for offset in PoolScanDriver(profile=self.profile).scan(address_space):
            pool_obj = self.profile.Object("_POOL_HEADER", vm=address_space,
                                           offset=offset)

            extension_obj = self.profile.Object(
                "_DRIVER_EXTENSION", vm = address_space,
                offset = (offset + pool_obj.BlockSize * self.pool_align -
                          self.get_rounded_size("_DRIVER_EXTENSION")))

            ## The _DRIVER_OBJECT is immediately below the _DRIVER_EXTENSION
            driver_obj = self.profile.Object(
                "_DRIVER_OBJECT", vm=address_space, offset=(
                    extension_obj.obj_offset -
                    self.get_rounded_size("_DRIVER_OBJECT"))
                )

            ## The _OBJECT_HEADER is immediately below the _DRIVER_OBJECT
            object_obj = self.profile.Object(
                "_OBJECT_HEADER", vm=address_space,
                offset = (driver_obj.obj_offset -
                          self.profile.get_obj_offset('_OBJECT_HEADER', 'Body')),
                )

            if object_obj.get_object_type(self.kernel_address_space) != "Driver":
                continue

            object_name = object_obj.NameInfo.Name.v(vm=self.kernel_address_space)

            yield (object_obj, driver_obj, extension_obj, object_name)


    def render(self, outfd):
        """Renders the text-based output"""
        outfd.write("{0:10} {1:4} {2:4} {3:10} {4:>6} {5:20} {6}\n".format(
                     'Offset(P)', '#Ptr', '#Hnd',
                     'Start', 'Size', 'Service key', 'Name'))

        for object_obj, driver_obj, extension_obj, object_name in self.generate_hits():
            outfd.write(u"0x{0:08x} {1:4} {2:4} 0x{3:08x} {4:6} {5:20} {6:12} {7}\n".format(
                         driver_obj.obj_offset, object_obj.PointerCount,
                         object_obj.HandleCount,
                         driver_obj.DriverStart, driver_obj.DriverSize,
                         extension_obj.ServiceKeyName.v(vm=self.kernel_address_space),
                         object_name,
                         driver_obj.DriverName.v(vm=self.kernel_address_space)))


class PoolScanSymlink(PoolScanFile):
    """ Scanner for symbolic link objects """
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
        address_space = self.physical_address_space
        for offset in PoolScanSymlink(profile=self.profile).scan(address_space):
            pool_obj = self.profile.Object("_POOL_HEADER", vm=address_space,
                                           offset=offset)

            link_obj = self.profile.Object("_OBJECT_SYMBOLIC_LINK", vm = address_space,
                                           offset = (
                    offset + pool_obj.BlockSize * self.pool_align -
                    self.get_rounded_size("_OBJECT_SYMBOLIC_LINK")))

            ## The _OBJECT_HEADER is immediately below the _OBJECT_SYMBOLIC_LINK
            object_obj = self.profile.Object(
                "_OBJECT_HEADER", vm=address_space,
                offset = (link_obj.obj_offset -
                          self.profile.get_obj_offset('_OBJECT_HEADER', 'Body'))
                )

            if object_obj.get_object_type(self.kernel_address_space) != "SymbolicLink":
                continue

            object_name = object_obj.NameInfo.Name.v(vm=self.kernel_address_space)

            yield object_obj, link_obj, object_name

    def render(self, outfd):
        """ Renders text-based output """

        outfd.write("{0:10} {1:4} {2:4} {3:24} {4:<20} {5}\n".format(
            'Offset(P)', '#Ptr', '#Hnd', 'CreateTime', 'From', 'To'))

        for o, link, name in self.generate_hits():
            outfd.write(u"{0:#010x} {1:4} {2:4} {3:<24} {4:<20} {5}\n".format(
                        link.obj_offset, o.PointerCount,
                        o.HandleCount, link.CreationTime or '',
                        name, link.LinkTarget.v(vm=self.kernel_address_space)))


class PoolScanMutant(PoolScanDriver):
    """ Scanner for Mutants _KMUTANT """
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
        address_space = self.physical_address_space
        for offset in PoolScanMutant(profile=self.profile).scan(address_space):
            pool_obj = self.profile.Object("_POOL_HEADER", vm=address_space,
                                           offset=offset)

            mutant = self.profile.Object(
                "_KMUTANT", vm=address_space,
                offset = (offset + pool_obj.BlockSize * self.pool_align -
                          self.get_rounded_size("_KMUTANT")))

            ## The _OBJECT_HEADER is immediately below the _KMUTANT
            object_obj = self.profile.Object(
                "_OBJECT_HEADER", vm=address_space,
                offset = (mutant.obj_offset -
                          self.profile.get_obj_offset('_OBJECT_HEADER', 'Body'))
                )

            if object_obj.get_object_type(self.kernel_address_space) != "Mutant":
                continue

            ## Skip unallocated objects
            ##if object_obj.Type == 0xbad0b0b0:
            ##   continue
            object_name = object_obj.NameInfo.Name.v(vm=self.kernel_address_space)

            if self.silent:
                if object_name.Length == 0:
                    continue

            yield (object_obj, mutant, object_name)


    def render(self, outfd):
        """Renders the output"""
        outfd.write("{0:10} {1:4} {2:4} {3:6} {4:10} {5:10} {6}\n".format(
                     'Offset(P)', '#Ptr', '#Hnd', 'Signal',
                     'Thread', 'CID', 'Name'))

        for object_obj, mutant, object_name in self.generate_hits():
            if mutant.OwnerThread > 0x80000000:
                thread = self.profile.Object("_ETHREAD", vm=self.kernel_address_space,
                                             offset=mutant.OwnerThread)
                CID = "{0}:{1}".format(thread.Cid.UniqueProcess, thread.Cid.UniqueThread)
            else:
                CID = ""

            outfd.write(u"0x{0:08x} {1:4} {2:4} {3:6} 0x{4:08x} {5:10} {6}\n".format(
                         mutant.obj_offset, object_obj.PointerCount,
                         object_obj.HandleCount, mutant.Header.SignalState,
                         mutant.OwnerThread, CID,
                         object_obj.NameInfo.Name.v(vm=self.kernel_address_space))
                        )

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


class PoolScanProcess(scan.PoolScanner):
    """PoolScanner for File objects"""
    ## We are not using a preamble for this plugin since we are walking back
    preamble = []

    def object_offset(self, found):
        """ This returns the offset of the object contained within
        this pool allocation.
        """
        ## The offset of the object is determined by subtracting the offset
        ## of the PoolTag member to get the start of Pool Object and then
        ## adding the size of the preamble data structures. This done
        ## because PoolScanners search for the PoolTag. 

        pool_base = found - self.profile.get_obj_offset(
            '_POOL_HEADER', 'PoolTag')

        pool_obj = self.profile.Object("_POOL_HEADER", vm = self.address_space,
                                       offset = pool_base)

        ## We work out the _EPROCESS from the end of the
        ## allocation (bottom up).
        pool_align = self.profile.constants['PoolAlignment']

        object_base = (pool_base + pool_obj.BlockSize * pool_align -
                       self.profile.get_obj_size("_EPROCESS"))

        return object_base

    checks = [ ('PoolTagCheck', dict(tag = '\x50\x72\x6F\xe3')),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x280)),
               ('CheckPoolType', dict(paged = True, non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ('CheckProcess', {}),
               ]


class PSScan(common.PoolScannerPlugin):
    """ Scan Physical memory for _EPROCESS pool allocations
    """
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

    def __init__(self, **kwargs):
        """Scan Physical memory for _EPROCESS pool allocations."""
        super(PSScan, self).__init__(**kwargs)

    # Can't be cached until self.kernel_address_space is moved entirely
    # within calculate
    def calculate(self):
        """Generate possible hits."""
        ## Just grab the AS and scan it using our scanner
        address_space = self.physical_address_space
        for offset in PoolScanProcess(profile=self.profile).scan(address_space):
            eprocess = self.profile.Object('_EPROCESS', vm=address_space,
                                           offset = offset)
            yield eprocess

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


    def render(self, outfd):
        """Render results in a table."""
        outfd.write(" Offset(P) Offset(V)  Name             PID    PPID   PDB        Time created             Time exited             \n" + \
                    "---------- --------- ---------------- ------ ------ ---------- ------------------------ ------------------------ \n")

        for eprocess in self.calculate():
            # Try to guess the virtual address of the eprocess
            eprocess_virtual_address = self.guess_eprocess_virtual_address(eprocess)

            outfd.write(u"0x{0:08x} 0x{1:08x} {2:16} {3:6} {4:6} 0x{5:08x} {6:24} {7:24}\n".format(
                eprocess.obj_offset,
                eprocess_virtual_address,
                eprocess.ImageFileName,
                eprocess.UniqueProcessId,
                eprocess.InheritedFromUniqueProcessId,
                eprocess.Pcb.DirectoryTableBase,
                eprocess.CreateTime or '',
                eprocess.ExitTime or ''))

    def render_dot(self, outfd):
        """Create a dot file for visualization."""
        objects = set()
        links = set()

        for eprocess in self.calculate():
            label = "{0} | {1} |".format(eprocess.UniqueProcessId,
                                         eprocess.ImageFileName)
            if eprocess.ExitTime:
                label += "exited\\n{0}".format(eprocess.ExitTime)
                options = ' style = "filled" fillcolor = "lightgray" '
            else:
                label += "running"
                options = ''

            objects.add('pid{0} [label="{1}" shape="record" {2}];\n'.format(eprocess.UniqueProcessId,
                                                                            label, options))
            links.add("pid{0} -> pid{1} [];\n".format(eprocess.InheritedFromUniqueProcessId,
                                                      eprocess.UniqueProcessId))

        ## Now write the dot file
        outfd.write("digraph processtree { \ngraph [rankdir = \"TB\"];\n")
        for link in links:
            outfd.write(link)

        for item in objects:
            outfd.write(item)
        outfd.write("}")
