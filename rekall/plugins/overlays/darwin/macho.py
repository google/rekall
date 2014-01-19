#!/usr/bin/python

# Rekall Memory Forensics
# Copyright (C) 2012 Michael Cohen <scudette@gmail.com>
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

"""This profile is for the MACH-O file format.

For now this is not a complete implementation - just enough to parse the MACHO
core dump style images.

References:
https://developer.apple.com/library/mac/#documentation/developertools/conceptual/MachORuntime/Reference/reference.html

http://www.opensource.apple.com/source/xnu/xnu-1456.1.26/EXTERNAL_HEADERS/mach-o/loader.h

http://svn.red-bean.com/bob/macholib/trunk/macholib/mach_o.py
"""

__author__ = "Michael Cohen <scudette@gmail.com>"

from rekall import obj
from rekall.plugins.overlays import basic


macho_vtypes = {
 'mach_header_64': [ 0x20, {
    'magic': [0x0, ['unsigned int']],
    'cputype': [0x4, ['Enumeration', dict(
                        choices={
                            1:      'VAX',
                            6:      'MC680x0',
                            7:      'i386',
                            8:      'MIPS',
                            10:     'MC98000',
                            11:     'HPPA',
                            12:     'ARM',
                            13:     'MC88000',
                            14:     'SPARC',
                            15:     'i860',
                            16:     'Alpha',
                            18:     'PowerPC',
                            (0x01000000 + 7): 'X86_64',
                            (0x01000000 + 18): 'PowerPC_64',
                            },
                        target="unsigned int",
                        )]],
    'cpusubtype': [0x8, ['int']],
    'filetype': [0xc, ['Enumeration', dict(
                        choices={
                            0x1: 'MH_OBJECT',  # relocatable object file
                            0x2: "MH_EXECUTE", # demand paged executable file
                            0x3: "MH_FVMLIB",  # fixed VM shared library file
                            0x4: 'MH_CORE',    # core file
                            0x5: 'MH_PRELOAD', # preloaded executable file
                            0x6: 'MH_DYLIB',   # dynamicly bound shared library file
                            0x7: 'MH_DYLINKER',# dynamic link editor
                            0x8: 'MH_BUNDLE',  # dynamicly bound bundle file
                            },
                        target="unsigned int",
                        )]],
    'ncmds': [0x10, ['unsigned int']],
    'sizeofcmds': [0x14, ['unsigned int']],
    'flags': [0x18, ['Flags', dict(maskmap={
                        'MH_NOUNDEFS':     0x1,
                        'MH_INCRLINK':     0x2,
                        'MH_DYLDLINK':     0x4,
                        'MH_BINDATLOAD':   0x8,
                        'MH_PREBOUND':     0x10,
                        })]],
    'reserved': [0x1c, ['unsigned int']],
    'segments': [0x20, ['Array', dict(
                        target="segment_command_64",
                        count=lambda x: x.ncmds)]],
}],

'segment_command_64': [ 0x48, {
    'cmd': [0x0, ['Enumeration', dict(
                        choices={
                            0x1: 'LC_SEGMENT',
                            0x2: 'LC_SYMTAB',
                            0x3: 'LC_SYMSEG',
                            0x4: 'LC_THREAD',
                            0x5: 'LC_UNIXTHREAD',
                            0x6: 'LC_LOADFVMLIB',
                            0x7: 'LC_IDFVMLIB',
                            0x8: 'LC_IDENT',
                            0x9: 'LC_FVMFILE',
                            0xa: 'LC_PREPAGE',
                            0xb: 'LC_DYSYMTAB',
                            0xc: 'LC_LOAD_DYLIB',
                            0xd: 'LC_ID_DYLIB',
                            0xe: 'LC_LOAD_DYLINKER',
                            0xf: 'LC_ID_DYLINKER',
                            0x10: 'LC_PREBOUND_DYLIB',
                            0x11: 'LC_ROUTINES',
                            0x12: 'LC_SUB_FRAMEWORK',
                            0x13: 'LC_SUB_UMBRELLA',
                            0x14: 'LC_SUB_CLIENT',
                            0x15: 'LC_SUB_LIBRARY',
                            0x16: 'LC_TWOLEVEL_HINTS',
                            0x17: 'LC_PREBIND_CKSUM',
                            0x80000000 + 0x18: 'LC_LOAD_WEAK_DYLIB',
                            0x19: 'LC_SEGMENT_64',
                            0x1a: 'LC_ROUTINES_64',
                            0x1b: 'LC_UUID',
                            0x80000000 + 0x1c: 'LC_RPATH',
                            0x1d: 'LC_CODE_SIGNATURE',
                            0x1e: 'LC_SEGMENT_SPLIT_INFO',
                            0x80000000 + 0x1f: 'LC_REEXPORT_DYLIB',
                            0x20: 'LC_LAZY_LOAD_DYLIB',
                            0x21: 'LC_ENCRYPTION_INFO',
                            0x22: 'LC_DYLD_INFO',
                            0x80000000 + 0x22: 'LC_DYLD_INFO_ONLY',
                            },
                        target="unsigned int")]],
    'cmdsize': [0x4, ['unsigned int']],
    'segname': [0x8, ['String', dict(length=16)]],
    'vmaddr': [0x18, ['unsigned long long']],
    'vmsize': [0x20, ['unsigned long long']],
    'fileoff': [0x28, ['unsigned long long']],
    'filesize': [0x30, ['unsigned long long']],
    'maxprot': [0x38, ['int']],
    'initprot': [0x3c, ['int']],
    'nsects': [0x40, ['unsigned int']],
    'flags': [0x44, ['unsigned int']],
}],
}


class MACHOFileImplementation(obj.ProfileModification):
    """An implementation of a parser for MAC-O files."""

    @classmethod
    def Modify(cls, profile):
        profile.add_types(macho_vtypes)


class MACHO64Profile(basic.ProfileLP64, basic.BasicClasses):
    """A profile for MAC-O files."""

    def __init__(self, **kwargs):
        super(MACHO64Profile, self).__init__(**kwargs)

        MACHOFileImplementation.Modify(self)

