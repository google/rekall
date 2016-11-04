# Rekall Memory Forensics
#
# Copyright 2016 Google Inc. All Rights Reserved.
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


"""This profile is for the Mach-O file format.

References:

https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html
http://www.opensource.apple.com/source/xnu/xnu-1456.1.26/EXTERNAL_HEADERS/Mach-O/loader.h
https://github.com/llvm-mirror/llvm/blob/release_34/include/llvm/Support/MachO.h
https://github.com/opensource-apple/xnu/blob/10.9/EXTERNAL_HEADERS/Mach-O/loader.h
"""

__author__ = ("Michael Cohen <scudette@gmail.com>",
              "Adam Sindelar <adamsh@google.com")

from rekall.plugins.overlays import basic


macho_vtypes = {
    'mach_header_64': [0x20, {
        'cputype': [None, ['Enumeration', dict(
            choices={
                1: 'VAX',
                6: 'MC680x0',
                7: 'i386',
                8: 'MIPS',
                10: 'MC98000',
                11: 'HPPA',
                12: 'ARM',
                13: 'MC88000',
                14: 'SPARC',
                15: 'i860',
                16: 'Alpha',
                18: 'PowerPC',
                (0x01000000 | 7): 'X86_64',
                (0x01000000 | 18): 'PowerPC_64',
            },
            target="unsigned int",
        )]],
        'filetype': [None, ['Enumeration', dict(
            choices={
                0x1: 'MH_OBJECT',  # relocatable object file
                0x2: "MH_EXECUTE",  # demand paged executable file
                0x3: "MH_FVMLIB",  # fixed VM shared library file
                0x4: 'MH_CORE',    # core file
                0x5: 'MH_PRELOAD',  # preloaded executable file
                0x6: 'MH_DYLIB',   # dynamicly bound shared library file
                0x7: 'MH_DYLINKER',  # dynamic link editor
                0x8: 'MH_BUNDLE',  # dynamicly bound bundle file
            },
            target="unsigned int",
        )]],
        'flags': [None, ['Flags', dict(maskmap={
            'MH_NOUNDEFS': 0x1,
            'MH_INCRLINK': 0x2,
            'MH_DYLDLINK': 0x4,
            'MH_BINDATLOAD': 0x8,
            'MH_PREBOUND': 0x10,
        })]],
        'segments': [lambda x: x.obj_size, ['Array', dict(
            target="segment_command_64",
            count=lambda x: x.ncmds)]],
    }],

    'segment_command_64': [0x48, {
        'cmd': [None, ['Enumeration', dict(
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
                0x80000000 | 0x18: 'LC_LOAD_WEAK_DYLIB',
                0x19: 'LC_SEGMENT_64',
                0x1a: 'LC_ROUTINES_64',
                0x1b: 'LC_UUID',
                0x80000000 | 0x1c: 'LC_RPATH',
                0x1d: 'LC_CODE_SIGNATURE',
                0x1e: 'LC_SEGMENT_SPLIT_INFO',
                0x80000000 | 0x1f: 'LC_REEXPORT_DYLIB',
                0x20: 'LC_LAZY_LOAD_DYLIB',
                0x21: 'LC_ENCRYPTION_INFO',
                0x22: 'LC_DYLD_INFO',
                0x80000000 | 0x22: 'LC_DYLD_INFO_ONLY',
            },
            target="unsigned int")]],
        'segname': [None, ['String', dict(length=16)]],
    }],
}


class MachoProfile(basic.ProfileLP64, basic.BasicClasses):
    """A profile for Mach-O files.

    This profile contains types for both 32 and 64bit Mach-O files, although
    only the latter is actually in use by anyone (including Apple).
    """

    @classmethod
    def Initialize(cls, profile):
        super(MachoProfile, cls).Initialize(profile)
        profile.add_overlay(macho_vtypes)
