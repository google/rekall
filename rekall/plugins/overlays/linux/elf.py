# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@gmail.com>
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

"""This file implements elf file parsing.

References:
http://downloads.openwatcom.org/ftp/devel/docs/elf-64-gen.pdf
/usr/include/linux/elf.h
"""

from rekall import obj
from rekall.plugins.overlays import basic


# These come out of the kernel symbols but are put here so we can use them
# outside the linux implementation.
elf_vtypes = {
    "elf64_hdr": [64, {
        'e_ident': [0, ['array', 16, ['unsigned char']]],
        'e_type': [16, ['short unsigned int']],
        'e_machine': [18, ['short unsigned int']],
        'e_version': [20, ['unsigned int']],
        'e_entry': [24, ['long long unsigned int']],
        'e_phoff': [32, ['long long unsigned int']],
        'e_shoff': [40, ['long long unsigned int']],
        'e_flags': [48, ['unsigned int']],
        'e_ehsize': [52, ['short unsigned int']],
        'e_phentsize': [54, ['short unsigned int']],
        'e_phnum': [56, ['short unsigned int']],
        'e_shentsize': [58, ['short unsigned int']],
        'e_shnum': [60, ['short unsigned int']],
        'e_shstrndx': [62, ['short unsigned int']],
        }],

    'elf64_phdr': [56, {
        'p_type': [0, [u'unsigned int']],
        'p_flags': [4, [u'unsigned int']],
        'p_offset': [8, [u'long long unsigned int']],
        'p_vaddr': [16, [u'long long unsigned int']],
        'p_paddr': [24, [u'long long unsigned int']],
        'p_filesz': [32, [u'long long unsigned int']],
        'p_memsz': [40, [u'long long unsigned int']],
        'p_align': [48, [u'long long unsigned int']],
        }],

    'elf64_shdr': [64, {
        'sh_name': [0, [u'unsigned int']],
        'sh_type': [4, [u'unsigned int']],
        'sh_flags': [8, [u'long long unsigned int']],
        'sh_addr': [16, [u'long long unsigned int']],
        'sh_offset': [24, [u'long long unsigned int']],
        'sh_size': [32, [u'long long unsigned int']],
        'sh_link': [40, [u'unsigned int']],
        'sh_info': [44, [u'unsigned int']],
        'sh_addralign': [48, [u'long long unsigned int']],
        'sh_entsize': [56, [u'long long unsigned int']],
        }],
    'elf64_note': [12, {
        'n_namesz': [0, ['unsigned int']],
        'n_descsz': [4, ['unsigned int']],
        'n_type': [8, ['unsigned int']],
        }],
    }


# Unfortunately the kernel uses #defines for many of these rather than enums, so
# we need to hand overlay them :-(.
elf_overlays = {
    "elf64_hdr": [None, {
        'e_ident': [None, ['Signature', dict(
            value="\x7fELF\x02\x01\x01"
            )]],
        'e_type': [None, ['Enumeration', {
            "choices": {
                0: 'ET_NONE',
                1: 'ET_REL',
                2:'ET_EXEC',
                3:'ET_DYN',
                4:'ET_CORE',
                0xff00:'ET_LOPROC',
                0xffff:'ET_HIPROC'},
            'target': 'unsigned char'}]],
        'e_phoff': [None, ['Pointer', dict(
            target='Array',
            target_args=dict(
                target='elf64_phdr',
                target_size=lambda x: x.e_phentsize,
                count=lambda x: x.e_phnum))]],
        'e_shoff': [None, ['Pointer', dict(target='elf64_shdr')]],
        }],

    "elf64_phdr": [None, {
        'p_type': [None, ['Enumeration', {
            "choices": {
                0: 'PT_NULL',
                1: 'PT_LOAD',
                2: 'PT_DYNAMIC',
                3: 'PT_INTERP',
                4: 'PT_NOTE',
                5: 'PT_SHLIB',
                6: 'PT_PHDR',
                7: 'PT_TLS',
                0x60000000 : 'PT_LOOS',
                0x6fffffff :'PT_HIOS',
                0x70000000 :'PT_LOPROC',
                0x7fffffff :'PT_HIPROC',
                0x6474e550 :'PT_GNU_EH_FRAME',
                },
            "target": "unsigned int"}]],
        "p_flags": [None, ['Flags', dict(
            maskmap=dict(
                PF_R=0x4,
                PF_W=0x2,
                PF_X=0x1,
                ),
            target='unsigned long')]],
        "p_offset": [None, ["Pointer", dict(target="Void")]],
        }],
    "elf64_note": [None, {
        'name': [lambda x: 12 + x.obj_offset,
                 ['String', dict(length=lambda x: x.n_namesz)]],

        'desc': [lambda x: 12 + x.n_namesz + x.obj_offset,
                 ['String', dict(length=lambda x: x.n_descsz)]],
        }],
    }


class ELFFileImplementation(obj.ProfileModification):
    """An implementation of a parser for ELF files."""

    @classmethod
    def Modify(cls, profile):
        profile.add_types(elf_vtypes)
        profile.add_overlay(elf_overlays)



class ELFProfile(basic.ProfileLP64, basic.BasicClasses):
    """A profile for ELF files."""

    def __init__(self, **kwargs):
        super(ELFProfile, self).__init__(**kwargs)
        ELFFileImplementation.Modify(self)
