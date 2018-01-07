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

https://lists.debian.org/lsb-spec/1999/12/msg00017.html
"""

from rekall import obj
from rekall.plugins.overlays import basic

from rekall_lib import utils


# These come out of the kernel symbols but are put here so we can use them
# outside the linux implementation.
elf_vtypes = {
    "elf64_hdr": [64, {
        'e_ident': [0, ['array', 16, ['uint8_t']]],
        'e_type': [16, ['uint16_t']],
        'e_machine': [18, ['uint16_t']],
        'e_version': [20, ['uint32_t']],
        'e_entry': [24, ['uint64_t']],
        'e_phoff': [32, ['uint64_t']],
        'e_shoff': [40, ['uint64_t']],
        'e_flags': [48, ['uint32_t']],
        'e_ehsize': [52, ['uint16_t']],
        'e_phentsize': [54, ['uint16_t']],
        'e_phnum': [56, ['uint16_t']],
        'e_shentsize': [58, ['uint16_t']],
        'e_shnum': [60, ['uint16_t']],
        'e_shstrndx': [62, ['uint16_t']],
        }],

    'elf64_phdr': [56, {
        'p_type': [0, [u'uint32_t']],
        'p_flags': [4, [u'uint32_t']],
        'p_offset': [8, [u'uint64_t']],
        'p_vaddr': [16, [u'uint64_t']],
        'p_paddr': [24, [u'uint64_t']],
        'p_filesz': [32, [u'uint64_t']],
        'p_memsz': [40, [u'uint64_t']],
        'p_align': [48, [u'uint64_t']],
        }],

    'elf64_shdr': [64, {
        'sh_name': [0, [u'uint32_t']],
        'sh_type': [4, [u'uint32_t']],
        'sh_flags': [8, [u'uint64_t']],
        'sh_addr': [16, [u'uint64_t']],
        'sh_offset': [24, [u'uint64_t']],
        'sh_size': [32, [u'uint64_t']],
        'sh_link': [40, [u'uint32_t']],
        'sh_info': [44, [u'uint32_t']],
        'sh_addralign': [48, [u'uint64_t']],
        'sh_entsize': [56, [u'uint64_t']],
        }],

    'elf64_note': [12, {
        'n_namesz': [0, ['uint16_t']],
        'n_descsz': [4, ['uint16_t']],
        'n_type': [8, ['uint32_t']],
        }],

    'elf64_verneed': [16, {
        'vn_version': [0, ['uint16_t']],
        'vn_cnt': [2, ['uint16_t']],
        'vn_file': [4, ['uint32_t']],
        'vn_aux': [8, ['uint32_t']],
        'vn_next': [12, ["uint32_t"]],
    }],

    'elf64_vernaux': [16, {
        'vna_hash': [0, ['uint32_t']],
        'vna_flags': [4, ['uint16_t']],
        'vna_other': [6, ['uint16_t']],
        'vna_name': [8, ['uint32_t']],
        'vna_next': [12, ['uint32_t']],
    }],

    'elf64_sym': [24, {
        "st_name": [0, ['uint32_t']],
        "st_info": [4, ['uint8_t']],
        "st_other": [5, ['uint8_t']],
        "st_shndx": [6, ['uint16_t']],
        "st_value": [8, ['uint64_t']],
        "st_size": [16, ['uint64_t']],
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
            'target': 'uint8_t'}]],

        'segments': lambda x: x.cast("Array",
            offset=x.e_phoff,
            target='elf64_phdr',
            target_size=x.e_phentsize,
            count=x.e_phnum),

        'sections': lambda x: x.cast("Array",
            offset=x.e_shoff,
            target='elf64_shdr',
            target_size=x.e_shentsize,
            count=x.e_shnum),
        }],
    "elf64_shdr": [lambda x: x.sh_size, {
        "name": lambda x: x.obj_context["shstrtab"].at_offset(x.sh_name),
        'sh_type': [None, ['Enumeration', dict(
            choices=utils.Invert(utils.MaskMapFromDefines("""
#define SHT_NULL          0             /* Section header table entry unused */
#define SHT_PROGBITS      1             /* Program data */
#define SHT_SYMTAB        2             /* Symbol table */
#define SHT_STRTAB        3             /* String table */
#define SHT_RELA          4             /* Relocation entries with addends */
#define SHT_HASH          5             /* Symbol hash table */
#define SHT_DYNAMIC       6             /* Dynamic linking information */
#define SHT_NOTE          7             /* Notes */
#define SHT_NOBITS        8             /* Program space with no data (bss) */
#define SHT_REL           9             /* Relocation entries, no addends */
#define SHT_SHLIB         10            /* Reserved */
#define SHT_DYNSYM        11            /* Dynamic linker symbol table */
#define SHT_INIT_ARRAY    14            /* Array of constructors */
#define SHT_FINI_ARRAY    15            /* Array of destructors */
#define SHT_PREINIT_ARRAY 16            /* Array of pre-constructors */
#define SHT_GROUP         17            /* Section group */
#define SHT_SYMTAB_SHNDX  18            /* Extended section indeces */
#define SHT_NUM           19            /* Number of defined types.  */
#define SHT_LOOS          0x60000000    /* Start OS-specific.  */
#define SHT_GNU_ATTRIBUTES 0x6ffffff5   /* Object attributes.  */
#define SHT_GNU_HASH      0x6ffffff6    /* GNU-style hash table.  */
#define SHT_GNU_LIBLIST   0x6ffffff7    /* Prelink library list */
#define SHT_CHECKSUM      0x6ffffff8    /* Checksum for DSO content.  */
#define SHT_LOSUNW        0x6ffffffa    /* Sun-specific low bound.  */
#define SHT_SUNW_move     0x6ffffffa
#define SHT_SUNW_COMDAT   0x6ffffffb
#define SHT_SUNW_syminfo  0x6ffffffc
#define SHT_GNU_verdef    0x6ffffffd    /* Version definition section.  */
#define SHT_GNU_verneed   0x6ffffffe    /* Version needs section.  */
#define SHT_GNU_versym    0x6fffffff    /* Version symbol table.  */
            """)),
            target="unsigned int"
        )]],
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

    "elf64_verneed": [lambda x: x.vn_next, {
        # Retrieve the filename from this section's linked section.
        'file': lambda x: x.obj_context[
            "section"].get_linked_section().get_section().at_offset(x.vn_file),

        # The Auxiliary record.
        "aux": lambda x: x.cast(
            "LinkedListArray",
            count=x.vn_cnt,
            next_member=lambda x, item: item.obj_offset + item.vna_next,
            target="elf64_vernaux",
            offset=x.obj_offset + x.m("vn_aux"))
        }],

    "elf64_vernaux": [None, {
        'name': lambda x: x.obj_context[
            "section"].get_linked_section().get_section().at_offset(x.vna_name),
    }],
    "elf64_sym": [None, {
        'name': lambda x: x.obj_context[
            "section"].get_linked_section().get_section().at_offset(x.st_name),
    }],
}


class elf64_hdr(obj.Struct):
    def __init__(self, *args, **kwargs):
        super(elf64_hdr, self).__init__(*args, **kwargs)

        # Add a reference to ourselves to the context so our children
        # can find us.
        self.obj_context["hdr"] = self

        # Find the section header strings table.
        self.obj_context["shstrtab"] = self.sections[
            self.e_shstrndx].get_section()

    def section_by_name(self, name):
        for section in self.sections:
            if section.name == name:
                return section

        return obj.NoneObject("Not found")


class IndexedListArray(obj.ListArray):
    def at_offset(self, offset):
        return self.cast("String", offset=self.obj_offset + offset)


class elf64_shdr(obj.Struct):
    def get_section(self):
        context = dict(section=self, **self.obj_context)
        if self.sh_type == "SHT_STRTAB":
            return self.cast("IndexedListArray",
                             offset=self.sh_offset,
                             maximum_size=self.sh_size,
                             context=context,
                             target="String")

        elif self.sh_type == "SHT_GNU_verneed":
            return self.cast("LinkedListArray",
                             offset=self.sh_offset,
                             next_member=lambda x, item: item.obj_offset + item.vn_next,
                             maximum_size=self.sh_size,
                             context=context,
                             target="elf64_verneed")

        elif self.sh_type == "SHT_NOTE":
            return self.cast("elf64_note", offset=sh_offset)

        elif self.sh_type == "SHT_GNU_versym":
            return self.cast("Array",
                             offset=self.sh_offset,
                             count=self.sh_size / 2,
                             context=context,
                             target="short unsigned int")

        elif self.sh_type == "SHT_DYNSYM":
            return self.cast("Array",
                             offset=self.sh_offset,
                             size=self.sh_size,
                             context=context,
                             target="elf64_sym")

        return self.cast("String", offset=self.sh_offset,
                         length=self.sh_size,
                         context=context,
                         term=None)

    def get_linked_section(self):
        """Get our linked section."""

        hdr = self.obj_context["hdr"]
        return hdr.sections[self.sh_link]


class ELFFileImplementation(obj.ProfileModification):
    """An implementation of a parser for ELF files."""

    @classmethod
    def Modify(cls, profile):
        profile.add_classes(elf64_shdr=elf64_shdr,
                            elf64_hdr=elf64_hdr,
                            IndexedListArray=IndexedListArray)
        profile.add_types(elf_vtypes)
        profile.add_overlay(elf_overlays)



class ELFProfile(basic.ProfileLP64, basic.BasicClasses):
    """A profile for ELF files."""

    def __init__(self, **kwargs):
        super(ELFProfile, self).__init__(**kwargs)
        ELFFileImplementation.Modify(self)
