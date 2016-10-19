# Rekall Memory Forensics
# Copyright (c) 2012 Michael Cohen <scudette@gmail.com>
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

"""A parser for dwarf modules which generates vtypes."""
import logging

from elftools import construct
from elftools.dwarf import callframe
from elftools.dwarf import compileunit
from elftools.dwarf import descriptions
from elftools.dwarf import dwarfinfo
from elftools.dwarf import enums
from elftools.dwarf import structs as dwarf_structs
from elftools.elf import elffile
from elftools.common.py3compat import itervalues
from elftools.dwarf.descriptions import describe_attr_value

from rekall import plugin
from rekall import utils



def PatchPyElftools():
    """Upgrade pyelftools to support DWARF 4.

    Hopefully these fixes will be pushed upstream soon.
    """
    # Check if pyelftools already supports dwarf 4.
    if "DW_FORM_sec_offset" not in enums.ENUM_DW_FORM:
        enums.ENUM_DW_FORM.update(dict(
            DW_FORM_sec_offset=0x17,
            DW_FORM_exprloc=0x18,
            DW_FORM_flag_present=0x19,
            DW_FORM_ref_sig8=0x20,
            ))

        class Implicit(object):
            def parse_stream(self, _):
                """This form consumes no data."""
                return True

        class DWARFStructs(dwarf_structs.DWARFStructs):
            def _create_dw_form(self):
                super(DWARFStructs, self)._create_dw_form()

                self.Dwarf_dw_form.update(dict(
                    DW_FORM_sec_offset=self.Dwarf_offset(''),
                    DW_FORM_exprloc=construct.PrefixedArray(
                        subcon=self.Dwarf_uint8('elem'),
                        length_field=self.Dwarf_uleb128('')),
                    DW_FORM_flag_present=Implicit(),
                    DW_FORM_ref_sig8=self.Dwarf_uint64(''),
                    ))

        dwarf_structs.DWARFStructs = DWARFStructs
        dwarfinfo.DWARFStructs = DWARFStructs
        callframe.DWARFStructs = DWARFStructs

        class DWARFInfo(dwarfinfo.DWARFInfo):
            def _is_supported_version(self, version):
                return 2 <= version <= 4

        dwarfinfo.DWARFInfo = DWARFInfo
        elffile.DWARFInfo = DWARFInfo

        class CompileUnit(compileunit.CompileUnit):
            def iter_DIEs(self):
                try:
                    self._parse_DIEs()
                except IndexError:
                    pass

                return iter(self._dielist)

        compileunit.CompileUnit = CompileUnit
        dwarfinfo.CompileUnit = CompileUnit


# Ensure Pyelftools is patched to support DWARF 4.
PatchPyElftools()


class DIETag(object):
    # The parent container for this DIE.
    parent = None

    def __init__(self, die, types, parents):
        self.attributes = {}
        self.die = die
        self.types = types
        if parents:
            self.parent = parents[-1]

        for attr in die.attributes.values():
            self.attributes[attr.name] = attr

    @utils.safe_property
    def name(self):
        # This node is directly named.
        if "DW_AT_name" in self.attributes:
            return self.attributes["DW_AT_name"].value

        if "DW_AT_sibling" in self.attributes:
            sibling = self.types.get(self.attributes["DW_AT_sibling"].value +
                                     self.die.cu.cu_offset)
            if sibling and sibling.die.tag == "DW_TAG_typedef":
                return sibling.name

        return "__unnamed_%s" % self.die.offset

    @utils.safe_property
    def type_id(self):
        if "DW_AT_type" in self.attributes:
            return self.attributes["DW_AT_type"].value + self.die.cu.cu_offset

    def VType(self):
        """Returns a vtype representation of this DIE."""
        return self.name

    def Definition(self, vtype):
        """This DW element is given an opportunity to generate a vtype."""

class DW_TAG_typedef(DIETag):

    def VType(self):
        """For typedefs we just substitute our base type."""
        if self.type_id is None:
            return self.name

        return self.types[self.type_id].VType()


class DW_TAG_volatile_type(DW_TAG_typedef):
    pass


class DW_TAG_base_type(DIETag):
    """A base type."""


class DW_TAG_structure_type(DIETag):
    """A struct definition."""
    def __init__(self, die, types, parents):
        super(DW_TAG_structure_type, self).__init__(die, types, parents)
        # All the members of this struct.
        self.members = []

    @utils.safe_property
    def name(self):
        if "DW_AT_name" in self.attributes:
            return self.attributes["DW_AT_name"].value
        else:
            return "__unnamed_%s" % self.die.offset

    @utils.safe_property
    def size(self):
        try:
            return self.attributes['DW_AT_byte_size'].value
        except KeyError:
            pass

    def Definition(self, vtype):
        # Forward declerations are not interesting.
        if "DW_AT_declaration" in self.attributes:
            return

        if self.name in vtype and vtype[self.name][0] != self.size:
            self.session.logging.warning(
                "Structs of different sizes but same name")

        count = 1
        result = [self.size, {}]

        for member in self.members:
            if isinstance(member, DW_TAG_member):
                name = member.name

                # Make nicer names for annonymous things (usually unions).
                if name.startswith("__unnamed_"):
                    name = "u%s" % count
                    count += 1

                result[1][name] = member.VType()

        # Only emit structs with actual members in them.
        if result[1]:
            vtype[self.name] = result


class DW_TAG_union_type(DW_TAG_structure_type):
    @utils.safe_property
    def name(self):
        if "DW_AT_name" in self.attributes:
            return self.attributes["DW_AT_name"].value

        if "DW_AT_sibling" in self.attributes:
            sibling = self.types.get(self.attributes["DW_AT_sibling"].value +
                                     self.die.cu.cu_offset)
            if sibling and sibling.die.tag == "DW_TAG_typedef":
                return sibling.name

        return "__unnamed_%s" % self.die.offset


class DW_TAG_pointer_type(DIETag):
    def VType(self):
        if 'DW_AT_type' in self.attributes:
            target = self.types[self.type_id]
            target_type = target.VType()
            if not isinstance(target_type, list):
                target_type = [target_type, None]

            return ['Pointer', dict(target=target_type[0],
                                    target_args=target_type[1])]

        return ['Pointer', dict(target="Void")]


class DW_TAG_subroutine_type(DIETag):
    def VType(self):
        return "void"


class DW_TAG_array_type(DIETag):
    count = 0

    def VType(self):
        if 'DW_AT_type' in self.attributes:
            target_type = self.types[self.type_id].VType()
            if not isinstance(target_type, list):
                target_type = [target_type, None]
            return ['Array', dict(target=target_type[0],
                                  target_args=target_type[1],
                                  count=self.count)]

        return ['Array', dict(count=self.count)]


class DW_TAG_subrange_type(DIETag):
    """These specify the count of arrays."""
    def __init__(self, die, types, parents):
        super(DW_TAG_subrange_type, self).__init__(die, types, parents)

        if "DW_AT_upper_bound" in self.attributes:
            self.parent.count = self.attributes['DW_AT_upper_bound'].value + 1


_DWARF_EXPR_DUMPER_CACHE = {}
def describe_DWARF_expr(expr, structs):
    """ Textual description of a DWARF expression encoded in 'expr'.
        structs should come from the entity encompassing the expression - it's
        needed to be able to parse it correctly.
    """
    # Since this function can be called a lot, initializing a fresh new
    # ExprDumper per call is expensive. So a rudimentary caching scheme is in
    # place to create only one such dumper per instance of structs.
    cache_key = id(structs)
    if cache_key not in _DWARF_EXPR_DUMPER_CACHE:
        _DWARF_EXPR_DUMPER_CACHE[cache_key] = \
            descriptions.ExprDumper(structs)
    dwarf_expr_dumper = _DWARF_EXPR_DUMPER_CACHE[cache_key]
    dwarf_expr_dumper.clear()
    dwarf_expr_dumper.process_expr(expr)
    return dwarf_expr_dumper.get_str().split(":")


class DW_TAG_member(DIETag):
    offset = 0
    type = None

    def __init__(self, die, types, parents):
        super(DW_TAG_member, self).__init__(die, types, parents)

        # Add ourselves to our parent struct.
        self.parent.members.append(self)

        if 'DW_AT_data_member_location' in self.attributes:
            value = self.attributes['DW_AT_data_member_location'].value
            if isinstance(value, (int, long)):
                self.offset = value
            else:
                op_code, value = describe_DWARF_expr(value, die.cu.structs)

                if op_code == "DW_OP_plus_uconst":
                    self.offset = int(value)

    def delegate(self):
        """A member is just a place holder for another type in the struct.

        Thie method returns the delegate.
        """
        return self.types[self.type_id]

    def VType(self):
        member_type = self.delegate().VType()

        # Does this member represent a bitfield?
        if "DW_AT_bit_size" in self.attributes:
            # The dwarf standard says:

            # For a DW_AT_data_bit_offset attribute, the value is an integer
            # constant (see Section 2.19) that specifies the number of bits from
            # the beginning of the containing entity to the beginning of the
            # data member.

            # This means that for little endian we need to swap them with the
            # size of the integer.
            full_size = self.attributes['DW_AT_byte_size'].value * 8
            start_bit = self.attributes['DW_AT_bit_offset'].value
            end_bit = self.attributes['DW_AT_bit_size'].value + start_bit

            converted_start_bit = full_size - end_bit
            converted_end_bit = full_size - start_bit

            # Sometimes the member is an Enumeration. In that case we need to
            # return something slightly different.
            if member_type[0] == "Enumeration":
                member_type[1]["target"] = "BitField"
                member_type[1]["target_args"] = {
                    'start_bit': converted_start_bit,
                    'end_bit': converted_end_bit
                    }
                return [self.offset, member_type]

            return [self.offset, ['BitField', {'start_bit': converted_start_bit,
                                               'target': member_type,
                                               'end_bit': converted_end_bit}]]

        if not isinstance(member_type, list):
            member_type = [member_type]

        return [self.offset, member_type]


class DW_TAG_enumeration_type(DIETag):
    """Holds enumerations."""

    byte_size_lookup = {4: "long",
                        2: "short int",
                        1: "char"}

    def __init__(self, die, types, parents):
        super(DW_TAG_enumeration_type, self).__init__(die, types, parents)
        self.enumerations = {}
        self.reverse_enumerations = {}

    def VType(self):
        byte_size = self.attributes['DW_AT_byte_size'].value
        return ['Enumeration', {'enum_name': self.name,
                                'target': self.byte_size_lookup[byte_size]}]

    def Definition(self, vtype):
        """Enumerations go into the $ENUMS vtype area."""
        vtype.setdefault("$ENUMS", {})[self.name] = self.enumerations
        vtype.setdefault("$REVENUMS", {})[self.name] = self.reverse_enumerations


class DW_TAG_enumerator(DIETag):
    """An enumeration."""

    def __init__(self, die, types, parents):
        super(DW_TAG_enumerator, self).__init__(die, types, parents)

        # Add ourselves to our parent container.
        value = self.attributes['DW_AT_const_value'].value
        self.parent.enumerations[value] = self.name
        self.parent.reverse_enumerations[self.name] = value


# A lookup table of the different tag handlers.
DIE_LOOKUP = {
    "DW_TAG_base_type": DW_TAG_base_type,
    "DW_TAG_structure_type": DW_TAG_structure_type,
    "DW_TAG_union_type": DW_TAG_union_type,
    "DW_TAG_member": DW_TAG_member,

    # typedefs and const types are just proxies to native types.
    "DW_TAG_typedef": DW_TAG_typedef,
    "DW_TAG_const_type": DW_TAG_typedef,

    # Enumrations.
    "DW_TAG_enumeration_type": DW_TAG_enumeration_type,
    "DW_TAG_enumerator": DW_TAG_enumerator,

    "DW_TAG_pointer_type": DW_TAG_pointer_type,
    "DW_TAG_array_type": DW_TAG_array_type,
    "DW_TAG_subrange_type": DW_TAG_subrange_type,
    "DW_TAG_subroutine_type": DW_TAG_subroutine_type,
    "DW_TAG_volatile_type": DW_TAG_volatile_type,
    }

def DIEFactory(die, types, parents):
    """Returns an instance of the DIE object."""
    if die.tag in DIE_LOOKUP:
        return DIE_LOOKUP[die.tag](die, types, parents)

    return DIETag(die, types, parents)


class DWARFParser(object):
    """A parser for DWARF files."""

    def __init__(self, fd, session):
        self.session = session
        self.elffile = elffile.ELFFile(fd)
        self.types = {}

        if self.elffile.has_dwarf_info():
            self._dwarfinfo = self.elffile.get_dwarf_info()
        else:
            raise RuntimeError("File does not have DWARF information - "
                               "was it compiled with debugging information?")
        self.logging = session.logging.getChild("linux.dwarf")
        self.logging.setLevel(logging.ERROR)
        self.compile()

    def compile(self):
        """Compile the vtypes from the dwarf information."""
        # We currently dump all compilation units into the same
        # vtype. Technically the same symbol can be defined differently in
        # different compilation units, but rekall does not have CU
        # resolution right now so we assume they are all the same.
        parents = []
        section_offset = self._dwarfinfo.debug_info_sec.global_offset
        for cu in self._dwarfinfo.iter_CUs():
            parents.append(cu)

            die_depth = 0
            for die in cu.iter_DIEs():
                self.logging.debug('%d %s<%x>: %s' % (
                    die_depth,
                    "\t" * die_depth,
                    die.offset,
                    ('%s' % die.tag) if not die.is_null() else ''))
                if die.is_null():
                    die_depth -= 1
                    parents = parents[:-1]
                    continue

                for attr in itervalues(die.attributes):
                    name = attr.name
                    # Unknown attribute values are passed-through as integers
                    if isinstance(name, int):
                        name = 'Unknown AT value: %x' % name

                    if self.logging.isEnabledFor(logging.DEBUG):
                        try:
                            self.logging.debug('%d %s    <%2x>   %-18s: %s' % (
                                die_depth,
                                "\t" * die_depth,
                                attr.offset,
                                name,
                                describe_attr_value(
                                    attr, die, section_offset)))
                        except Exception:
                            pass

                # Record the type in this DIE.
                t = self.types[die.offset] = DIEFactory(
                    die, self.types, parents)

                if die.has_children:
                    parents.append(t)
                    die_depth += 1


    def VType(self):
        """Build a vtype for this module's dwarf information."""
        result = {}
        for type in self.types.values():
            self.session.report_progress("Extracting type %s", type.name)
            # Only structs emit definitions basically.
            type.Definition(result)

        return result


class DwarfParser(plugin.TypedProfileCommand, plugin.Command):
    """Parse the dwarf file and dump a vtype structure from it."""
    __name = "dwarfparser"

    __args = [
        dict(name="dwarf_filename", positional=True, required=True,
             help="The filename of the PDB file."),

        dict(name="profile_class", default="Linux64",
             help="The name of the profile implementation. "),
    ]

    def __init__(self, *args, **kwargs):
        super(DwarfParser, self).__init__(*args, **kwargs)

        self.parser = DWARFParser(
            open(self.plugin_args.dwarf_filename, "rb"), self.session)

    def render(self, renderer):
        vtypes = self.parser.VType()
        result = {
            "$METADATA": dict(
                Type="Profile",

                # This should probably be changed for something more specific.
                ProfileClass=self.plugin_args.profile_class),
            "$STRUCTS": vtypes,
            "$ENUMS": vtypes.pop("$ENUMS", {}),
            "$REVENUMS": vtypes.pop("$REVENUMS", {}),
            }

        renderer.write(utils.PPrint(result))
