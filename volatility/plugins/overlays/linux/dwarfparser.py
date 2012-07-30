# Volatility
# Copyright (c) 2012 Michael Cohen <scudette@gmail.com>
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
import json
import optparse
import sys

from elftools.dwarf import descriptions
from elftools.elf import elffile


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

    @property
    def name(self):
        if "DW_AT_name" in self.attributes:
            return self.attributes["DW_AT_name"].value
        else:
            return "__unnamed_%s" % self.die.offset

    @property
    def type_id(self):
        if "DW_AT_type" in self.attributes:
            return self.attributes["DW_AT_type"].value + self.die.cu.cu_offset

    def VType(self):
        """Returns a vtype representation of this DIE."""
        return self.name

    def Definition(self):
        pass

class DW_TAG_typedef(DIETag):

    def VType(self):
        """For typedefs we just substitute our base type."""
        return self.types[self.type_id].VType()


class DW_TAG_base_type(DIETag):
    """A base type."""


class DW_TAG_structure_type(DIETag):
    """A struct definition."""
    def __init__(self, die, types, parents):
        super(DW_TAG_structure_type, self).__init__(die, types, parents)
        # All the members of this struct.
        self.members = []

    @property
    def size(self):
        try:
            return self.attributes['DW_AT_byte_size'].value
        except KeyError:
            pass

    def Definition(self):
        result = [self.size, {}]
        for member in self.members:
            vtype = member.VType()
            result[1][member.name] = vtype

        # Only emit structs with actual members in them.
        if result[1]:
            return [self.name, result]


class DW_TAG_union_type(DW_TAG_structure_type):
    def Definition(self):
        pass


class DW_TAG_pointer_type(DIETag):
    def VType(self):
        if 'DW_AT_type' in self.attributes:
            target = self.types[self.type_id]
            target_type = target.VType()
            if not isinstance(target_type, list):
                target_type = [target_type]

            return ['pointer', target_type]

        return ['pointer', ['void']]


class DW_TAG_subroutine_type(DIETag):
    def VType(self):
        return "void"


class DW_TAG_array_type(DIETag):
    count = 0

    def VType(self):
        if 'DW_AT_type' in self.attributes:
            target_type = self.types[self.type_id].VType()
            if not isinstance(target_type, list):
                target_type = [target_type]
            return ['array', self.count, target_type]

        return ['array', self.count, ['void']]


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
    offset = None
    type = None

    def __init__(self, die, types, parents):
        super(DW_TAG_member, self).__init__(die, types, parents)

        # Add ourselves to our parent struct.
        self.parent.members.append(self)

        if 'DW_AT_data_member_location' in self.attributes:
            op_code, value = describe_DWARF_expr(
                self.attributes['DW_AT_data_member_location'].value,
                die.cu.structs)

            if op_code=="DW_OP_plus_uconst":
                self.offset = int(value)

    def VType(self):
        if self.type_id not in self.types:
            import pdb; pdb.set_trace()

        member_type = self.types[self.type_id].VType()

        # Does this member represent a bitfield?
        if "DW_AT_bit_size" in self.attributes:
            # The dwarf standard says:

            # For a DW_AT_data_bit_offset attribute, the value is an integer
            # constant (see Section 2.19) that specifies the number of bits from
            # the beginning of the containing entity to the beginning of the data
            # member.

            # This means that for little endian we need to swap them with the
            # size of the integer.
            full_size = self.attributes['DW_AT_byte_size'].value * 8
            start_bit = self.attributes['DW_AT_bit_offset'].value
            end_bit = self.attributes['DW_AT_bit_size'].value + start_bit

            converted_start_bit = full_size - end_bit
            converted_end_bit = full_size - start_bit

            return [self.offset, ['BitField', {'start_bit': converted_start_bit,
                                               'native_type': member_type,
                                               'end_bit': converted_end_bit}]]

        if not isinstance(member_type, list):
            member_type = [member_type]
        return [self.offset, member_type]


class DW_TAG_enumeration_type(DIETag):
    """Holds enumerations."""

    byte_size_lookup = { 4: "long",
                         2: "short int",
                         1: "char" }

    def __init__(self, die, types, parents):
        super(DW_TAG_enumeration_type, self).__init__(die, types, parents)
        self.enumerations = {}

    def VType(self):
        byte_size = self.attributes['DW_AT_byte_size'].value
        return ['Enumeration', {'choices': self.enumerations,
                                'target': self.byte_size_lookup[byte_size]}]

class DW_TAG_enumerator(DIETag):
    """An enumeration."""

    def __init__(self, die, types, parents):
        super(DW_TAG_enumerator, self).__init__(die, types, parents)

        # Add ourselves to our parent container.
        value = self.attributes['DW_AT_const_value'].value
        self.parent.enumerations[value] = self.name


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
    }

def DIEFactory(die, types, parents):
    """Returns an instance of the DIE object."""
    if die.tag in DIE_LOOKUP:
        return DIE_LOOKUP[die.tag](die, types, parents)

    return DIETag(die, types, parents)


class DWARFParser(object):
    """A parser for DWARF files."""

    def __init__(self, fd):
        self.elffile = elffile.ELFFile(fd)
        self.types = {}

        if self.elffile.has_dwarf_info():
            self._dwarfinfo = self.elffile.get_dwarf_info()
        else:
            raise RuntimeError("File does not have DWARF information - "
                               "was it compiled with debugging information?")
        self.compile()

    def compile(self):
        """Compile the vtypes from the dwarf information."""
        # We currently dump all compilation units into the same
        # vtype. Technically the same symbol can be defined differently in
        # different compilation units, but volatility does not have CU
        # resolution right now so we assume they are all the same.
        parents = []
        for cu in self._dwarfinfo.iter_CUs():
            parents.append(cu)

            for die in cu.iter_DIEs():
                if die.is_null():
                    parents = parents[:-1]
                    continue

                # Record the type in this DIE.
                t = self.types[die.offset] = DIEFactory(die, self.types, parents)

                if die.has_children:
                    parents.append(t)

    def VType(self):
        """Build a vtype for this module's dwarf information."""
        result = {}
        for type_id, type in self.types.items():
            # Only structs emit definitions basically.
            definition = type.Definition()
            if definition:
                result[definition[0]] = definition[1]

        return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: dwarfparser.py  module.ko > module.json"
    else:
        parser = DWARFParser(open(sys.argv[1]), "rb")
        vtypes = parser.VType()

        print json.dumps(vtypes)
