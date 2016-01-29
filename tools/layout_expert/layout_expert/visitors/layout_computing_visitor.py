# -*- coding: utf-8 -*-

# Copyright (C) 2016 Google Inc. All Rights Reserved.
#
# Authors:
# Arkadiusz Socała <as277575@mimuw.edu.pl>
# Michael Cohen <scudette@google.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.
"""A visitor computing layout from a type definition."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import fractions

from layout_expert.c_ast import c_ast
from layout_expert.lib import parsers
from layout_expert.layout import layout as layouts


class LayoutComputingVisitor(object):
    """A visitor computing layout from a type definition."""

    def __init__(self, type_manager):
        self.type_manager = type_manager

    def compute_layout(self, element):
        return element.accept(self)

    def visit_c_program(self, program):
        for element in program.content:
            return element.accept(self)

    def visit_c_enum(self, enum):
        _ = enum
        return self.compute_layout(c_ast.CTypeReference('int'))

    def visit_c_struct(self, struct):
        """A method visiting a struct definition and returing the layout.

        Args:
          struct: an object representing a struct definition in AST.

        Returns:
          An object representing the layout of the struct.
        """
        fields = self.type_manager.collect_fields(struct)
        packed = self._is_packed(struct.attributes)
        bit_alignment = self._get_attributes_alignment(struct.attributes)
        bit_offset = 0
        for field, type_definition in zip(fields, struct.content):
            bit_offset = self._align_field(
                bit_offset,
                field.layout,
                type_definition,
                packed,
            )
            if not packed or self._is_alignment_overriden(type_definition):
                bit_alignment = self._lcm(
                    bit_alignment, field.layout.bit_alignment)
            field.bit_offset = bit_offset
            bit_offset += field.layout.bit_size
        bit_size = self._align(bit_offset, bit_alignment)
        return layouts.Layout(
            bit_size=bit_size,
            bit_alignment=bit_alignment,
            fields=fields,
        )

    def visit_c_union(self, union):
        """A method visiting a union definition and returing the layout.

        Args:
          union: an object representing a union definition in AST.

        Returns:
          An object representing the layout of the union.
        """
        fields = self.type_manager.collect_fields(union)
        packed = self._is_packed(union.attributes)
        bit_alignment = self._get_attributes_alignment(union.attributes)
        bit_size = 0
        for field, type_definition in zip(fields, union.content):
            if not packed or self._is_alignment_overriden(type_definition):
                bit_alignment = self._lcm(
                    bit_alignment, field.layout.bit_alignment)
            field.bit_offset = 0
            bit_size = max(bit_size, field.layout.bit_size)
        bit_size = self._align(bit_size, bit_alignment)
        return layouts.Layout(
            bit_size=bit_size,
            bit_alignment=bit_alignment,
            fields=fields,
        )

    def visit_c_array(self, array):
        layout = array.type_definition.accept(self)
        length = self.type_manager.evaluate(array.length)
        array.evaluated_length = length
        return layouts.ArrayLayout(
            bit_size=length * layout.bit_size,
            bit_alignment=layout.bit_alignment,
            length=length,
            member_layout=layout
        )

    def visit_c_pointer(self, pointer):
        _ = pointer
        return layouts.Layout(
            bit_size=self._pointer_bit_size(),
            bit_alignment=self._pointer_bit_alignment(),
            fields=[],
        )

    def visit_c_pointer_to_function(self, pointer_to_function):
        return self.visit_c_pointer(pointer_to_function)

    def visit_c_simple_type(self, simple_type):
        return layouts.Layout(
            bit_size=simple_type.bit_size,
            bit_alignment=simple_type.bit_alignment,
            fields=[],
        )

    def visit_c_type_reference(self, type_reference):
        # Dereference the referred type.
        reference_ast = self.type_manager.get_type_ast(type_reference.name)

        # This is a circular reference which means it is not defined.
        if reference_ast == type_reference:
            raise c_ast.IrreducibleFunction(
                "Unable to resolve type name %s. Is it defined?",
                type_reference.name)

        # Visit it.
        return reference_ast.accept(self)

    def visit_c_type_definition(self, type_definition):
        return type_definition.type_definition.accept(self)

    def visit_c_typedef(self, typedef):
        layout = typedef.type_definition.accept(self)
        for attribute in typedef.attributes:
            if parsers.attribute_name_match(attribute.name, 'aligned'):
                expression = attribute.parameters[0]
                byte_alignment = self.type_manager.evaluate(
                    expression)
                layout.bit_alignment = 8 * byte_alignment
        return layout

    def _get_results(self, elements):
        collected_layouts = []
        for element in elements:
            element_layouts = element.accept(self)
            collected_layouts.extend(element_layouts)
        return collected_layouts

    def _is_packed(self, attributes):
        for attribute in attributes:
            if parsers.attribute_name_match(attribute.name, 'packed'):
                return True
        return False

    def _get_attributes_alignment(self, attributes):
        bit_alignment = self._base_alignment()
        for attribute in attributes:
            if parsers.attribute_name_match(attribute.name, 'aligned'):
                expression = attribute.parameters[0]
                byte_alignment = int(self.type_manager.evaluate(
                    expression))
                bit_alignment = self._lcm(bit_alignment, 8 * byte_alignment)
        return bit_alignment

    def _align_field(self, bit_offset, layout, type_definition, packed):
        bit_alignment = self._get_field_alignment(
            layout, type_definition, packed)
        aligned = self._align(bit_offset, bit_alignment)
        if layout.bit_field and bit_offset + layout.bit_size <= aligned:
            return bit_offset
        return aligned

    def _get_field_alignment(self, layout, type_definition, packed):
        if packed and not self._is_alignment_overriden(type_definition):
            if layout.bit_field:
                return 1
            else:
                return self._base_alignment()
        else:
            return layout.bit_alignment

    def _align(self, offset, alignment):
        # round up offset to the next multiplication of alignment
        return alignment * ((offset + alignment - 1) // alignment)

    def _is_alignment_overriden(self, type_definition):
        if hasattr(type_definition, 'attributes'):
            for attribute in type_definition.attributes:
                if parsers.attribute_name_match(attribute.name, 'aligned'):
                    return True
        return False

    def _base_alignment(self):
        return 8

    def _pointer_bit_size(self):
        return self.type_manager.get_type_ast('long').bit_size

    def _pointer_bit_alignment(self):
        return self.type_manager.get_type_ast('long').bit_alignment

    def _lcm(self, a, b):
        return a * b // fractions.gcd(a, b)

    def visit_c_void_type(self, _):
        raise c_ast.IrreducibleFunction("Unable to layout Void expression.")
