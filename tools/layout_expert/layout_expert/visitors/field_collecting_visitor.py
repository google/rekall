#!/usr/bin/env python
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

"""A visitor collecting fields from a type definition."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import fractions
from layout_expert.lib import parsers

from layout_expert.layout import layout as layouts


class FieldCollectingVisitor(object):

    """A visitor collecting fields from a type definition.
    """

    def __init__(self, type_manager):
        self.type_manager = type_manager

    def collect_fields(self, elements):
        fields = []
        for element in elements:
            fields.extend(element.accept(self))
        return fields

    def visit_c_type_definition(self, type_definition):
        layout = self.type_manager.compute_layout(
            type_definition.type_definition,
        )
        field = layouts.Field(
            bit_offset=None,
            name=None,
            layout=layout,
        )
        return [field]

    def visit_c_field(self, field):
        field_layout = self.type_manager.compute_layout(
            field.type_definition)
        self._update_layout_with_field_attributes(
            field_layout, field.attributes)
        self._update_layout_with_field_bit_size(field_layout, field.bit_size)
        field_to_collect = layouts.Field(
            bit_offset=None,
            name=field.name,
            layout=field_layout,
        )
        return [field_to_collect]

    def _update_layout_with_field_bit_size(self, layout, bit_size_expression):
        if bit_size_expression is not None:
            layout.bit_size = self.type_manager.evaluate(
                bit_size_expression,
            )
            layout.bit_field = True

    def _update_layout_with_field_attributes(self, layout, attributes):
        """Modifies a given layout with the given field attributes.

        Args:
          layout: an object representing a layout.
          attributes: a list of objects representing field attributes.
        """
        attributes_alignment = self._compound_type_bit_alignment()

        for attribute in attributes:
            if parsers.attribute_name_match(attribute.name, 'packed'):
                layout.bit_alignment = self._compound_type_bit_alignment()
            elif parsers.attribute_name_match(attribute.name, 'aligned'):
                byte_alignment = self.type_manager.evaluate(
                    expression=attribute.parameters[0],
                )
                attributes_alignment = self._lcm(
                    attributes_alignment,
                    8 * byte_alignment,
                )

        layout.bit_alignment = self._lcm(
            layout.bit_alignment,
            attributes_alignment,
        )

    def _compound_type_bit_alignment(self):
        return 8

    def _lcm(self, a, b):
        return a * b // fractions.gcd(a, b)
