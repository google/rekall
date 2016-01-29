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

"""A module containing a converter from layout to vtype format."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


class LayoutToVTypeConverter(object):

    """A class representing a converter from layout to vtype format."""

    def __init__(self, type_description_visitor):
        self._type_description_visitor = type_description_visitor

    def to_vtype(self, layout, type_definition, types):
        byte_size = layout.bit_size // 8
        fields = {}
        for field_layout, field in zip(layout.fields, type_definition.content):
            byte_offset = field_layout.bit_offset // 8
            type_description = self._get_type_description(
                field_layout, field, types)
            fields[field_layout.name] = [byte_offset, type_description]
        return [byte_size, fields]

    def _get_type_description(self, field_layout, field, types):
        """Returns a vtype description of the type of a given field."""
        type_description = self._type_description_visitor.get_description(
            field.type_definition,
            types,
        )
        if field_layout.layout.bit_field:
            type_description = self._get_bitfield_type_description(
                field_layout,
                type_description,
            )
        return type_description

    def _get_bitfield_type_description(self, field_layout, type_description):
        start_bit = field_layout.bit_offset % 8
        end_bit = start_bit + field_layout.layout.bit_size
        return [
            'BitField', {
                'start_bit': start_bit,
                'end_bit': end_bit,
                'target': type_description[0],
            }
        ]
