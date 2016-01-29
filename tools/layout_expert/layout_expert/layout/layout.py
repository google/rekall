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

"""A module containing classes to represent layouts.

Process information about each type, alignment and size.

Used to represent the output of our layout computation for each field,
represent the alignment, type and size.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from layout_expert.common import data_container


class _LayoutNode(data_container.DataContainer):
    """A base class for layout nodes."""
    pass


class Layout(_LayoutNode):
    """A class to represent a layout of a type."""

    def __init__(self, bit_size, bit_alignment, fields=None, bit_field=False):
        """Initializes a Layout object.

        Args:
          bit_size: an int representing the size of a type in bits.
          bit_alignment: an int representing the alignment of a type in bits.
          fields: a list of CField objects representing the fields nested inside
            of a type.  bit_field: a bool indicating weather a field is as a
            BitField.
        """
        super(Layout, self).__init__()
        self.bit_size = bit_size
        self.bit_alignment = bit_alignment
        self.fields = fields or []
        self.bit_field = bit_field


class ArrayLayout(_LayoutNode):
    """A class to represent a layout of an array of some type."""

    def __init__(self, bit_size, bit_alignment, length, member_layout):
        """Initializes an ArrayLayout object.

        Args:
          bit_size: an int representing the size of an array in bits.
          bit_alignment: an int representing the alignment of an array in bits.
          length: an int representing the lenght of an array.
          member_layout: a Layout object to represent the layout of one field of
            an array.
        """
        super(ArrayLayout, self).__init__()
        self.bit_size = bit_size
        self.bit_alignment = bit_alignment
        self.length = length
        self.member_layout = member_layout
        self.bit_field = False


class Field(_LayoutNode):
    """A class to represent a field nested inside of a layout."""

    def __init__(self, bit_offset, name, layout):
        """Initializes a CField object.

        Args:
          bit_offset: an integer representing a bit offset from the beginning of
              the struct. It can be None if the offset is unknown.
          name: a string representing a name of a field. It can be None if
              the field is anonymous.
          layout: an object representing a layout of a field.
          type_definition: The type of this field.
        """
        super(Field, self).__init__()
        self.bit_offset = bit_offset
        self.name = name
        self.layout = layout
