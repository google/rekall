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
"""A module containing definitions of compiler builtin types."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from layout_expert.c_ast import c_ast


def get_64bit_types():
    """A functions returns a dict with type definitions for LP64 model.

    Verified with 64bit GCC.

    Returns:
      A dict from type names to type definitions  for LP64 model.
    """
    # Not perfect! Spaces should not be important!
    result = {
        'char': c_ast.CSimpleType(8, 8, True),
        'unsigned char': c_ast.CSimpleType(8, 8),
        'signed char': c_ast.CSimpleType(8, 8, True),

        'short': c_ast.CSimpleType(16, 16, True),
        'unsigned short': c_ast.CSimpleType(16, 16),
        'signed short': c_ast.CSimpleType(16, 16, True),
        'short int': c_ast.CSimpleType(16, 16, True),
        'unsigned short int': c_ast.CSimpleType(16, 16),
        'signed short int': c_ast.CSimpleType(16, 16, True),

        'int': c_ast.CSimpleType(32, 32, True),
        'unsigned': c_ast.CSimpleType(32, 32),
        'unsigned int': c_ast.CSimpleType(32, 32),
        'signed': c_ast.CSimpleType(32, 32, True),
        'signed int': c_ast.CSimpleType(32, 32, True),

        'long': c_ast.CSimpleType(64, 64, True),
        'unsigned long': c_ast.CSimpleType(64, 64),
        'signed long': c_ast.CSimpleType(64, 64, True),
        'long int': c_ast.CSimpleType(64, 64, True),
        'unsigned long int': c_ast.CSimpleType(64, 64),
        'signed long int': c_ast.CSimpleType(64, 64, True),

        'long long': c_ast.CSimpleType(64, 64, True),
        'unsigned long long': c_ast.CSimpleType(64, 64),
        'signed long long': c_ast.CSimpleType(64, 64, True),
        'long long int': c_ast.CSimpleType(64, 64, True),
        'unsigned long long int': c_ast.CSimpleType(64, 64),
        'signed long long int': c_ast.CSimpleType(64, 64, True),

        '_Bool': c_ast.CSimpleType(8, 8),
        'size_t': c_ast.CSimpleType(64, 64),

        # Pointers to void are allowed.
        'void *': c_ast.CSimpleType(64, 64),
        'void': c_ast.CVoidType(),
    }

    # Some aliases.
    result['__signed__ int'] = result["signed int"]
    result['__signed__ short'] = result["signed short"]
    result['__signed__ long'] = result["signed long"]

    # Tell the types about their names.
    for name, type in result.iteritems():
        type.name = name

    return result
