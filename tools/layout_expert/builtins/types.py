"""A module containing definitions of compiler builtin types.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from rekall.layout_expert.c_ast import c_ast


def get_64bit_types():
  """A functions returns a dict with type definitions for LP64 model.

  Verified with 64bit GCC.

  Returns:
    A dict from type names to type definitions  for LP64 model.
  """
  # Not perfect! Spaces should not be important!
  return {
      'char': c_ast.CSimpleType(8, 8),
      'unsigned char': c_ast.CSimpleType(8, 8),
      'signed char': c_ast.CSimpleType(8, 8),

      'short': c_ast.CSimpleType(16, 16),
      'unsigned short': c_ast.CSimpleType(16, 16),
      'signed short': c_ast.CSimpleType(16, 16),
      'short int': c_ast.CSimpleType(16, 16),
      'unsigned short int': c_ast.CSimpleType(16, 16),
      'signed short int': c_ast.CSimpleType(16, 16),

      'int': c_ast.CSimpleType(32, 32),
      'unsigned': c_ast.CSimpleType(32, 32),
      'unsigned int': c_ast.CSimpleType(32, 32),
      'signed': c_ast.CSimpleType(32, 32),
      'signed int': c_ast.CSimpleType(32, 32),

      'long': c_ast.CSimpleType(64, 64),
      'unsigned long': c_ast.CSimpleType(64, 64),
      'signed long': c_ast.CSimpleType(64, 64),
      'long int': c_ast.CSimpleType(64, 64),
      'unsigned long int': c_ast.CSimpleType(64, 64),
      'signed long int': c_ast.CSimpleType(64, 64),

      'long long': c_ast.CSimpleType(64, 64),
      'unsigned long long': c_ast.CSimpleType(64, 64),
      'signed long long': c_ast.CSimpleType(64, 64),
      'long long int': c_ast.CSimpleType(64, 64),
      'unsigned long long int': c_ast.CSimpleType(64, 64),
      'signed long long int': c_ast.CSimpleType(64, 64),

      '_Bool': c_ast.CSimpleType(8, 8),
      'size_t': c_ast.CSimpleType(64, 64),
  }
