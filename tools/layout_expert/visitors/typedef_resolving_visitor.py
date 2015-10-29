"""A module containing a visitor class that resolves typedef references."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


class TypedefResolvingVisitor(object):
  """A class representing a visitor that resolves typedef references."""

  def resolve(self, node, types):
    return node.accept(self, types)

  def visit_c_enum(self, enum, types):
    _ = enum
    _ = types
    return None

  def visit_c_struct(self, struct, types):
    _ = struct
    _ = types
    return None

  def visit_c_union(self, union, types):
    _ = union
    _ = types
    return None

  def visit_c_array(self, array, types):
    _ = array
    _ = types
    return None

  def visit_c_pointer(self, pointer, types):
    _ = pointer
    _ = types
    return None

  def visit_c_pointer_to_function(self, pointer_to_function, types):
    _ = pointer_to_function
    _ = types
    return None

  def visit_c_type_reference(self, type_reference, types):
    type_name = type_reference.type_name
    if type_name in types:
      resolved = self.resolve(types[type_name], types)
      if resolved:
        return resolved
    return type_reference

  def visit_c_type_definition(self, type_definition, types):
    _ = types
    if type_definition.type_name:
      return type_definition
    else:
      return None

  def visit_c_typedef(self, typedef, types):
    return self.resolve(typedef.type_definition, types)

  def visit_c_simple_type(self, simple_type, types):
    _ = simple_type
    _ = types
    return None
