"""A module containing a visitor computing a vtype description of a type."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import re


class TypeDescriptionVisitor(object):
  """A class representing a visitor computing a vtype description of a type."""

  COMPLEX_TYPE_REGEX = re.compile(r'^((enum)|(struct)|(union)) ')

  def __init__(self, typedef_resolver):
    self._typedef_resolver = typedef_resolver

  def get_description(self, type_definition, types):
    return type_definition.accept(self, types)

  def visit_c_enum(self, enum, types):
    _ = enum
    _ = types
    return ['__enum']

  def visit_c_struct(self, struct, types):
    _ = struct
    _ = types
    return ['__struct']

  def visit_c_union(self, union, types):
    _ = union
    _ = types
    return ['__union']

  def visit_c_array(self, array, types):
    target_description = self.get_description(array.type_definition, types)
    type_parameters = dict(
        count=array.evaluated_length,
        target=target_description[0],
        target_args=self._get_target_args(target_description),
    )
    return ['Array', type_parameters]

  def visit_c_pointer(self, pointer, types):
    target_description = self.get_description(pointer.type_definition, types)
    type_parameters = dict(
        target=target_description[0],
        target_args=self._get_target_args(target_description),
    )
    return ['Pointer', type_parameters]

  def visit_c_pointer_to_function(self, pointer_to_function, types):
    _ = pointer_to_function
    _ = types
    type_parameters = dict(
        target='void',
        target_args=None,
    )
    return ['Pointer', type_parameters]

  def visit_c_type_reference(self, type_reference, types):
    resolved = self._typedef_resolver.resolve(type_reference, types)
    type_name = self._transform_name(resolved.type_name)
    if type_reference.type_name.startswith('enum '):
      return self._get_enum_reference_description(type_name)
    return [type_name]

  def _get_enum_reference_description(self, enum_name):
    type_parameters = {
        'target': 'long',
        'enum_name': enum_name,
    }
    return ['Enumeration', type_parameters]

  def _get_target_args(self, target_description):
    if len(target_description) > 1:
      return target_description[1]
    else:
      return None

  def _transform_name(self, type_name):
    if self.COMPLEX_TYPE_REGEX.match(type_name):
      return type_name.split(' ')[1]
    if type_name == 'void':
      return 'Void'
    return type_name
