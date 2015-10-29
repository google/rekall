"""A module containing a visitor collecting types from an AST tree.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


class TypeCollectingVisitor(object):
  """A class representing a visitor collecting types from an AST tree.
  """

  def __init__(self, expression_evaluator):
    self._expression_evaluator = expression_evaluator

  def collect_types(self, program):
    return program.accept(self)

  def visit_c_program(self, program):
    types = {}
    for element in program.content:
      element_types = element.accept(self)
      self._update_types(types, element_types)
    return types

  def visit_if(self, if_):
    types = {}
    try:
      content = if_.get_active_content(self._expression_evaluator)
    except KeyError:
      return {}
    for element in content:
      self._update_types(types, element.accept(self))
    return types

  def visit_c_type_definition(self, type_definition):
    types = {}
    if type_definition.type_name:
      types[type_definition.type_name] = type_definition.type_definition
    return types

  def visit_c_field(self, _):
    return {}

  def visit_c_typedef(self, typedef):
    types = typedef.type_definition.accept(self)
    types[typedef.name] = typedef
    return types

  def visit_c_type_reference(self, type_reference):
    _ = type_reference
    return {}

  def visit_c_enum(self, enum):
    _ = enum
    return {}

  def visit_c_struct(self, struct):
    _ = struct
    return {}

  def visit_c_union(self, union):
    _ = union
    return {}

  def visit_c_pointer(self, pointer):
    _ = pointer
    return {}

  def visit_c_pointer_to_function(self, pointer_to_function):
    _ = pointer_to_function
    return {}

  def visit_c_array(self, array):
    _ = array
    return {}

  def _update_types(self, types, element_types):
    for type_name, definition in element_types.iteritems():
      if type_name in types:
        raise TwoDefinitionsOfTheSameTypeException(type_name)
      types[type_name] = definition


class TwoDefinitionsOfTheSameTypeException(Exception):

  def __init__(self, type_name):
    super(TwoDefinitionsOfTheSameTypeException, self).__init__()
    self.type_name = type_name
