"""A module containing a visitor collecting fields from a type definition.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import fractions
from rekall.layout_expert.common import string_util

from rekall.layout_expert.layout import layout as layouts


class FieldCollectingVisitor(object):
  """A visitor collecting fields from a type definition.
  """

  def __init__(self, expression_evaluator, layout_computer=None):
    self._expression_evaluator = expression_evaluator
    self.layout_computer = layout_computer

  def collect_fields(self, elements):
    fields = []
    for element in elements:
      fields.extend(element.accept(self))
    return fields

  def visit_if(self, if_):
    content = if_.get_active_content(self._expression_evaluator)
    fields = []
    for element in content:
      fields.extend(element.accept(self))
    return fields

  def visit_c_type_definition(self, type_definition):
    if not type_definition.type_name and not type_definition.following_fields:
      layout = self.layout_computer.compute_layout(
          type_definition.type_definition,
      )
      field = layouts.Field(
          bit_offset=None,
          name=None,
          layout=layout,
      )
      return [field]
    else:
      fields = []
      for following_field in type_definition.following_fields:
        fields.extend(following_field.accept(self))
      return fields

  def visit_c_field(self, field):
    field_layout = self.layout_computer.compute_layout(field.type_definition)
    self._update_layout_with_field_attributes(field_layout, field.attributes)
    self._update_layout_with_field_bit_size(field_layout, field.bit_size)
    field_to_collect = layouts.Field(
        bit_offset=None,
        name=field.name,
        layout=field_layout,
    )
    return [field_to_collect]

  def _update_layout_with_field_bit_size(self, layout, bit_size_expression):
    if bit_size_expression:
      layout.bit_size = self._expression_evaluator.evaluate(
          bit_size_expression,
      )
      layout.bit_field = True

  def _update_layout_with_field_attributes(self, layout, attributes):
    """A method that modifies a given layout with the given field attributes.

    Args:
      layout: an object representing a layout.
      attributes: a list of objects representing field attributes.
    """
    attributes_alignment = self._compound_type_bit_alignment()

    for attribute in attributes:
      if string_util.attribute_name_match(attribute.name, 'packed'):
        layout.bit_alignment = self._compound_type_bit_alignment()
      elif string_util.attribute_name_match(attribute.name, 'aligned'):
        byte_alignment = self._expression_evaluator.evaluate(
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
