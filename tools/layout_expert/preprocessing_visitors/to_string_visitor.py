"""A module containing a visitor that transforms a simple Pre-AST to string.

It is used to pretty print the AST.
Also used to substitute macros when evaluation the Pre-AST.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


class ToStringVisitor(object):
  """A visitor class that transforms a simple Pre-AST to string.

  Works on already prepared Pre-AST so it can only contain a reduced
  set of nodes.
  """

  def to_string(self, node, parts=None):
    if parts is None:
      parts = []
    node.accept(self, parts)
    return ' '.join(parts)

  def visit_file(self, file_, parts):
    self.to_string(file_.content, parts)

  def visit_composite_block(self, composite_block, parts):
    for element in composite_block.content:
      if element is not None:
        self.to_string(element, parts)

  def visit_text_block(self, text_block, parts):
    parts.append(text_block.content)
