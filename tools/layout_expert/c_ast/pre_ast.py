"""A module containing classes representing nodes of AST before preprocessing.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from rekall.layout_expert.c_ast import visitor_mixin
from rekall.layout_expert.common import data_container
from rekall.layout_expert.common import enum


class _PreASTNode(data_container.DataContainer, visitor_mixin.VisitorMixin):
  """A base clas for pre-AST nodes."""


class File(_PreASTNode):

  def __init__(self, content):
    super(File, self).__init__()
    self.content = content


class Include(_PreASTNode):

  class QuotesType(enum.Enum):
    ANGLE_BRACKETS = 1
    DOUBLE_QUOTES = 2

  def __init__(self, path, quotes_type, absolute_path=None, content=None):
    super(Include, self).__init__()
    self.path = path
    self.quotes_type = quotes_type
    self.absolute_path = absolute_path
    self.content = content


class Pragma(_PreASTNode):

  def __init__(self, arguments):
    super(Pragma, self).__init__()
    self.arguments = arguments


class PragmaArgument(_PreASTNode):

  def __init__(self, name, arguments=None, value=None):
    super(PragmaArgument, self).__init__()
    self.name = name
    self.arguments = arguments
    self.value = value

  @property
  def is_functional(self):
    return self.arguments is not None


class Error(_PreASTNode):

  def __init__(self, message):
    super(Error, self).__init__()
    self.message = message


class DefineObjectLike(_PreASTNode):
  """A class that represents an object-like definition.

  For example:
  #define foo
  """

  def __init__(self, name, replacement, string_replacement):
    super(DefineObjectLike, self).__init__()
    self.name = name
    self.replacement = replacement
    self.string_replacement = string_replacement


class DefineFunctionLike(_PreASTNode):
  """A class that represents a function-like definition.

  For exmaple:
  #define foo()
  """

  def __init__(self, name, arguments, replacement, string_replacement):
    super(DefineFunctionLike, self).__init__()
    self.name = name
    self.arguments = arguments
    self.replacement = replacement
    self.string_replacement = string_replacement


class Undef(_PreASTNode):

  def __init__(self, name):
    super(Undef, self).__init__()
    self.name = name


class If(_PreASTNode):
  """A class to represent a conditional (e.g. ifdef) block."""

  def __init__(self, conditional_blocks, else_content=None):
    """Initializes an If object.

    Args:
      conditional_blocks: A list of ConditionalBlock objects.
      else_content: A list of elements representing a block in an #else clause.

    Note that the child nodes are of types ConditionalBlock and CompositeBlock
    (the last one in the case of else clause).
    """
    super(If, self).__init__()
    self.conditional_blocks = conditional_blocks
    self.else_content = else_content or CompositeBlock([])

  def get_active_content(self, expression_evaluator):
    for conditional_block in self.conditional_blocks:
      evaluated_conditional_expression = expression_evaluator.evaluate(
          conditional_block.conditional_expression,
      )
      if evaluated_conditional_expression.value:
        return conditional_block.content
    return self.else_content


class ConditionalBlock(_PreASTNode):
  """A class representing a pair of conditional expression and content.

  This is an internal node to represent the condition inside of an If block.
  """

  def __init__(self, conditional_expression, content):
    """Initiates a ConditionalBlock object.

    Args:
      conditional_expression: an expression representing a logic
        condition
      content: a content corresponding to this condition.
    """
    super(ConditionalBlock, self).__init__()
    self.conditional_expression = conditional_expression
    self.content = content


class CompositeBlock(_PreASTNode):

  def __init__(self, content):
    super(CompositeBlock, self).__init__()
    self.content = content

  def __str__(self):
    return ' '.join(map(str, self.content))


class TextBlock(_PreASTNode):

  def __init__(self, content):
    super(TextBlock, self).__init__()
    self.content = content
