"""A module containing a Preprocessing Visitor for Pre-AST trees."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from rekall.layout_expert.c_ast import pre_ast


class PreprocessingVisitor(object):
  """A class representing a Preprocessing Visitor for Pre-AST trees."""

  def __init__(
      self,
      object_likes,
      function_likes,
      functions,
      expression_evaluator,
      macro_expander,
  ):
    self._object_likes = object_likes
    self._function_likes = function_likes
    self._functions = functions
    self._expression_evaluator = expression_evaluator
    self._macro_expander = macro_expander

  def preprocess(self, node):
    return node.accept(self)

  def visit_file(self, file_):
    content = file_.content.accept(self)
    return pre_ast.File(content)

  def visit_include(self, include):
    if include.content:
      return self.preprocess(include.content)
    else:
      return None

  def visit_pragma(self, pragma):
    return pragma

  def visit_error(self, error):
    raise PreprocessingException(error)

  def visit_define_object_like(self, define_object_like):
    name = define_object_like.name
    self._object_likes[name] = define_object_like
    return None

  def visit_define_function_like(self, define_function_like):
    name = define_function_like.name
    self._function_likes[name] = define_function_like
    return None

  def visit_undef(self, undef):
    name = undef.name
    self._object_likes.pop(name, None)
    self._function_likes.pop(name, None)
    return None

  def visit_if(self, if_):
    active_content = if_.get_active_content(self._expression_evaluator)
    return active_content.accept(self)

  def visit_composite_block(self, composite_block):
    preprocessed_content = []
    for element in composite_block.content:
      maybe_preprocessed_element = element.accept(self)
      if element:
        preprocessed_content.append(maybe_preprocessed_element)
    return pre_ast.CompositeBlock(preprocessed_content)

  def visit_text_block(self, text_block):
    expanded_content = self._macro_expander.expand(text_block.content)
    return pre_ast.TextBlock(expanded_content)


class PreprocessingException(Exception):
  pass


