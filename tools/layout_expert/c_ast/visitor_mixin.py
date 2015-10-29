"""A module containing a VisitorMixin for the purpose of Visitor Pattern."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from rekall.layout_expert.common import string_util


class VisitorMixin(object):
  """A mixin that provides Visitor Pattern.

  This is mixed into AST node to provide visitor pattern. Used in both ASTs.
  """

  def accept(self, visitor, *args, **kwargs):
    """Accepts a visitor from Visitor Pattern.

    Args:
      visitor: a visitor with .visit_CLASSNAME(type_reference_node) method
          where CLASSNAME is the name of a visited class.
      *args: additional positional arguments to be passed to the visitor call.
      **kwargs: additional keyword arguments to be passed to the visitor call.

    Returns:
      A value returned by the visitor.
    """
    lower_underscore_class_name = string_util.camel_case_to_lower_underscore(
        self.__class__.__name__,
    )
    visitor_method_name = 'visit_' + lower_underscore_class_name
    visitor_method = getattr(visitor, visitor_method_name)
    return visitor_method(self, *args, **kwargs)
