from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

import mock
from rekall.layout_expert.c_ast import visitor_mixin


class TestVisitorMixin(unittest.TestCase):

  class MockSubclass(visitor_mixin.VisitorMixin):
    pass

  def test_accept(self):
    visitor = mock.MagicMock()
    visitor.visit_visitor_mixin.return_value = -2
    visitor_mixin_instance = visitor_mixin.VisitorMixin()
    actual = visitor_mixin_instance.accept(visitor, 42, foo=33)
    self.assertEqual(actual, -2)
    visitor.visit_visitor_mixin.assert_called_with(
        visitor_mixin_instance,
        42,
        foo=33,
    )

  def test_accept_with_mock_subclass(self):
    visitor = mock.MagicMock()
    visitor.visit_mock_subclass.return_value = 7
    subclass_instance = self.MockSubclass()
    actual = subclass_instance.accept(visitor, 33, 42, bar='baz')
    self.assertEqual(actual, 7)
    visitor.visit_mock_subclass.assert_called_with(
        subclass_instance,
        33,
        42,
        bar='baz',
    )


if __name__ == '__main__':
  unittest.main()
