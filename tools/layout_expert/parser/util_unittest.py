from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

import mock

from rekall.layout_expert.parser import util


class TestAction(unittest.TestCase):
  """A class to test the util.action function/decorator.

  The util.action is intended to wrap a function that expects to receive
  parsed tokens into a wrapper that receives also parsed string and a line
  number and ignores them. This transforms a provided function on parsed tokens
  into a parse action in a sense of pyparsing library.

  We test util.action by passing a mock function as an argument to it and
  checking if proper arguments were passed to it. Also we check if the
  correct result was returned from the wrapper.
  """

  def setUp(self):
    self.tokens = mock.MagicMock()

  def test_action_with_args_and_kwargs(self):

    def function(*args, **kwargs):
      self.assertEqual(args, (51, 42, 33))
      self.assertEqual(kwargs, {'a': 3, 'b': 2, 'c': 1})
      return -1

    self.tokens.asList.return_value = [51, 42, 33]
    wrapped_function = util.action(function, a=3, b=2, c=1)
    actual = wrapped_function('string1', 0, self.tokens)
    expected = -1
    self.assertEqual(actual, expected)


if __name__ == '__main__':
  unittest.main()
