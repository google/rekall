"""A module containing common utils to be used by other parser modules.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


def action(function, **kwargs):
  """A convenience ParseAction decorator.

  It transforms a function(token1, token2, token3,...) into
  a function(string, line, parser_result) which can be passed to
  some_parser.setParseAction(...) or some_parser.addParseAction(...)
  methods.

  Args:
    function: a function to be wrapped.
    **kwargs: additional keyword arguments to be passed in a function call,
        useful in the non-decorator form e.g.:
        integer_parser.setParseAction(action(int, base=0))
  Returns:
    A result of the given function with tokens provided as arguments and passed
    **kwargs.
  """

  def wrapped_function(string, line, tokens):
    """Wrapped function on tokens.

    It neglects the parsed string and the number of the line. Parsed tokens
    are passed to the function as positional arguments. It is useful when we
    want to pass a constructor depending on the parsed tokens as a parse action
    to a parser e.g.:
        integer_parser.setParseAction(action(int))
    Additionally **kwargs of the surrounding functions are passed (see example
    int a description of the surrounding function).

    Args:
      string: a string representing a parsed text.
      line: an int representing parsed line number.
      tokens: a pyparsing.ParseResults object containing the parsed tokens.

    Returns:
      A result of the function on parsed tokens and **kwargs of the surrounding
      function.
    """

    _ = string
    _ = line
    return function(*tokens.asList(), **kwargs)

  return wrapped_function
