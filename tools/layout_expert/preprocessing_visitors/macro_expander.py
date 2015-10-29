"""A module containing Macro Expander for macro substitution in strings.

It is used by Macro Expression Evaluator Visitor.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pyparsing

pyparsing.ParserElement.enablePackrat()  # speed hack


class MacroExpander(object):

  def __init__(self, expression_parser, expression_evaluator):
    self._expression = expression_parser
    self._expression_evaluator = expression_evaluator

  def expand(self, source):
    expanded = []
    processed_chars = 0
    for tokens, start, end in self._expression.scanString(source):
      evaluated = self._expression_evaluator.evaluate(tokens[0])
      expanded.append(source[processed_chars:start])
      expanded.append(str(evaluated))
      processed_chars = end
    expanded.append(source[processed_chars:])
    return ' '.join(expanded)



