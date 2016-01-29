
from ._version import get_versions
__version__ = get_versions()['version']
del get_versions

import pyparsing

# Fix bugs in pyparsing.

if getattr(pyparsing, "disablePackrat", None) is None:
  def disablePackrat():
    # pylint: disable=protected-access
    pyparsing.ParserElement._packratEnabled = False
    pyparsing.ParserElement._parse = pyparsing.ParserElement._parseNoCache
    # pylint: enable=protected-access

  pyparsing.ParserElement.disablePackrat = staticmethod(disablePackrat)
