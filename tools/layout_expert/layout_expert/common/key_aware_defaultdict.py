"""A module provides a ,,defaultdict'' that passes the key to the factory."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


class KeyAwareDefaultDict(dict):
  """A class similar to defaultdict, but it passes the key to the factory."""

  def __init__(self, default_factory=None, *args, **kwargs):
    """Initializes a KeyAwareDefaultDict.

    Args:
      default_factory: a function from key to the default value. It is used
          when the key is missing and we try to get the corresponding value. If
          default_factory is None, then in this case KeyError is raised.
      *args: other positional arguments are like the positional arguments in
          the case of dict.
      **kwargs: other keyword arguments are like the keyword arguments in
          the case of dict.
    """
    super(KeyAwareDefaultDict, self).__init__(*args, **kwargs)
    self._default_factory = default_factory

  def __missing__(self, key):
    if not self._default_factory:
      raise KeyError(key)
    value = self._default_factory(key)
    self[key] = value
    return value
