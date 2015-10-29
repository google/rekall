"""A module containing a common base class for data holder objects.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


class DataContainer(object):
  """A common base class for data holder objects.

  Provides equality checks and string representation.
  """
  # This is the dict that holds the state variables.
  state = None

  def __init__(self, **kwargs):
    self.state = kwargs

  def __getattr__(self, item):
    try:
      return self.state[item]
    except KeyError:
      raise AttributeError(item)

  def __setattr__(self, key, value):
    try:
      super(DataContainer, self).__getattribute__(key)
      super(DataContainer, self).__setattr__(key, value)
    except AttributeError:
      self.state[key] = value

  def __eq__(self, other):
    if type(other) is not type(self):
      return False
    return self.state == other.state

  def __ne__(self, other):
    return not self.__eq__(other)

  def __str__(self):
    str_key_values = []
    for key, value in self.state.iteritems():
      str_key_value = '%s: %s' % (key, value)
      str_key_values.append(str_key_value)
    return self.__class__.__name__ + '{' + ', '.join(str_key_values) + '}'
