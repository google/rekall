"""A module providing an Enum with state property (used for serialization)."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import enum


class Enum(enum.Enum):

  @property
  def state(self):
    return dict(value=self.value)
