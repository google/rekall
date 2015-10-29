from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest
from rekall.layout_expert.common import enum


class TestEnumWithState(unittest.TestCase):

  class MockEnum(enum.Enum):
    FOO = 42
    BAR = 33
    BAZ = 24

  def test_state(self):
    self.assertEqual(self.MockEnum.FOO.state, dict(value=42))
    self.assertEqual(self.MockEnum.BAR.state, dict(value=33))
    self.assertEqual(self.MockEnum.BAZ.state, dict(value=24))

if __name__ == '__main__':
  unittest.main()
