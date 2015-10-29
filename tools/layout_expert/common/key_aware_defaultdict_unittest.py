from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest
from rekall.layout_expert.common import key_aware_defaultdict


class TestKeyAwareDefaultDict(unittest.TestCase):

  def test_missing_key_and_no_default_factory(self):
    d = key_aware_defaultdict.KeyAwareDefaultDict(
        a=42,
        b='33',
    )
    with self.assertRaises(KeyError) as context:
      _ = d['c']
    self.assertEqual(context.exception.args[0], 'c')
    expected_dict = {
        'a': 42,
        'b': '33'
    }
    self.assertEqual(d, expected_dict)

  def test_existing_key_and_no_default_factory(self):
    d = key_aware_defaultdict.KeyAwareDefaultDict(
        a=42,
        b='33',
        c='24',
    )
    actual = d['a']
    self.assertEqual(actual, 42)
    expected_dict = {
        'a': 42,
        'b': '33',
        'c': '24'
    }
    self.assertEqual(d, expected_dict)

  def test_missing_key_with_default_factory(self):
    d = key_aware_defaultdict.KeyAwareDefaultDict(
        lambda key: 'the key is ' + key + ' !',
        c=33,
    )
    actual = d['42']
    self.assertEqual(actual, 'the key is 42 !')
    expected_dict = {
        '42': 'the key is 42 !',
        'c': 33,
    }
    self.assertEqual(d, expected_dict)

  def test_existing_key_with_default_factory(self):
    d = key_aware_defaultdict.KeyAwareDefaultDict(
        lambda key: 'the key is ' + key,
        c=33,
        d=42,
    )
    actual = d['c']
    self.assertEqual(actual, 33)
    expected_dict = {
        'c': 33,
        'd': 42,
    }
    self.assertEqual(d, expected_dict)

  def test_insert_missing_key_and_no_default_factory(self):
    d = key_aware_defaultdict.KeyAwareDefaultDict(
        a=42,
        b='33',
    )
    d['c'] = 24
    expected = {
        'a': 42,
        'b': '33',
        'c': 24,
    }
    self.assertEqual(d, expected)

  def test_insert_existing_key_and_no_default_factory(self):
    d = key_aware_defaultdict.KeyAwareDefaultDict(
        a=42,
        b='33',
        c='24',
    )
    d['a'] = 'b'
    expected = {
        'a': 'b',
        'b': '33',
        'c': '24',
    }
    self.assertEqual(d, expected)

  def test_insert_missing_key_with_default_factory(self):
    d = key_aware_defaultdict.KeyAwareDefaultDict(
        lambda key: 'the key is ' + key,
        c=33,
    )
    d['42'] = 'e'
    expected = {
        '42': 'e',
        'c': 33,
    }
    self.assertEqual(d, expected)

  def test_insert_existing_key_with_default_factory(self):
    d = key_aware_defaultdict.KeyAwareDefaultDict(
        lambda key: 'the key is ' + key,
        c=33,
        d=42,
    )
    d['c'] = 'a'
    expected = {
        'c': 'a',
        'd': 42,
    }
    self.assertEqual(d, expected)


if __name__ == '__main__':
  unittest.main()
