from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest
from rekall.layout_expert.common import string_util


class TestCamelCaseToLowerUnderscore(unittest.TestCase):

  def test_with_empty_string(self):
    actual = string_util.camel_case_to_lower_underscore('')
    self.assertEqual(actual, '')

  def test_with_upper_camel_case(self):
    actual = string_util.camel_case_to_lower_underscore('UpperCamelCase')
    self.assertEqual(actual, 'upper_camel_case')

  def test_with_upper_camel_case_with_additional_underscore(self):
    actual = string_util.camel_case_to_lower_underscore('Upper_CamelCase')
    self.assertEqual(actual, 'upper_camel_case')

  def test_with_upper_camel_case_with_additional_underscore_after_one_letter(
      self,
  ):
    actual = string_util.camel_case_to_lower_underscore('U_CamelCase')
    self.assertEqual(actual, 'u_camel_case')

  def test_with_upper_camel_case_with_initial_underscore(self):
    actual = string_util.camel_case_to_lower_underscore('_UpperCamelCase')
    self.assertEqual(actual, '_upper_camel_case')

  def test_with_lower_camel_case(self):
    actual = string_util.camel_case_to_lower_underscore('lowerCamelCase')
    self.assertEqual(actual, 'lower_camel_case')

  def test_with_lower_camel_case_with_initial_underscore(self):
    actual = string_util.camel_case_to_lower_underscore('_lowerCamelCase')
    self.assertEqual(actual, '_lower_camel_case')

  def test_with_lower_camel_case_with_addidtional_underscore(
      self,
  ):
    actual = string_util.camel_case_to_lower_underscore('lower_CamelCase')
    self.assertEqual(actual, 'lower_camel_case')

  def test_with_lower_camel_case_with_addidtional_underscore_after_one_letter(
      self,
  ):
    actual = string_util.camel_case_to_lower_underscore('l_CamelCase')
    self.assertEqual(actual, 'l_camel_case')

  def test_with_digits_at_the_beginning(self):
    actual = string_util.camel_case_to_lower_underscore('24UpperCamelCase')
    self.assertEqual(actual, '24_upper_camel_case')

  def test_with_digits_inside(self):
    actual = string_util.camel_case_to_lower_underscore('UpperCamel42Case')
    self.assertEqual(actual, 'upper_camel42_case')

  def test_with_digits_at_the_end(self):
    actual = string_util.camel_case_to_lower_underscore('UpperCamelCase33')
    self.assertEqual(actual, 'upper_camel_case33')

  def test_with_digits_only(self):
    actual = string_util.camel_case_to_lower_underscore('42')
    self.assertEqual(actual, '42')

  def test_with_a_few_capitals_in_a_row_at_the_beginning(self):
    actual = string_util.camel_case_to_lower_underscore('UPPERCamelCase')
    self.assertEqual(actual, 'upper_camel_case')

  def test_with_a_few_capitals_in_a_row_inside(self):
    actual = string_util.camel_case_to_lower_underscore('UpperCAMELCase')
    self.assertEqual(actual, 'upper_camel_case')

  def test_with_a_few_capitals_in_a_row_at_the_end(self):
    actual = string_util.camel_case_to_lower_underscore('UpperCamelCASE')
    self.assertEqual(actual, 'upper_camel_case')

  def test_with_digits_and_a_few_capitals_in_a_row(self):
    actual = string_util.camel_case_to_lower_underscore('Upper33CAMELCase')
    self.assertEqual(actual, 'upper33_camel_case')

  def test_with_capitals_ony(self):
    actual = string_util.camel_case_to_lower_underscore('UPPER')
    self.assertEqual(actual, 'upper')


class TestAttributeNameMatch(unittest.TestCase):

  def test_with_variants_of_the_same_name(self):
    variants = (
        'some_name',
        '__some_name',
        'some_name__',
        '__some_name__',
    )
    for variant1 in variants:
      for variant2 in variants:
        self.assertTrue(string_util.attribute_name_match(variant1, variant2))

  def test_with_variants_of_different_names(self):
    variants1 = (
        'some_name_1',
        '__some_name_1',
        'some_name_1__',
        '__some_name_1__',
    )
    variants2 = (
        'some_name_2',
        '__some_name_2',
        'some_name_2__',
        '__some_name_2__',
    )
    for variant1 in variants1:
      for variant2 in variants2:
        self.assertFalse(string_util.attribute_name_match(variant1, variant2))

if __name__ == '__main__':
  unittest.main()
