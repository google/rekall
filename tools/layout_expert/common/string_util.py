"""A module containing common string operations."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import re


def camel_case_to_lower_underscore(name):
  # Taken from StackOverflow.
  s1 = re.sub('([^_])([A-Z][a-z]+)', r'\1_\2', name)
  return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def attribute_name_match(name1, name2):
  name1 = _drop_starting_and_ending_double_underscores(name1)
  name2 = _drop_starting_and_ending_double_underscores(name2)
  return name1 == name2


def _drop_starting_and_ending_double_underscores(name):
  if name.startswith('__'):
    name = name[2:]
  if name.endswith('__'):
    name = name[:-2]
  return name
