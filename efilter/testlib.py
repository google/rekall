# EFILTER Forensic Query Language
#
# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
EFILTER test helpers.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import unittest

from efilter import expression
from efilter import protocol
from efilter import query


class EngineTestCase(unittest.TestCase):
    def _guess_syntax(self, source, default=None):
        if default:
            return default

        if isinstance(source, expression.Expression):
            return "expression"

        if isinstance(source, basestring):
            return "dotty"

        if isinstance(source, tuple):
            return "lisp"

        raise ValueError("Cannot guess syntax of %r." % source)

    def parse_query(self, source, source_syntax=None, app_delegate=None):
        source_syntax = self._guess_syntax(source, source_syntax)
        return query.Query(source, syntax=source_syntax,
                           application_delegate=app_delegate)

    def get_engine_result(self, engine, source, source_syntax=None,
                          app_delegate=None, **kwargs):
        q = self.parse_query(source=source, source_syntax=source_syntax,
                             app_delegate=app_delegate)
        return q.run_engine(engine, **kwargs)

    # Custom assertions:

    def assertEngineResult(self, engine, source, expected, source_syntax=None,
                           assertion=None, app_delegate=None, **kwargs):
        result = self.get_engine_result(
            engine, source, source_syntax, app_delegate, **kwargs)
        if callable(assertion):
            assertion(expected, result)
        else:
            self.assertEqual(expected, result)

    def assertTransform(self, engine, original, expected, original_syntax=None,
                        expected_syntax=None, app_delegate=None, **kwargs):
        orig_query = self.parse_query(original, original_syntax, app_delegate)
        actual = orig_query.run_engine(engine, **kwargs)
        baseline = self.parse_query(expected, expected_syntax, app_delegate)

        self.assertEqual(actual, baseline)

    def assertIsa(self, t, p):
        self.assertTrue(protocol.isa(t, p))
