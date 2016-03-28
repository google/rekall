#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2016 Google Inc. All Rights Reserved.
#
# Authors:
# Arkadiusz Socała <as277575@mimuw.edu.pl>
# Michael Cohen <scudette@google.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


import unittest
from layout_expert.c_ast import c_ast
from layout_expert.c_ast import c_ast_test
from layout_expert.parsers import trimming_parser


class TestTrimmingParser(c_ast_test.CASTTestCase):

    def test_function_typedef(self):
        source = """
        struct work_struct;
        typedef void (*work_func_t)(struct work_struct *work);
        void delayed_work_timer_fn(unsigned long __data);
        """
        actual = trimming_parser.build_snippets(source)
        self.assertTrue("work_func_t" in actual)

    def test_pointer_typedef(self):
        source = """
        typedef __signalfn_t  * __sighandler_t ;
        """
        actual = trimming_parser.build_snippets(source)
        self.assertTrue("__sighandler_t" in actual)

    def test_anonymous_enum(self):
        source = """
        struct work_struct work;
}; enum {
        WQ_UNBOUND              = 1 << 1,
        WQ_FREEZABLE            = 1 << 2,
        WQ_MEM_RECLAIM          = 1 << 3,
        WQ_HIGHPRI              = 1 << 4,
        WQ_CPU_INTENSIVE        = 1 << 5,
        WQ_SYSFS                = 1 << 6,


        WQ_POWER_EFFICIENT      = 1 << 7,

        __WQ_DRAINING           = 1 << 16,
        __WQ_ORDERED            = 1 << 17,

        WQ_MAX_ACTIVE           = 512,
        WQ_MAX_UNBOUND_PER_CPU  = 4,
        WQ_DFL_ACTIVE           = WQ_MAX_ACTIVE / 2,
}; extern struct workqueue_struct *system_wq;
extern struct workqueue_struct *system_highpri_wq;
extern struct workqueue_struct
        """
        actual = trimming_parser.build_snippets(source)
        # Make sure $VARS is filled in with the global values.
        self.assertEqual(len(actual["$VARS"]), 12)
        self.assertEqual(actual["$VARS"]["WQ_POWER_EFFICIENT"],
                         c_ast.CFunctionCall(
                             function_name="<<",
                             arguments=[
                                 c_ast.CNumber(1),
                                 c_ast.CNumber(7)
                             ]
                         ))

        # Ensure that a new anonymous enum is added to the snippets.
        self.assertEqual(set(actual.keys()),
                         set(['enum __unknown_enum_1', '$VARS']))


if __name__ == '__main__':
    unittest.main()
