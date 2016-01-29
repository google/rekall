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


from layout_expert.c_ast import c_ast_test
from layout_expert.preprocessing_visitors import macro_expander
from layout_expert.preprocessing_visitors import macro_expression_evaluator_visitor
from layout_expert.preprocessing_visitors import preprocessing_visitor
from layout_expert.preprocessing_parser import preprocessing_parser


class MacroExpressionParserTest(c_ast_test.CASTTestCase):
    def setUp(self):
        self.macros = preprocessing_parser.Macros()
        self.parser = preprocessing_parser.PreprocessingParser()
        self.visitor = preprocessing_visitor.PreprocessingVisitor(self.macros)
        self.macro_expander = macro_expander.MacroParser(
            self.macros, eval_mode=True)

    def test_simple_tokenization(self):
        parsed_pre_ast = self.parser.parse("""
    #define BAZ    1024
    #define BAR(x, y) ((x) << 12)
    #define FOO(x) (BAR(1 + x, 3) + x + BAZ)
    """)

        # Learn about the macros defined above.
        self.visitor.preprocess(parsed_pre_ast)

        # Now expand the following:
        actual = self.macro_expander.expand(
            "hello world - FOO(12) + UNKNWON(2) + 23")

        # Should expand the FOO() macro but not the UNKNWON macro.
        self.assertEqualWhitespace(
            actual,
            u'hello world - (((1 + 12) << 12) + 12 + 1024) + UNKNWON(2) + 23')

    def test_parse_define_object_with_string_concatenation(self):
        source = '#define foo(bar, baz) bar ## baz'
        parsed_pre_ast = self.parser.parse(source)
        self.visitor.preprocess(parsed_pre_ast)

        actual = self.macro_expander.expand("hello foo(1, 2)")
        self.assertEqualWhitespace(actual, "hello 12")

    def test_defined_function(self):
        self.macro_expander.eval_mode = True
        source = """
    #define foo
    #define _LINUX_BITOPS_H
    """
        parsed_pre_ast = self.parser.parse(source)
        self.visitor.preprocess(parsed_pre_ast)

        actual = self.macro_expander.expand(" defined(foo)")
        self.assertEqualWhitespace(actual, "1")

        actual = self.macro_expander.expand(" defined (foo)")
        self.assertEqualWhitespace(actual, "1")

        actual = self.macro_expander.expand(" defined foo ")
        self.assertEqualWhitespace(actual, "1")

        actual = self.macro_expander.expand("!defined(_LINUX_BITOPS_H)")
        self.assertEqualWhitespace(actual, "!1")

    def test_non_existant_defined(self):
        actual = self.macro_expander.expand(" defined(fadsdasdas) ")
        self.assertEqualWhitespace(actual, "0")

    def test_repeated_expansion(self):
        source = """
    #define __GNUC__ 4
    #define __GNUC_MINOR__ 8
    #define __GNUC_PATCHLEVEL__ 4
    #define GCC_VERSION (__GNUC__*10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
    """
        parsed_pre_ast = self.parser.parse(source)
        self.visitor.preprocess(parsed_pre_ast)

        actual = self.macro_expander.expand(" GCC_VERSION < 30200 ")
        self.assertEqualWhitespace(
            actual, "( 4 * 10000 +  8 *  100 +  4 ) <  30200")

    def test_self_referential_expansion(self):
        """Macros are allowed to refer to themselves.

        But this stops recursive expansion.
        https://gcc.gnu.org/onlinedocs/cpp/Self-Referential-Macros.html
        """
        source = """
    #define __kernel_old_uid_t __kernel_old_uid_t
    """
        parsed_pre_ast = self.parser.parse(source)
        self.visitor.preprocess(parsed_pre_ast)

        code = "typedef unsigned short __kernel_old_uid_t ;"
        actual = self.macro_expander.expand(code)
        # No change.
        self.assertEqualWhitespace(actual, code)

    def test_expansion(self):
        source = """
    #define __ALIGN_MASK(x, mask)   (((x)+(mask))&~(mask))
    #define PAGE_FRAG_CACHE_MAX_SIZE  __ALIGN_MASK(32768, ~PAGE_MASK)
    #define PAGE_MASK  (~(PAGE_SIZE-1))
    #define PAGE_SIZE  (_AC(1,UL) << PAGE_SHIFT)
    #define PAGE_SHIFT  12
    #define __AC(X,Y)       (X##Y)
    #define _AC(X,Y)        __AC(X,Y)
    """
        parsed_pre_ast = self.parser.parse(source)
        self.visitor.preprocess(parsed_pre_ast)

        code = "PAGE_FRAG_CACHE_MAX_SIZE"
        actual = self.macro_expander.expand(code)
        self.assertEqualWhitespace(
            actual,
            "(((32768) +(~(~(((1UL) <<12) -1)))) &~(~(~(((1UL) <<12) -1))))")

    def test_foo(self):
        source = """
    #define __STDC_VERSION__  201112L
    """
        parsed_pre_ast = self.parser.parse(source)
        self.visitor.preprocess(parsed_pre_ast)

        code = ("!defined(__STRICT_ANSI__) || __STDC_VERSION__ + 0 >= 199900L "
                "|| defined(__GXX_EXPERIMENTAL_CXX0X__)")
        actual = self.macro_expander.expand(code)
        expected = '!0||201112L+0>=199900L||0'
        self.assertEqualWhitespace(actual, expected)

    def test_object_like_expansion(self):
        """Object like macros with no value must expand to something true.

        Otherwise they may result in an illegal expression.
        https://gcc.gnu.org/onlinedocs/cpp/Defined.html
        """
        self.macro_expander.eval_mode = True
        source = """
    #define FOO
    """
        parsed_pre_ast = self.parser.parse(source)
        self.visitor.preprocess(parsed_pre_ast)

        code = ("defined(FOO) && FOO > 10")
        actual = self.macro_expander.expand(code)
        expected = '1 && 1 > 10'
        self.assertEqualWhitespace(actual, expected)

    def test_config_enabled(self):
        """Test IS_MODULE/IS_BUILTIN/IS_ENABLED.

        These macros use complex interpolation tricks to test for things being a
        module or built in. This is a very good test of the macro expander to
        make sure we cover all the edge cases.

        """
        source = """
    #define __ARG_PLACEHOLDER_1 0,
    #define config_enabled(cfg) _config_enabled(cfg)
    #define _config_enabled(value) __config_enabled(__ARG_PLACEHOLDER_##value)
    #define __config_enabled(arg1_or_junk) ___config_enabled(arg1_or_junk 1, 0)
    #define ___config_enabled(__ignored, val, ...) val

    #define IS_BUILTIN(option) config_enabled(option)
    #define IS_MODULE(option) config_enabled(option##_MODULE)

    #define CONFIG_X86_MSR_MODULE 1
    #define CONFIG_FOOBAR 1
    """
        parsed_pre_ast = self.parser.parse(source)
        self.visitor.preprocess(parsed_pre_ast)

        # Since CONFIG_X86_MSR_MODULE is defined - it is a module.
        actual = self.macro_expander.expand("IS_MODULE(CONFIG_X86_MSR)")
        self.assertEqualWhitespace(actual, "1")

        # And it is not a builtin.
        actual = self.macro_expander.expand("IS_BUILTIN(CONFIG_X86_MSR)")
        self.assertEqualWhitespace(actual, "0")

        # But CONFIG_FOOBAR is a builtin.
        actual = self.macro_expander.expand("IS_BUILTIN(CONFIG_FOOBAR)")
        self.assertEqualWhitespace(actual, "1")

    def test_typeof(self):
        source = """
    #define __round_mask(x, y) ((__typeof__(x))((y)-1))
    #define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
    #define FIXADDR_TOP (round_up(VSYSCALL_ADDR + PAGE_SIZE, 1<<PMD_SHIFT) - \
                         PAGE_SIZE)
    #define PAGE_SIZE  (_AC(1,UL) << PAGE_SHIFT)
    #define PAGE_SHIFT  12
    #define _AC(X,Y)        __AC(X,Y)
    #define __AC(X,Y)       (X##Y)
    #define PMD_SHIFT21
    #define VSYSCALL_ADDR (-10UL << 20)
    """
        parsed_pre_ast = self.parser.parse(source)
        self.visitor.preprocess(parsed_pre_ast)

        # Since CONFIG_X86_MSR_MODULE is defined - it is a module.
        actual = self.macro_expander.expand(
            "VSYSCALL_PAGE = (FIXADDR_TOP - VSYSCALL_ADDR) >> PAGE_SHIFT")
        self.assertEqualWhitespace(
            actual,
            "VSYSCALL_PAGE = (((((((- 10UL << 20) + ((1UL) << 12)) - 1) | "
            "((unsigned int) ((1 << PMD_SHIFT) - 1))) + 1) - ((1UL) << 12)) - "
            "(-10UL << 20)) >> 12")

    def test_macros_set_to_zero_expand_in_non_expression_mode(self):
        source = """
        #define CONFIG_BASE_SMALL 0
        #define RADIX_TREE_MAP_SHIFT    (CONFIG_BASE_SMALL ? 4 : 6)
        #define RADIX_TREE_MAP_SIZE     (1UL << RADIX_TREE_MAP_SHIFT)
        """
        parsed_pre_ast = self.parser.parse(source)
        self.visitor.preprocess(parsed_pre_ast)
        self.macro_expander.eval_mode = False

        actual = self.macro_expander.expand("RADIX_TREE_MAP_SIZE")
        self.assertEqualWhitespace(actual, '(1UL << (0 ? 4 : 6))')



if __name__ == '__main__':
    unittest.main()
