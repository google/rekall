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

"""GCC compile time intrinsic constants."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from layout_expert.c_ast import pre_ast


def get_x86_64_kernel_compile_object_likes():
    return {
        '__STDC__': pre_ast.DefineObjectLike(
            name='__STDC__',
            replacement='1',
        ),
        '__STDC_VERSION__': pre_ast.DefineObjectLike(
            name='__STDC_VERSION__',
            replacement='201112L',
        ),
        '_XOPEN_SOURCE': pre_ast.DefineObjectLike(
            name='_XOPEN_SOURCE',
            replacement='500',
        ),
        '__GNUC__': pre_ast.DefineObjectLike(
            name='__GNUC__',
            replacement='4',
        ),
        '__GNUC_MINOR__': pre_ast.DefineObjectLike(
            name='__GNUC_MINOR__',
            replacement='8',
        ),
        '__GNUC_PATCHLEVEL__': pre_ast.DefineObjectLike(
            name='__GNUC_PATCHLEVEL__',
            replacement='4',
        ),
        '__x86_64__': pre_ast.DefineObjectLike(
            name='__x86_64__',
            replacement='1',
        ),
        '__KERNEL__': pre_ast.DefineObjectLike(
            name='__KERNEL__',
            replacement='',
        ),

        '__cplusplus': pre_ast.DefineObjectLike(
            name='__cplusplus',
            replacement='',
        ),

        '__GLIBC__': pre_ast.DefineObjectLike(
            name='__GLIBC__',
            replacement='2',
        ),

        '__GLIBC_MINOR__': pre_ast.DefineObjectLike(
            name='__GLIBC_MINOR__',
            replacement='19',
        ),

        # Derived from scripts/gcc-goto.sh
        "CC_HAVE_ASM_GOTO": pre_ast.DefineObjectLike(
            name='CC_HAVE_ASM_GOTO',
            replacement='1',
        ),
    }
