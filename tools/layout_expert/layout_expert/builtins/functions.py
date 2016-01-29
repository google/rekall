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

"""Definitions of compiler builtin functions."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import operator
from layout_expert.c_ast import c_ast


def _lazy_and(evaluator, x, y, **_):
    if not evaluator(x):
        return 0

    if not evaluator(y):
        return 0

    return 1


def _lazy_or(evaluator, x, y, **_):
    if evaluator(x):
        return 1

    if evaluator(y):
        return 1

    return 0


def _lazy_ternary(evaluator, x, y, z, **_):
    if evaluator(x):
        return evaluator(y)
    return evaluator(z)

def _cast(evaluator, left, right, **__):
    # Not sure what to do with a cast at the moment?
    _ = left
    return evaluator(right)


def operator_for_ast(operator_):
    """Wraps a function for AST.

    Assume it works on CNumber objects.
    """
    def wrapped_function(evaluator, left, right=None, **_):
        # Support unary operators.
        left = evaluator(left)
        if right is None:
            return operator_(left)

        # Binary operators.
        right = evaluator(right)
        return operator_(left, right)

    return wrapped_function


ARITHMETIC_FUNCTIONS = {
    '+': lambda *args: args[0] + args[1] if len(args) > 1 else args[0],
    '-': lambda *args: args[0] - args[1] if len(args) > 1 else -args[0],
    '!': operator.not_,
    '~': operator.inv,
    '*': operator.mul,
    '/': operator.floordiv,
    '%': operator.mod,
    '<<': operator.lshift,
    '>>': operator.rshift,
    '<': operator.lt,
    '>': operator.gt,
    '<=': operator.le,
    '>=': operator.ge,
    '==': operator.eq,
    '!=': operator.ne,
    '&': operator.and_,
    '^': operator.xor,
    '|': operator.or_,
}


def sizeof(evaluator=None, name=None, type_manager=None):
    """This is the implementation of the sizeof function.

    We get called whenever the expression evaluator is asked to evaluate an
    expression with a sizeof() in it. This might happen recursively. For
    example:

struct xregs_state {
  struct fxregs_state             i387;
  struct xstate_header            header;
  u8                              __reserved [(sizeof(struct ymmh_struct) +
                                               sizeof(struct lwp_struct) +
                                               sizeof(struct mpx_struct))];
} __attribute__ ((packed, aligned (64)));

    """
    _ = evaluator
    name = str(name)

    # To know the size of a type we need to ask the type manager to produce the
    # layout for this type.
    try:
        type_layout = type_manager.get_type_layout(name)
        return c_ast.CNumber(type_layout.bit_size // 8)
    except (AttributeError, KeyError):
        raise c_ast.IrreducibleFunction("Unsupported sizeof")


def get_builtins():
    return dict(
        sizeof=sizeof,
    )


def get_arithmetic_functions():
    result = {}
    for name, func in ARITHMETIC_FUNCTIONS.iteritems():
        result[name] = operator_for_ast(func)

    # Now add the two lazy operators:
    result["&&"] = _lazy_and
    result["||"] = _lazy_or
    result["?:"] = _lazy_ternary

    result["()"] = _cast

    return result
