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

"""A module for evaluating expressions given as AST tree.

Used for evaluation the normal AST.

Evaluates simple expressions in pre-processed AST e.g. calculates size of
array based on size or number of other elements. For example:
int t[10 * sizeof(struct s) + 1]
"""


from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from layout_expert.c_ast import c_ast
from layout_expert.c_ast import visitor_mixin


class ExpressionEvaluatorVisitor(object):
    """A class for evaluating expressions given as AST tree."""

    def __init__(self, type_manager=None):
        self.type_manager = type_manager

    def evaluate(self, expression):
        if isinstance(expression, visitor_mixin.VisitorMixin):
            return expression.accept(self)
        return expression

    def visit_c_function_call(self, function_call):
        function = self.type_manager.functions[function_call.function_name]
        arguments = []
        for argument in function_call.arguments:
            arguments.append(argument.accept(self))
        return function(
            self.evaluate, *arguments, type_manager=self.type_manager)

    def visit_c_nested_expression(self, nested_expression):
        return self.evaluate(nested_expression.content)

    def visit_c_variable(self, variable):
        name = variable.name
        result = self.type_manager.variables.get(name)
        if result is None:
            raise c_ast.IrreducibleFunction(
                "Unable to evaluate expression since %s has no value." % name)

        # Continue to resolve the variable AST.
        return result.accept(self)

    def visit_c_number(self, number):
        return number.value

    def visit_c_literal(self, literal):
        return literal.value

    def visit_composite_block(self, block):
        # Multiwords block.
        return " ".join(str(x) for x in block.content)
