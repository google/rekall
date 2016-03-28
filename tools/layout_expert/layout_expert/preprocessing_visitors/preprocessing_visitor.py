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

"""A module containing a Preprocessing Visitor for Pre-AST trees."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from layout_expert.c_ast import c_ast
from layout_expert.c_ast import pre_ast
from layout_expert.parsers import expression_parser
from layout_expert.preprocessing_visitors import macro_expander
from layout_expert.preprocessing_visitors import macro_expression_evaluator_visitor


class PreprocessingVisitor(object):
    """A class representing a Preprocessing Visitor for Pre-AST trees.

    Run this visitor on the PreAST to populate the Macros() manager and expand
    the TEXT nodes.
    """

    def __init__(self, macros, progress_cb=None):
        self.progress_cb = progress_cb or (lambda *_: None)
        self._macros = macros
        # Ensure that the macro expander produces output suitable to evaluation.
        self._macro_expander = macro_expander.MacroParser(
            macros, progress_cb=None)
        self._expression_parser = expression_parser.ExpressionParser()
        self._expression_evaluator = (
            macro_expression_evaluator_visitor.MacroExpressionEvaluatorVisitor(
                macros))

    def preprocess(self, node):
        return node.accept(self)

    def visit_file(self, file_):
        content = file_.content.accept(self)
        return pre_ast.File(content)

    def visit_include(self, include):
        self.progress_cb("Processing include %s", include.absolute_path)
        if include.content:
            return self.preprocess(include.content)

    def visit_pragma(self, pragma):
        return pragma

    def visit_error(self, error):
        raise PreprocessingException(error)

    def visit_define_object_like(self, define_object_like):
        name = define_object_like.name
        self._macros.add_object_likes(**{name: define_object_like})

    def visit_define_function_like(self, define_function_like):
        name = define_function_like.name
        self._macros.add_function_like(name, define_function_like)

    def visit_undef(self, undef):
        self._macros.remove_symbol(undef.name)

    def visit_if(self, if_):
        # Select which of the conditional_blocks are valid. Choose the first one
        # which evaluates to non zero.
        for block in if_.conditional_blocks:
            # First expand all the macros in the condition.
            conditional_expression = self._macro_expander.expand(
                block.conditional_expression, eval_mode=True)

            expression = self._expression_parser.parse(conditional_expression)

            try:
                # Choose the block if the evaluator returns truth.
                if self._expression_evaluator.evaluate(expression):
                    return block.accept(self)
            except c_ast.IrreducibleFunction as e:
                import pdb
                pdb.post_mortem()
                print("Unable to evaluate conditional_expression: %s"
                      % block.conditional_expression)
                print("Expanded to: %s"
                      % conditional_expression)
                print("Error: %s" % e)
                import pdb
                pdb.set_trace()

    def visit_conditional_block(self, block):
        # The condition was already evaluated in the If block.
        return self.visit_composite_block(block)

    def visit_composite_block(self, composite_block):
        preprocessed_content = []
        for element in composite_block.content:
            maybe_preprocessed_element = element.accept(self)
            if maybe_preprocessed_element:
                preprocessed_content.append(maybe_preprocessed_element)
        return pre_ast.CompositeBlock(preprocessed_content)

    def visit_text_block(self, text_block):
        expanded_content = self._macro_expander.expand(
            text_block.content, eval_mode=False)
        return pre_ast.TextBlock(expanded_content)


class PreprocessingException(Exception):
    pass
