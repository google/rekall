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

"""Classes representing nodes of AST before preprocessing."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from layout_expert.c_ast import visitor_mixin
from layout_expert.common import data_container
from layout_expert.serialization import json_serialization


class _PreASTNode(data_container.DataContainer, visitor_mixin.VisitorMixin):
    """A base clas for pre-AST nodes."""


class File(_PreASTNode):

    def __init__(self, content):
        super(File, self).__init__()
        self.content = content


class Include(_PreASTNode):

    def __init__(self, path, quotes_type, absolute_path=None, content=None):
        super(Include, self).__init__()
        self.path = path
        self.quotes_type = quotes_type
        self.absolute_path = absolute_path
        self.content = content


class Pragma(_PreASTNode):

    def __init__(self, argument_string):
        super(Pragma, self).__init__()
        self.argument_string = argument_string


class Error(_PreASTNode):

    def __init__(self, message):
        super(Error, self).__init__()
        self.message = message


class DefineObjectLike(_PreASTNode):
    """A class that represents an object-like definition.

    For example:
    #define foo
    """

    def __init__(self, name, replacement):
        super(DefineObjectLike, self).__init__()
        self.name = name
        self.replacement = replacement


class DefineFunctionLike(_PreASTNode):
    """A class that represents a function-like definition.

    For exmaple:
    #define foo()
    """

    def __init__(self, name, arguments, replacement):
        super(DefineFunctionLike, self).__init__()
        self.name = name
        self.arguments = arguments
        self.replacement = replacement


class MacroExpression(_PreASTNode):
    """Represent an expression to be expanded by the preprocessor.

    Actually evaluating the expression happens upon macro substitution. We just
    copy the expression verbatim here.
    """

    def __init__(self, expression_string):
        super(MacroExpression, self).__init__()
        self.expression_string = expression_string


class Undef(_PreASTNode):

    def __init__(self, name):
        super(Undef, self).__init__()
        self.name = name


class If(_PreASTNode):
    """A class to represent a conditional (e.g. ifdef) block."""

    def __init__(self, conditional_blocks):
        """Initializes an If object.

        Args:
          conditional_blocks: A list of ConditionalBlock objects.

        Note that the child nodes are of types ConditionalBlock and
        CompositeBlock (the last one in the case of else clause).

        """
        super(If, self).__init__()
        self.conditional_blocks = conditional_blocks


class ConditionalBlock(_PreASTNode):
    """A class representing a pair of conditional expression and content.

    This is an internal node to represent the condition inside of an If block.
    """

    def __init__(self, conditional_expression, content):
        """Initiates a ConditionalBlock object.

        Args:
          conditional_expression: an expression representing a logic
            condition
          content: a content corresponding to this condition.
        """
        super(ConditionalBlock, self).__init__()
        self.conditional_expression = conditional_expression
        self.content = content


class CompositeBlock(_PreASTNode):

    def __init__(self, content=None):
        super(CompositeBlock, self).__init__()
        self.content = content or []

    def __str__(self):
        return ' '.join(map(str, self.content))


class TextBlock(_PreASTNode):

    def __init__(self, content):
        super(TextBlock, self).__init__()
        self.content = content


json_serialization.DataContainerObjectRenderer.set_safe_constructors(
    File,
    Include,
    Pragma,
    Error,
    DefineObjectLike,
    DefineFunctionLike,
    Undef,
    If,
    ConditionalBlock,
    CompositeBlock,
    TextBlock,
    MacroExpression,
)
