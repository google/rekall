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

"""A module containing a parser for unpreprocessed C headers."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pyparsing

from layout_expert.builtins import functions
from layout_expert.builtins import gcc_constants

from layout_expert.c_ast import pre_ast
from layout_expert.lib import parsers


STANDARD_FUNCTION_LIKE = [
    ("__typeof__", ["x"], "unsigned int"),
]

# A list of function_likes that we define internally.
EXCLUDED_FUNCTION_LIKE = [
    "offsetof", "container_of",
]


class Sanitizer(object):
    """Clean up source by removing problematic idioms.

    Developing a more complete parser to deal with the fine edge cases is not
    worth it. We transform certain rare idioms to more standard idioms.
    """
    transforms = [
        ("gcc_header(__GNUC__)", "<linux/compiler-gcc4.h>"),
        # We dont care about consts.
        ("const ", ""),
    ]

    def transform(self, text):
        for source, replacement in self.transforms:
            text = text.replace(source, replacement)

        return text


class Macros(object):
    """A class to manage all the macros we know about."""

    def __init__(self, config_flags=None):
        self.config_flags = config_flags or {}
        self.object_likes = {}

        # Macro function_likes.
        self.function_likes = {}

        # Built in functions.
        self.functions = {}

        # Defined is a built in keyword.
        self.symbols = set(["defined"] + EXCLUDED_FUNCTION_LIKE)

        # Initialize the MacroManager.
        self.add_object_likes(**self._get_object_like_macros())
        self.add_functions(**functions.get_arithmetic_functions())

        for name, args, repl in STANDARD_FUNCTION_LIKE:
            self.add_function_like(
                name, pre_ast.DefineFunctionLike(name, args, repl))

    def _get_object_like_macros(self):
        """A function that produces object like macros from config flags."""
        # Add object like intrinsics from gcc.
        result = gcc_constants.get_x86_64_kernel_compile_object_likes()

        # Append config vars.
        for flag, value in self.config_flags.iteritems():
            result[flag] = pre_ast.DefineObjectLike(
                name=flag,
                # Macros replacements are always strings - even for CNumber()
                # config options.
                replacement=str(value.value),
            )

        return result

    def add_object_likes(self, **object_likes):
        self.object_likes.update(object_likes)
        self.symbols.update(object_likes)

    def add_function_like(self, name, function_like):
        # Do not allow new macros to override old ones.
        if name not in EXCLUDED_FUNCTION_LIKE:
            self.function_likes[name] = function_like
            self.symbols.add(name)

    def add_functions(self, **funcs):
        self.functions.update(funcs)
        self.symbols.update(funcs)

    def remove_symbol(self, name):
        if name not in EXCLUDED_FUNCTION_LIKE:
            self.object_likes.pop(name, None)
            self.function_likes.pop(name, None)
            self.functions.pop(name, None)
            self.symbols.discard(name)


_SHARP = pyparsing.Literal('#')
_DOUBLE_QUOTE = pyparsing.Literal('"')
_OPEN_PARENTHESES = pyparsing.Literal('(')
_CLOSE_PARENTHESES = pyparsing.Literal(')')
_OPEN_ANGLE_BRACKETS = pyparsing.Literal('<')
_CLOSE_ANGLE_BRACKETS = pyparsing.Literal('>')
_EQUALS = pyparsing.Literal('=')
_COMA = pyparsing.Literal(',')

_IDENTIFIER = pyparsing.Word(pyparsing.alphanums + '_')
_INCLUDE = pyparsing.Keyword('include')
_PRAGMA = pyparsing.Keyword('pragma')
_ERROR = pyparsing.Keyword('error')
_DEFINE = pyparsing.Keyword('define')
_UNDEF = pyparsing.Keyword('undef')
_IF = pyparsing.Keyword('if')
_IFDEF = pyparsing.Keyword('ifdef')
_IFNDEF = pyparsing.Keyword('ifndef')
_ELIF = pyparsing.Keyword('elif')
_ELSE = pyparsing.Keyword('else')
_ENDIF = pyparsing.Keyword('endif')

_PREPROCESSOR_KEYWORD = (
    _INCLUDE
    | _PRAGMA
    | _ERROR
    | _DEFINE
    | _UNDEF
    | _IF
    | _IFDEF
    | _IFNDEF
    | _ELIF
    | _ELSE
    | _ENDIF
)


class PreprocessingParser(object):
    """Preprocess header files and build a preprocessor AST."""

    def __init__(self):
        pyparsing.ParserElement.disablePackrat()
        pyparsing.ParserElement.resetCache()

        self._define_parser = (self._define_function_like()
                               | self._define_object_like())

        # Current level of nesting.
        self.stack = []

    def _define_object_like(self):
        return (
            _IDENTIFIER.setResultsName("name")
            + pyparsing.restOfLine.setResultsName("replacement")
        ).setParseAction(self._add_object_like)

    def _add_object_like(self, tok):
        self.current_node.content.append(pre_ast.DefineObjectLike(
            name=tok.name, replacement=tok.replacement.strip()))

    def _define_function_like(self):
        return (
            (_IDENTIFIER.setResultsName("name")
             + _OPEN_PARENTHESES).leaveWhitespace()
            + pyparsing.Optional(
                pyparsing.delimitedList(
                    _IDENTIFIER
                    | pyparsing.Literal("...")  # vararg macro.
                )).setResultsName("arguments")
            + _CLOSE_PARENTHESES
            + pyparsing.restOfLine.setResultsName("replacement")
        ).setParseAction(self._add_function_like)

    def _add_function_like(self, tok):
        self.current_node.content.append(pre_ast.DefineFunctionLike(
            name=tok.name, arguments=tok.arguments.asList(),
            replacement=tok.replacement.strip()))

    @property
    def current_node(self):
        return self.stack[-1]

    def push_node(self, node):
        self.stack.append(node)

    def pop_node(self):
        return self.stack.pop(-1)

    def parse(self, source):
        line_continuation = pyparsing.Literal('\\\n')
        ignorable = (
            line_continuation
            | pyparsing.cppStyleComment.addParseAction(
                pyparsing.ParserElement.resetCache)
            # Removed for now because it is too expensive at this point. We can
            # eliminate those later in the trimming phase.
            # | parser.extern_field()
            | self.static_function()
        ).suppress()
        source = ignorable.transformString(source)
        source = Sanitizer().transform(source)

        # Start parsing: Top level node will be a pre_ast.File
        self.push_node(pre_ast.CompositeBlock(content=[]))
        last_block_end = 0

        scanner = self._preprocessor_directive().parseWithTabs()
        for tokens, start, end in scanner.scanString(source):
            text = source[last_block_end:start].strip()
            if text:
                # We skipped over a text block - push it on the current node.
                self.current_node.content.append(pre_ast.TextBlock(text))

            last_block_end = end

            # Now process the different directives.
            directive, rest_of_line = tokens
            if directive == "include":
                self._process_include(rest_of_line)

            # Im not really sure what #pragma is supposed to do here.
            elif directive == "pragma":
                self.current_node.content.append(
                    pre_ast.Pragma(rest_of_line))

            elif directive == "error":
                self.current_node.content.append(
                    pre_ast.Error(rest_of_line))

            elif directive == "define":
                self._define_parser.parseString(rest_of_line)

            elif directive == "undef":
                self.current_node.content.append(
                    pre_ast.Undef(rest_of_line))

            elif directive == "if":
                self._add_conditional_block(rest_of_line)

            elif directive == "ifdef":
                self._add_conditional_block("defined(%s)" % rest_of_line)

            elif directive == "ifndef":
                self._add_conditional_block("!defined(%s)" % rest_of_line)

            elif directive == "else":
                self._add_elif_block("1")

            elif directive == "elif":
                self._add_elif_block(rest_of_line)

            elif directive == "endif":
                # Pop the stack.
                self.pop_node()  # ConditionalBlock
                self.pop_node()  # If block.

        # Last text node.
        text = source[last_block_end:].strip()
        if text:
            self.current_node.content.append(pre_ast.TextBlock(text))

        return self.pop_node()

    def static_function(self):
        return (
            (pyparsing.Keyword("static") | pyparsing.Keyword("inline"))
            + pyparsing.OneOrMore(pyparsing.Word(pyparsing.alphanums + "_*&"))
            + parsers.anything_in_parentheses()
            + parsers.anything_in_curly()
        ).suppress()

    def _process_include(self, rest_of_line):
        # Strip quotes
        path = rest_of_line[1:-1]
        quote = rest_of_line[0]
        self.current_node.content.append(
            pre_ast.Include(path=path, quotes_type=quote)
        )

    def _add_conditional_block(self, expression):
        conditional_block = pre_ast.ConditionalBlock(
            conditional_expression=expression,
            content=[])

        if_block = pre_ast.If([conditional_block])

        self.current_node.content.append(if_block)
        self.push_node(if_block)
        self.push_node(conditional_block)

    def _add_elif_block(self, expression):
        # An else clause is just a ConditionalBlock with a true expression.
        self.pop_node()  # Pop the ConditionalBlock

        # Make a new conditional node.
        conditional_block = pre_ast.ConditionalBlock(
            conditional_expression=expression,
            content=[])

        # Add the new conditional_block to the if block.
        self.current_node.conditional_blocks.append(conditional_block)

        # Now add nodes to that ConditionalBlock.
        self.push_node(conditional_block)

    def _preprocessor_directive(self):
        return (_SHARP.suppress()
                + _PREPROCESSOR_KEYWORD
                + pyparsing.SkipTo(pyparsing.lineEnd))
