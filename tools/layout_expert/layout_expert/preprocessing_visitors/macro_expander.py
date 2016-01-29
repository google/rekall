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

"""A module containing Macro Expander for macro substitution in strings.

It is used by Macro Expression Evaluator Visitor.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

# pylint: disable=expression-not-assigned

import pyparsing
import re

IGNORE_MACROS = set("inline likely unlikely".split())


# Macro expander: Macros are expanded by first tokenizing the input then
# substituting existing macros.
_VALID_TOKEN_CHARS = pyparsing.alphanums + "_"
_TOKEN = lambda: pyparsing.Word(_VALID_TOKEN_CHARS).setName("token")
_NOT_TOKEN = lambda: pyparsing.Word("!\"#$%&\'*+-./:;<=>?@[\\]^`{|}~").setName(
    "non-token")
_TOKEN_RUN = lambda: pyparsing.OneOrMore(
    _TOKEN()
    | _NOT_TOKEN()
)
_OPEN_PARENTHESIS = lambda: pyparsing.Literal('(')
_CLOSE_PARENTHESIS = lambda: pyparsing.Literal(')')
_COMMA = lambda: pyparsing.Literal(",")
_DEFINED = lambda: pyparsing.Keyword("defined")


class MacroParser(object):
    def __init__(self, macros, eval_mode=False, progress_cb=None):
        self.macros = macros
        self.progress_cb = progress_cb or (lambda *_: None)
        self.eval_mode = eval_mode
        self.frames = []
        self._expression = self.expression()
        self._token_replacer = _TOKEN().setParseAction(self._is_known_object)

    @property
    def current_frame(self):
        if not self.frames:
            return {}

        return self.frames[-1]

    def _combine_lists(self, inst, offset, tokens):
        _ = inst, offset
        result = []
        for x in tokens[0]:
            try:
                result.extend(x.asList())
            except AttributeError:
                result.append(x)

        return "(" + " ".join(result) + ")"

    def expression(self):
        expression = pyparsing.Forward()

        # (1 + (2 + 3))
        nested_expression = pyparsing.nestedExpr(
            "(", ")", expression).setParseAction(self._combine_lists)

        # FOO(2 , 3)
        function_call = (
            _TOKEN().setResultsName("function")
            + _OPEN_PARENTHESIS()
            + pyparsing.delimitedList(
                pyparsing.Combine(expression, adjacent=False, joinString=" "),
                delim=",").setResultsName("func_args")
            + _CLOSE_PARENTHESIS()
        )

        expression << pyparsing.OneOrMore(
            function_call.setParseAction(self._is_known_function)
            | pyparsing.Group(nested_expression)
            | _TOKEN()
            | _NOT_TOKEN()
        )

        return pyparsing.Combine(expression, adjacent=False, joinString=" ")

    def _is_known_object(self, tok):
        """Try to expand the object like macro."""
        name = tok.first

        # Support the non bracket form of defined: "defined foo"
        # foo will be expanded to 0 or 1 anyway so the defined operator here can
        # just be removed.
        if name == "defined":
            return ""

        value = self.current_frame.get(name)
        if value is None:
            value = self.macros.object_likes.get(name)
            if value is not None:
                value = value.replacement

                # In eval mode empty macros must expand to something or we cant
                # have an expression we can evaluate.
                # https://gcc.gnu.org/onlinedocs/cpp/Defined.html
                if value == "" and self.eval_mode:
                    return "1"

                # Self referential rule.
                for tokens, _, _ in _TOKEN().scanString(value):
                    if tokens[0] == name:
                        return str(value)

        # Dont expand it - return it as is.
        if value is None:
            return name

        # Recursively expand this expansion.
        if value:
            result = self.expand(str(value))
            self.progress_cb(
                "Expanded object-like %s: %s into %s", name, value, result)
            return result

        return value

    def _is_known_function(self, tok):
        if tok.function == "defined":
            name = tok.func_args.first
            return str(int(name in self.macros.symbols))

        # If the function is not known then we can not expand it.
        func_definition = self.macros.function_likes.get(tok.function)
        if func_definition is not None:
            # https://gcc.gnu.org/onlinedocs/cpp/Macro-Arguments.html#Macro-Arguments
            # All arguments to a macro are completely macro-expanded before they
            # are substituted into the macro body. After substitution, the
            # complete text is scanned again for macros to expand, including the
            # arguments.
            args = {}

            for name, value in zip(func_definition.arguments, tok.func_args):
                args[name] = self.expand(value)

            # Expand the function using the MacroExpanderVisitor.
            result = self._expand_objects(func_definition.replacement, **args)

            # Concatenate ## directives.
            result = re.sub(r"\s*##\s*", "", result)

            self.progress_cb("Expanded function-like %s: %s into %s",
                             tok.function, tok.func_args, result)

            return self._expand_functions(result)

        # Pass the function call along.
        return (tok.function + "(" + ", ".join(str(x) for x in tok.func_args) +
                ")")

    def _arguments(self):
        return pyparsing.Group(
            pyparsing.Optional(
                pyparsing.delimitedList(self.expression())))

    def might_match(self, text):
        # Split the text into tokens.
        tokens = re.findall("[a-zA-Z0-9_]+", text)
        result = self.macros.symbols.intersection(tokens) - IGNORE_MACROS
        return bool(result)

    def expand(self, source, force=False, eval_mode=None):
        if eval_mode is not None:
            self.eval_mode = eval_mode
        result = []
        for line in source.splitlines():
            try:
                result.append(self.expand_line(line, force=force))
            except Exception as e:
                print(e)
                result.append(line)

        return '\n'.join(result)

    def expand_line(self, source, force=False):
        # If there is no chance that this text contains macros just skip parsing
        # it. (The below parsing is very expensive and should be avoided if
        # possible).
        if not force and not self.might_match(source):
            return source

        # First pass - expand functional macros.
        result = self._expand_functions(source)

        # Second pass - expand object like macros.
        return self._expand_objects(result)

    def _expand_functions(self, source):
        result = self._expression.transformString(source)
        return result

    def _expand_objects(self, source, **kwargs):
        self.frames.append(kwargs)
        result = self._token_replacer.transformString(source)
        self.frames.pop(-1)
        return result
