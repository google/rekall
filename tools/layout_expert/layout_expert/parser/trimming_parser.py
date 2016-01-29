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

"""Trims a C file into dependencies important for us.

Parsing the entire C file is a little slow in Python and we normally do not need
to extract struct layouts from all of the types defined in the Linux kernel.

We therefore need a way to trim the entire re-constructed pre-processed C file
into a distilled version which only contains those types we care about.

This parser uses a cheap and rough parsing pass to partition the C file into
segments and quickly identify the types defined in those segments. We then use
the C parser to only parse those items we care about.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pyparsing
# pylint: disable=expression-not-assigned

from layout_expert.c_ast import c_ast
from layout_expert.lib import parsers
from layout_expert.lib import type_manager as type_manager_module


_STRUCT = pyparsing.Keyword('struct')
_UNION = pyparsing.Keyword('union')
_IDENTIFIER = pyparsing.Word(pyparsing.alphanums + '_')
_SEMICOLON = pyparsing.Literal(';')
_ENUM = pyparsing.Keyword('enum')
_TYPEDEF = pyparsing.Keyword('typedef')
_OPEN_PARENTHESIS = pyparsing.Literal('(')
_CLOSE_PARENTHESIS = pyparsing.Literal(')')
_STAR = pyparsing.Literal('*')


def _struct_definition():
    return (
        (_STRUCT.setResultsName("type") | _UNION.setResultsName("type"))
        + _IDENTIFIER.setResultsName("name")
        + parsers.anything_in_curly()
        + pyparsing.SkipTo(_SEMICOLON)
        + _SEMICOLON
    ).setResultsName("_struct_definition")

def _struct_typedef():
    return (
        _TYPEDEF
        + (_STRUCT.setResultsName("type") | _UNION.setResultsName("type"))
        + pyparsing.Optional(_IDENTIFIER).setResultsName("id")
        + parsers.anything_in_curly()
        + pyparsing.Optional(_STAR)
        + _IDENTIFIER.setResultsName("typedef_name")
        + pyparsing.SkipTo(_SEMICOLON)
        + _SEMICOLON
    ).setResultsName("_struct_typedef")


def _simple_typedef():
    return (
        _TYPEDEF
        + pyparsing.SkipTo(_SEMICOLON)
        + _SEMICOLON
    ).setResultsName("_simple_typedef")


def _enum():
    return (
        _ENUM
        + pyparsing.Optional(_IDENTIFIER).setResultsName("id")
        + parsers.anything_in_curly()
        + _SEMICOLON
    ).setResultsName("_enum")


def _stuff_we_care_about():
    """Only match the stuff we care about.

    This removes quite a lot of useless code we dont want to spend time parsing.
    """
    return (
        _struct_definition()
        | _struct_typedef()
        | _simple_typedef()
        | _enum()
    )


def build_snippets(c_file_text, progress_cb=None):
    """Builds a snippets dict.

    Args:
        c_file_text: The text of the pre-processed C file to use.

    Returns:
        a dict with keys being the name of the type defined in each snippet and
    value being the snippet itself.
    """
    type_manager = type_manager_module.TypeManager()
    pyparsing.ParserElement.disablePackrat()    # Packrat caching slows us down
    # here.

    context = {}
    # We store global constants here (e.g. from enums). This is required because
    # enum field names are global and un-typed and may be used by any structs
    # without us being able to easily find which enum they come from.
    context["$VARS"] = {}

    scanner = _stuff_we_care_about().parseWithTabs()
    for tokens, start, end in scanner.scanString(c_file_text):
        match_data = c_file_text[start:end]
        results_name = tokens.getName()
        if progress_cb:
            progress_cb(
                "Trimming @%s: %02d%%", start, start * 100 / len(c_file_text))

        if results_name in ("_simple_typedef", "_function_typedef"):
            # Last identifier before the _SEMICOLON.
            try:
                parsed_c_ast = type_manager.parse_c_code(match_data)
                typedef_name = parsed_c_ast.content[0].name
                context[typedef_name] = parsed_c_ast
                type_manager.add_type(typedef_name)

                # Just ignore parse errors for now.
            except c_ast.IrreducibleFunction:
                pass

        elif results_name == "_struct_typedef":
            typedef_name = tokens['typedef_name']
            context[typedef_name] = match_data

            # If this is not an anonymous struct we also add a reference to
            # "struct identifier"
            id = tokens.get("id")
            if id is not None:
                type_name = tokens["type"] + " " + id
                context[type_name] = context[typedef_name]
                type_manager.add_type(type_name)

        elif results_name == "_struct_definition":
            name = tokens["type"] + " " + tokens["name"]
            context[name] = match_data
            type_manager.add_type(name)

        elif results_name == "_enum":
            parsed_c_ast = type_manager.parse_c_code(match_data)
            for field in parsed_c_ast.content[0].type_definition.fields:
                # Enums fill in the global namespace so they can be expanded.
                context["$VARS"][field.name] = field.value

            enum_name = parsed_c_ast.content[0].name
            context[enum_name] = parsed_c_ast

    return context
