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

"""Manager for types, constants and everything required to parse C code.

The TypeManager() object is passed to all components in order to allow them to
use any of the services of the Layout Expert (such as Expression Parsing, Type
retrieval etc.)
"""
import logging

from layout_expert.builtins import functions
from layout_expert.builtins import types
from layout_expert.c_ast import c_ast
from layout_expert.parsers import c_parser
from layout_expert.visitors import expression_evaluator_visitor
from layout_expert.visitors import layout_computing_visitor
from layout_expert.visitors import type_collecting_visitor
from layout_expert.visitors import field_collecting_visitor


class TypeManager(object):
    """Manager for types, constants and everything required to parse C code.

    C code is not context free - this means we need to understand C code in
    order to parse it properly. In particular the parser needs to be aware of
    types. Consider the following expression:

    (x) & y

    If x is a type this represents a cast of a pointer reference to the variable
    y. But if x is a variable then this is an AND operation between two
    variables. Therefore, the parser needs to have type manager which learns
    about new types during the parsing (when the parser meets typedef
    statements) and can resolve these situations where type information is
    required.

    """
    def __init__(self, trimming_dict=None, progress_cb=None):
        self.trimming_dict = trimming_dict
        self.types_cast_to_void = set()
        self.progress_cb = progress_cb or (lambda *_: None)
        self.parser = c_parser.Parser(type_manager=self)
        self.variables = {}
        self.types = types.get_64bit_types()
        self.functions = functions.get_arithmetic_functions()
        self.functions.update(functions.get_builtins())
        self.expression_evaluator = (
            expression_evaluator_visitor.ExpressionEvaluatorVisitor(
                type_manager=self))

        self.dependency_visitor = type_collecting_visitor.DependencyVisitor(
            type_manager=self)

        self.field_collector = field_collecting_visitor.FieldCollectingVisitor(
            type_manager=self)

        self.layout_computer = layout_computing_visitor.LayoutComputingVisitor(
            type_manager=self)

        # Add the constants from the trimming dict. These represent global enum
        # values.
        if trimming_dict:
            self.variables = self.trimming_dict.get("$VARS", {})

    def add_constant(self, name, value):
        """Evaluate the AST to retrieve a constant."""
        self.variables[name] = value

    def add_type(self, name, value=None):
        self.types[name] = value

    def evaluate(self, expression):
        return self.expression_evaluator.evaluate(expression)

    def compute_layout(self, type_definition):
        return self.layout_computer.compute_layout(type_definition)

    def get_type_of(self, type_expression):
        """Parses type_expression and retrieves the type."""
        if isinstance(type_expression, (int, long)):
            return "unsigned int"

        # TODO: Parse the type expression to determine if we have the type.
        return str(type_expression)

    def collect_fields(self, struct):
        return self.field_collector.collect_fields(struct.content)

    def resolve_dependencies(self, node):
        """Walks the AST given at node and collects all dependencies of node."""
        return self.dependency_visitor.get_dependencies(node)

    def parse_c_code(self, source):
        """Parse C code into a C AST."""
        # Already parsed, just return it.
        if isinstance(source, c_ast.CASTNode):
            return source

        result = self.parser.parse(source)
        return result

    def get_type_ast(self, type_name):
        # If we already know about this type - just get it from the cache.
        if type_name in self.types:
            return self.types[type_name]

        # We do not know about the type but we have a trimming dict so we can
        # just parse the snippet.
        if self.trimming_dict and type_name in self.trimming_dict:
            self.progress_cb("Parsing layout type %s", type_name)

            # The parser is responsible for populating new types into the type
            # manager so this will discover new types.
            parsed_c_ast = self.parse_c_code(self.trimming_dict[type_name])
            self.types[type_name] = parsed_c_ast

            # Resolve all dependencies.
            self.resolve_dependencies(parsed_c_ast)

            # Type should be known now.
            return parsed_c_ast

        # It is possible to have a dependency that is not found in the
        # trimming tree. This happens if for example, the module.c does
        # not include the relevant header file at all. The compiler is
        # fine with that as long as all references to the type are
        # pointers, and no code is attempting to dereference the
        # struct. For example:

        # struct {
        #    struct foo* bar;
        # }

        # Can be generated, even without knowing the definition of
        # struct foo because all we need to know is that this is a
        # pointer size. The compiler (and us) must just change this into
        # a pointer to void (void *). Unfortunately for us, the struct
        # layout will not be known in the profile, so we should consider
        # adding the include to the module.c as well.
        if type_name not in self.types_cast_to_void:
            logging.debug("Type %s is not included, assuming void.",
                          type_name)
            # Only report this warning once.
            self.types_cast_to_void.add(type_name)

        return c_ast.CTypeReference(type_name)


    def get_type_layout(self, type_name):
        return self.compute_layout(self.get_type_ast(type_name))
