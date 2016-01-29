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
"""A visitor collecting types from an AST tree."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


from layout_expert.c_ast import visitor_mixin


class DependencyVisitor(visitor_mixin.CASTVisitorWalker):
    """Recursively collect the dependent types.

    This calls back into the type manager to discover types that are not already
    known.
    """

    def __init__(self, type_manager):
        self.type_manager = type_manager

    def get_dependencies(self, node):
        """Collects all the type names that are used by node."""
        self.dependencies = set()
        return self.visit(node)

    def visit_c_type_definition(self, type):
        self.dependencies.add(type.name)
        self.type_manager.add_type(type.name, type.type_definition)
        type.type_definition.accept(self)

    def visit_c_type_reference(self, reference):
        """Resolve type references."""
        type_name = reference.name
        if type_name is not None and type_name not in self.dependencies:
            self.dependencies.add(type_name)

            # Resolve the reference by loading it from the type manager.
            reference_ast = self.type_manager.get_type_ast(type_name)

            # Recurse into it.
            reference_ast.accept(self)

    def visit_c_variable(self, variable):
        """Variables are constants like Enum fields."""
        self.dependencies.add(variable.name)
