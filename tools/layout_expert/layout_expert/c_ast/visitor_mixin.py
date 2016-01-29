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

"""A module containing a VisitorMixin for the purpose of Visitor Pattern."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import re


def camel_case_to_lower_underscore(name):
    # Taken from StackOverflow.
    s1 = re.sub('([^_])([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


class VisitorMixin(object):

    """A mixin that provides Visitor Pattern.

    This is mixed into AST node to provide visitor pattern. Used in both ASTs.
    """

    def accept(self, visitor, *args, **kwargs):
        """Accepts a visitor from Visitor Pattern.

        Args:
          visitor: a visitor with .visit_CLASSNAME(type_reference_node) method
              where CLASSNAME is the name of a visited class.

          *args: additional positional arguments to be passed to the visitor
           call.

          **kwargs: additional keyword arguments to be passed to the visitor
            call.

        Returns:
          A value returned by the visitor.

        """
        lower_underscore_cls_name = camel_case_to_lower_underscore(
            self.__class__.__name__,
        )
        visitor_method_name = 'visit_' + lower_underscore_cls_name
        visitor_method = getattr(visitor, visitor_method_name)

        result = visitor_method(self, *args, **kwargs)
        #print("%s: %s" % (visitor_method_name, result))
        return result


class CASTVisitorWalker(object):
    """A base class for visitors of c_ast objects.

    Implements all the common methods to visit the AST.
    """

    def visit(self, node):
        return node.accept(self)

    def visit_c_program(self, program):
        for element in program.content:
            element.accept(self)

    def visit_c_type_definition(self, type):
        type.type_definition.accept(self)

    def visit_c_struct(self, struct):
        for field in struct.content:
            field.accept(self)

    def visit_c_union(self, union):
        for field in union.content:
            field.accept(self)

    def visit_c_enum(self, enum):
        pass

    def visit_c_field(self, field):
        field.type_definition.accept(self)

    def visit_c_type_reference(self, reference):
        """By default do not resolve references."""

    def visit_c_variable(self, variable):
        pass

    def visit_c_array(self, array):
        array.type_definition.accept(self)
        array.length.accept(self)

    def visit_c_typedef(self, typedef):
        typedef.type_definition.accept(self)

    def visit_c_pointer(self, ptr):
        ptr.type_definition.accept(self)

    def visit_c_void_type(self, ptr):
        pass

    def visit_c_function(self, ptr):
        pass

    def visit_c_number(self, _):
        pass

    def visit_c_simple_type(self, _):
        pass

    def visit_c_function_call(self, _):
        pass

    def visit_c_nested_expression(self, nested):
        nested.content.accept(self)
