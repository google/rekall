# EFILTER Forensic Query Language
#
# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
EFILTER rule-based query analyzer.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter import engine
from efilter import errors
from efilter import protocol

from efilter.protocols import associative
from efilter.protocols import boolean
from efilter.protocols import name_delegate


class TypeInferencer(engine.VisitorEngine):
    """Determines the types of each subexpression and validates sanity.

    This class follows the visitor pattern. See documentation on VisitorEngine.
    """

    def visit_Literal(self, expr, **_):
        return type(expr.value)

    def visit_BinaryExpression(self, expr, **kwargs):
        lhst = self.visit(expr.lhs, **kwargs)
        if not protocol.isa(lhst, expr.type_signature[0]):
            raise errors.EfilterTypeError(query=self.query, root=expr.lhs,
                                          expected=expr.type_signature[0],
                                          actual=lhst)

        rhst = self.visit(expr.rhs, **kwargs)
        if not protocol.isa(rhst, expr.type_signature[1]):
            raise errors.EfilterTypeError(query=self.query, root=expr.rhs,
                                          expected=expr.type_signature[1],
                                          actual=rhst)

        return expr.return_signature

    def visit_Binding(self, expr, scope=None, **_):
        if isinstance(self.application_delegate, name_delegate.INameDelegate):
            result = name_delegate.reflect(self.application_delegate,
                                           expr.value,
                                           scope)
            if result:
                return result

        return protocol.AnyType

    def visit_VariadicExpression(self, expr, **kwargs):
        for subexpr in expr.children:
            t = self.visit(subexpr, **kwargs)
            if not protocol.isa(t, expr.type_signature):
                raise errors.EfilterTypeError(query=self.query,
                                              root=subexpr,
                                              expected=expr.type_signature,
                                              actual=t)

        return expr.return_signature

    def visit_Let(self, expr, scope=None, **kwargs):
        t = self.visit(expr.context, scope=scope, **kwargs)
        if not (t is protocol.AnyType
                or protocol.isa(t, associative.IAssociative)):
            raise errors.EfilterTypeError(query=self.query, root=expr,
                                          actual=t,
                                          expected=associative.IAssociative)

        return self.visit(expr.expression, scope=t, **kwargs)

    def visit_LetAny(self, expr, **kwargs):
        t = self.visit_Let(expr, **kwargs)
        if not protocol.isa(t, boolean.IBoolean):
            raise errors.EfilterTypeError(query=self.query, root=expr,
                                          actual=t,
                                          expected=associative.IBoolean)

        return boolean.IBoolean

    def visitLetEach(self, expr, **kwargs):
        return self.visit_LetAny(expr, **kwargs)


engine.Engine.register_engine(TypeInferencer, "infer_types")
