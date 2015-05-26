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

import collections

from efilter import engine
from efilter import errors
from efilter import expression
from efilter import protocol

from efilter.protocols import iset

Analysis = collections.namedtuple("Analysis",
                                  ("symbols", "eq_indexables"))


class RuleAnalyzer(engine.VisitorEngine):
    """This is a rule-driven analyzer that gets a list of symbols and indexing.

    The analyzer will produce a list of symbols required by the query (based on
    the Bindings/variables) and recommend a list of Bindings suitable for
    building an equivalence-based index (based on Equivalence expressions in
    the query).
    """

    def visit_Expression(self, expr, **_):
        _ = expr
        return Analysis((), ())

    def visit_Binding(self, expr, **_):
        return Analysis((expr.value,), ())

    def visit_BinaryExpression(self, expr, **kwargs):
        lhsa = self.visit(expr.lhs, **kwargs)
        rhsa = self.visit(expr.rhs, **kwargs)

        return Analysis(
            iset.union(lhsa.symbols, rhsa.symbols),
            iset.union(lhsa.eq_indexables, rhsa.eq_indexables))

    def visit_VariadicExpression(self, expr, **kwargs):
        symbols = set()
        eq_indexables = set()

        for child in expr:
            analysis = self.visit(child, **kwargs)
            symbols.update(analysis.symbols)
            eq_indexables.update(analysis.eq_indexables)

        return Analysis(symbols, eq_indexables)

    def visit_Let(self, expr, scope=None, **kwargs):
        if not isinstance(expr.lhs, expression.Binding):
            # Technically, the LHS context can be anything that implements
            # IAssociative, so a literal, or a subexpression that evaluates to
            # one are possible. Unfortunately, when that happens it is
            # non-trivial (read hard (read impossible)) to correctly determine
            # the scope for the RHS of the Let-form.
            #
            # As this is the case, we are unable to create any hints, and
            # any symbols in the RHS expression are bound to an anonymous scope
            # and, and, as such, not useful.
            return self.visit_BinaryExpression(expr, scope=scope, **kwargs)

        scope = expr.lhs.value
        rhsa = self.visit(expr.rhs, scope=scope, **kwargs)
        symbols = set("%s.%s" % (scope, symbol) for symbol in rhsa.symbols)
        symbols.update(rhsa.symbols)
        symbols.add(expr.lhs.value)
        return rhsa._replace(symbols=symbols)

    def visit_Membership(self, expr, **kwargs):
        symbols = set()
        lha = self.visit(expr.lhs, **kwargs)
        rha = self.visit(expr.rhs, **kwargs)
        symbols.update(lha.symbols)
        symbols.update(rha.symbols)

        if (not isinstance(expr.rhs, expression.Literal)
                or not isinstance(expr.lhs, expression.Binding)):
            return Analysis(symbols, ())

        if not protocol.implements(expr.rhs.value, iset.ISet):
            # Yup, no can do.
            raise errors.EfilterTypeError(root=expr.rhs, query=self.query,
                                          actual=type(expr.rhs.value),
                                          expected=iset.ISet)

        return Analysis(symbols, (expr.lhs.value,))

    def visit_Equivalence(self, expr, **kwargs):
        literal = None
        indexables = set()
        symbols = set()
        for child in expr.children:
            if isinstance(child, expression.Literal):
                if literal is not None and literal != child.value:
                    # This means something like 5 == 6 is being asked. This
                    # expression will always be false and it makes no sense to
                    # continue.
                    return Analysis((), ())
                else:
                    literal = child.value
            elif isinstance(child, expression.Binding):
                indexables.add(child.value)
                symbols.add(child.value)
            elif isinstance(child, expression.Let):
                # If we get a let-form, follow down as long as RHS is another
                # left form and the LHS is a binding. (something like
                # foo.bar.baz)
                let = child
                path = []
                while (isinstance(let, expression.Let)
                       and isinstance(let.lhs, expression.Binding)):
                    path.append(let.lhs.value)
                    symbols.add(".".join(path))
                    let = let.rhs

                if isinstance(let, expression.Binding):
                    path.append(let.value)

                remainder = self.visit(child, **kwargs)
                symbols.update(remainder.symbols)

                symbol = ".".join(path)
                symbols.add(symbol)
                indexables.add(symbol)
            else:
                analysis = self.visit(child, **kwargs)
                symbols.update(analysis.symbols)

        return Analysis(symbols, indexables)

engine.Engine.register_engine(RuleAnalyzer, "analyzer")
