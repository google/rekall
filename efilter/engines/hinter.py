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
from efilter import expression


class Hinter(engine.VisitorEngine):
    """Retargets the query to apply to a subexpression, to be used for hinting.

    This class follows the visitor pattern. See documentation on VisitorEngine.

    Discussion of mechanism and rationale:
    ======================================

    Bear with me on this one.

    As with any database-like system, certain EFILTER queries can be satisfied
    by following several equally valid, but differently expensive strategies.
    Because traditional notions of cardinality and available indexing do not
    apply to most systems that provide EFILTER with data (and, at any rate,
    such concerns are usually negligible in comparison with the actual
    collection of data), it becomes useful for the expert system supplying the
    data to be able to influence the strategy based on what it knows about the
    relative trade-offs.

    To give a concrete example, take the following query:
        VAD.flags contains {'execute', 'write'} and VAD.process.name == 'init'

    (In this example a VAD is a virtual address descriptor, which is a data
    structure used by operating systems to keep track of pageable memory.)

    A naive expert (uh...) system will generate all possible VADs and feed them
    to the EFILTER matcher engine. An optimized system - lets call it an expert
    expert system - can only collect VADs belonging to the 'init' process at
    fraction of the cost, and supply those to EFILTER for indexing and
    filtering. This is possible, because the expert system knows that processes
    are the first to be collected, and that each process holds a reference to
    related VADs, making it beneficial to skip processes that don't apply. What
    the expert system needs is a way to signal that such a strategy is
    available, and a way to recognize the processes which cannot be skipped.

    Enter the Hinter - taking the example above, the expert system can run:
        q = Query("VAD.flags contains {'execute', 'write'} "
                  " and VAD.process.name == 'init'")
        hint = q.run_engine('hinter', selector='VAD.process')

    This will cause the Hinter to generate a hint query equivalent to the
    expression "name == 'init'", which can be applied to a process object
    for prefiltering. Amazing.
    """

    def run(self, selector=None, *args, **kwargs):
        self.selector = tuple(selector.split(".")) if selector else ()

        # Make sure the query is reasonably shaped with respect to let-forms.
        self.query = self.query.run_engine("normalizer")

        expr = super(Hinter, self).run(*args, trace=(), **kwargs)
        return self.query.subquery(expr)

    def _next_crumb(self, trace):
        if self.selector[:len(trace)] == trace:
            next_crumb = self.selector[len(trace)]
            return next_crumb

        return None

    def visit_Let(self, expr, trace=None, **_):
        if self.selector == trace:
            # We're already in a subexpression we want to preserve.
            return expr

        self._last_let_form_reached_bottom = False

        if not isinstance(expr.lhs, expression.Binding):
            # Can't do anything - might not be correct - perhaps we should
            # blow up here? (Only Let-forms with a Binding on the LHS can be
            # hinted.)
            raise errors.EfilterError(
                query=self.query,
                message=("Hinter can only optimize let forms where lhs is a "
                         "binding (a variable). Got %r instead.")
                % (self.query.subquery(expr)),
                root=expr)

        crumb = expr.lhs.value
        next_crumb = self._next_crumb(trace)

        if next_crumb == crumb:
            # Descend.
            trace_ = trace + (next_crumb,)
            branch = self.visit(expr.rhs, trace=trace + (next_crumb,))

            if trace_ == self.selector:
                # Bottom.
                self._last_let_form_reached_bottom = True

            # This could have been set by the conditional above or by a nested
            # let-form. Either way, we keep the branch only if it matched the
            # entire selector, otherwise it's discarded.
            if self._last_let_form_reached_bottom:
                return branch

        return None  # Eliminate this branch.

    def _build_variadic(self, expr, **kwargs):
        children = []
        for child in expr.children:
            branch = self.visit(child, **kwargs)
            if branch:
                children.append(branch)

        return children

    def visit_VariadicExpression(self, expr, **kwargs):
        children = self._build_variadic(expr, **kwargs)
        if not children:
            return None

        if len(children) == 1:
            # We play it safe and keep the only child in case the return type
            # of this expression isn't just a boolean (math).
            # More specific visitors will eliminate the whole thing.
            return children[0]

        return type(expr)(*children)

    def visit_Relation(self, expr, **kwargs):
        children = self._build_variadic(expr, **kwargs)

        if len(children) == 1:
            return None  # It's pointless to execute this relation.

        return type(expr)(*children)

    def visit_ValueExpression(self, expr, **kwargs):
        return type(expr)(self.visit(expr.value, **kwargs))

    def visit_BinaryExpression(self, expr, **kwargs):
        lhs = self.visit(expr.lhs, **kwargs)
        if not lhs:
            return None

        rhs = self.visit(expr.rhs, **kwargs)
        if not rhs:
            return None

        return type(expr)(lhs, rhs)

    def visit_Literal(self, expr, **_):
        return expr

    def visit_Binding(self, expr, trace=None, **_):
        if self.selector == trace:
            return expr

        return None


engine.Engine.register_engine(Hinter, "hinter")
