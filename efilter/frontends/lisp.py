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
Lisp-like EFILTER syntax.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter import expression
from efilter import frontend


EXPRESSIONS = {
    "var": expression.Binding,
    "!": expression.Complement,
    "let": expression.Let,
    "let-any": expression.LetAny,
    "let-each": expression.LetEach,
    "in": expression.Membership,
    "regex": expression.RegexFilter,
    "|": expression.Union,
    "&": expression.Intersection,
    ">": expression.StrictOrderedSet,
    ">=": expression.PartialOrderedSet,
    "==": expression.Equivalence,
    "+": expression.Sum,
    "-": expression.Difference,
    "*": expression.Product,
    "/": expression.Quotient,
}


class Parser(frontend.Frontend):
    """Parses the lisp expression language into the query AST."""

    @property
    def root(self):
        return self._parse_atom(self.original)

    def _parse_atom(self, atom):
        if isinstance(atom, tuple):
            return self._parse_s_expression(atom)

        return expression.Literal(atom)

    def _parse_s_expression(self, atom):
        car = atom[0]
        cdr = atom[1:]

        # Bindings are a little special.
        if car == "var":
            return expression.Binding(cdr[0])

        return EXPRESSIONS[car](*(self._parse_atom(a) for a in cdr))


frontend.Frontend.register_frontend(Parser, shorthand="lisp")
