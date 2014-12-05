# Rekall Memory Forensics
#
# Copyright 2014 Google Inc. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""
The Rekall Entity Layer.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

import collections
import re

from rekall.entities.query import expression


# Transformation functions, for expressions that don't directly map to
# something in the AST.

def ComplementEquivalence(*args, **kwargs):
    return expression.Complement(
        expression.Equivalence(*args, **kwargs), **kwargs)


def ComplementMembership(*args, **kwargs):
    return expression.Complement(
        expression.Membership(*args, **kwargs), **kwargs)


def ReverseStrictOrderedSet(*args, **kwargs):
    return expression.StrictOrderedSet(*reversed(args), **kwargs)


def ReversePartialOrderedSet(*args, **kwargs):
    return expression.PartialOrderedSet(*reversed(args), **kwargs)


def NegateValue(*args, **kwargs):
    return expression.Product(
        expression.Literal(-1),
        *args,
        **kwargs)


def FlattenComponentLiteral(*args, **kwargs):
    if not isinstance(args[0], expression.Binding):
        raise ValueError(
            "'has component' must be followed by a component. Got %s." % (
                args[0]))
    return expression.ComponentLiteral(args[0].value, **kwargs)


def TransformLetAny(let, **kwargs):
    if not isinstance(let, expression.Let):
        raise ValueError("'any' must be followed by a 'matches' expression.")
    context, expr = let.children
    return expression.LetAny(context, expr, **kwargs)


def TransformLetEach(let, **kwargs):
    if not isinstance(let, expression.Let):
        raise ValueError("'each' must be followed by a 'matches' expression.")
    context, expr = let.children
    return expression.LetEach(context, expr, **kwargs)


# Operators - infix and prefix.

Operator = collections.namedtuple("Operator",
                                  "precedence assoc handler docstring")

# The order of precedence matters for generated matching rules, which is why
# this is an OrderedDict.
INFIX = collections.OrderedDict([
    ("->", Operator(precedence=2, assoc="left", handler=expression.Let,
                    docstring="Shorthand for 'matches'.")),
    ("+", Operator(precedence=3, assoc="left", handler=expression.Sum,
                   docstring="Arithmetic addition.")),
    ("-", Operator(precedence=3, assoc="left", handler=expression.Difference,
                   docstring="Arithmetic subtraction.")),
    ("*", Operator(precedence=5, assoc="left", handler=expression.Product,
                   docstring="Arithmetic multiplication.")),
    ("/", Operator(precedence=5, assoc="left", handler=expression.Quotient,
                   docstring="Arithmetic division.")),
    ("==", Operator(precedence=2, assoc="left",
                    handler=expression.Equivalence,
                    docstring="Equivalence (same as 'is').")),
    ("!=", Operator(precedence=2, assoc="left",
                    handler=ComplementEquivalence,
                    docstring="Inequivalence (same as 'is not').")),
    ("is not", Operator(precedence=2, assoc="left",
                        handler=ComplementEquivalence,
                        docstring="Inequivalence (same as '!=').")),
    ("is", Operator(precedence=2, assoc="left",
                    handler=expression.Equivalence,
                    docstring="Equivalence (same as '==')")),
    ("not in", Operator(precedence=2, assoc="left",
                        handler=ComplementMembership,
                        docstring="Left-hand operand is not in list.")),
    ("in", Operator(precedence=2, assoc="left",
                    handler=expression.Membership,
                    docstring="Left-hand operand is in list.")),
    (">", Operator(precedence=2, assoc="left",
                   handler=expression.StrictOrderedSet,
                   docstring="Greater-than.")),
    (">=", Operator(precedence=2, assoc="left",
                    handler=expression.PartialOrderedSet,
                    docstring="Equal-or-greater-than.")),
    ("<", Operator(precedence=2, assoc="left",
                   handler=ReverseStrictOrderedSet,
                   docstring="Less-than.")),
    ("<=", Operator(precedence=2, assoc="left",
                    handler=ReversePartialOrderedSet,
                    docstring="Equal-or-less-than.")),
    ("matches", Operator(precedence=2, assoc="left",
                         handler=expression.Let,
                         docstring="Left-hand operand matched subquery.")),
    ("and", Operator(precedence=1, assoc="left",
                     handler=expression.Intersection,
                     docstring="Logical AND.")),
    ("or", Operator(precedence=0, assoc="left", handler=expression.Union,
                    docstring="Logical OR.")),
    ("=~", Operator(precedence=2, assoc="left",
                    handler=expression.RegexFilter,
                    docstring="Left-hand operand matches regex.")),
])


PREFIX = {
    "not": Operator(precedence=6, assoc=None, handler=expression.Complement,
                    docstring="Logical NOT."),
    "-": Operator(precedence=4, assoc=None, handler=NegateValue,
                  docstring="Unary -."),
    "has component": Operator(precedence=7, assoc=None,
                              handler=FlattenComponentLiteral,
                              docstring="Matching entity must have component."),
    "any": Operator(precedence=1, assoc=None, handler=TransformLetAny,
                    docstring=("Following 'matches' should succeed if "
                               "any left-hand value matches.")),
    "each": Operator(precedence=1, assoc=None, handler=TransformLetEach,
                     docstring=("Following 'matches' should only "
                                "succeed if all left-hand values match.")),
}


def EnumAsPattern(strings):
    """Return a regex that'll match any of the strings in order."""
    return "(%s)" % "|".join([re.escape(x) for x in strings])


class Token(object):
    """Represents a result from the tokenizer."""

    def __init__(self, name, value, start, end):
        self.name = name
        self.value = value
        self.start = start
        self.end = end

    def __repr__(self):
        return "Token(name='%s', value='%s', start=%d, end=%d)" % (
            self.name, self.value, self.start, self.end)


class Pattern(object):
    """A token pattern.

    Args:
      state_regex: If this regular expression matches the current state this
                   rule is considered.
      regex: A regular expression to try and match from the current point.
      actions: A command separated list of method names in the Lexer to call.
      next_state: The next state we transition to if this Pattern matches.
      flags: flags to re.compile.
    """

    def __init__(self, label, state_regex, regex, actions, next_state,
                 flags=re.I):
        self.state_regex = re.compile(
            state_regex, re.DOTALL | re.M | re.S | re.U | flags)
        self.regex = re.compile(regex, re.DOTALL | re.M | re.S | re.U | flags)
        self.label = label
        self.re_str = regex

        if actions:
            self.actions = actions.split(",")
        else:
            self.actions = []

        self.next_state = next_state


class ParseError(expression.QueryError):
    pass


class Tokenizer(object):
    """Context-free tokenizer for the efilter language.

    This is a very basic pattern-based tokenizer. Any rule from patterns
    will try to match the next token in the buffer if its state_regex matches
    the current state. Only meaningful tokens are emitted (not whitespace.)
    """
    patterns = [
        # Keywords, operators and symbols
        Pattern("symbol", "INITIAL", r"(\&?[A-Z][A-Za-z0-9]+\/[a-z0-9_]+)",
                "emit", None),
        Pattern("infix", "INITIAL", EnumAsPattern(INFIX.keys()),
                "emit", None),
        Pattern("prefix", "INITIAL", EnumAsPattern(PREFIX.keys()),
                "emit", None),
        Pattern("lparen", "INITIAL", r"\(",
                "emit", None),
        Pattern("rparen", "INITIAL", r"\)",
                "emit", None),
        Pattern("comma", "INITIAL", r",",
                "emit", None),
        Pattern("symbol", "INITIAL", r"([a-z_\.][a-z_\.0-9]+)", "emit", None),
        Pattern("param", "INITIAL", r"\{([a-z_0-9]*)\}", "emit_param", None),

        # Numeric literals
        Pattern("literal", "INITIAL", r"(\d+\.\d+)", "emit_float", None),
        Pattern("literal", "INITIAL", r"(0x[0-9a-zA-Z]+)", "emit_int16", None),
        Pattern("literal", "INITIAL", r"(\d+)", "emit_int", None),

        # String literals
        Pattern(None, "INITIAL", r"\"", "string_start", "STRING"),
        Pattern(None, "INITIAL", r"'", "string_start", "SQ_STRING"),

        Pattern("literal", "STRING", "\"", "pop_state,emit_string", None),
        Pattern(None, "STRING", r"\\(.)", "string_escape", None),
        Pattern(None, "STRING", r"[^\\\"]+", "string_append", None),

        Pattern("literal", "SQ_STRING", "'", "pop_state,emit_string", None),
        Pattern(None, "SQ_STRING", r"\\(.)", "string_escape", None),
        Pattern(None, "SQ_STRING", r"[^\\']+", "string_append", None),

        # Whitespace is ignored.
        Pattern(None, ".", r"\s+", None, None),
    ]

    def __init__(self, query):
        self.buffer = query
        self.state_stack = ["INITIAL"]
        self.current_token = None
        self._position = 0
        self.limit = len(query)
        self.lookahead = []
        self._param_idx = 0

    @property
    def position(self):
        """Returns the logical position (unaffected by lookahead)."""
        if self.lookahead:
            return self.lookahead[0].start

        return self._position

    def pop_state(self, **_):
        try:
            self.state_stack.pop()
        except IndexError:
            self.error("Pop state called on an empty stack.", self.position)

    def next_token(self):
        """Returns the next logical token.

        Will trigger parsing if it has to.
        """
        if self.lookahead:
            self.current_token = self.lookahead.pop(0)
            return self.current_token

        self.current_token = self._parse_next_token()
        return self.current_token

    def _parse_next_token(self):
        """Will parse patterns until it gets to the next token or EOF."""
        while self._position < self.limit:
            token = self.next_pattern()
            if token:
                return token

        return None

    def peek(self, steps=1):
        """Look ahead, doesn't affect current_token and next_token."""
        while len(self.lookahead) < steps:
            token = self._parse_next_token()
            if token is None:
                return None

            self.lookahead.append(token)

        return self.lookahead[steps - 1]

    def parse(self):
        """Yield every token in turn."""
        while self._position < self.limit:
            token = self.next_token()
            if not token:
                return

            yield token

    def next_pattern(self):
        """Parses the next pattern by matching each in turn."""
        current_state = self.state_stack[-1]
        position = self._position
        for pattern in self.patterns:
            if not pattern.state_regex.match(current_state):
                continue

            m = pattern.regex.match(self.buffer, position)
            if not m:
                continue

            position = m.end()
            token = None

            if pattern.next_state:
                self.state_stack.append(pattern.next_state)

            for action in pattern.actions:
                callback = getattr(self, action, None)
                if callback is None:
                    raise RuntimeError(
                        "No method defined for pattern action %s!" % action)

                token = callback(string=m.group(0), match=m, pattern=pattern)

            self._position = position

            return token

        self.error("Don't know how to match next. Did you forget quotes?",
                   self.position)

    def error(self, message, start, end=None):
        """Print a nice error."""
        raise ParseError(query=self.buffer, start=start, end=end,
                         error=message)

    def emit(self, string, match, pattern, **_):
        """Emits a token using the current pattern match and pattern label."""
        return Token(name=pattern.label, value=string, start=match.start(),
                     end=match.end())

    def emit_param(self, match, pattern, **_):
        param_name = match.group(1)
        if not param_name:
            param_name = self._param_idx
            self._param_idx += 1

        return Token(name=pattern.label, value=param_name, start=match.start(),
                     end=match.end())

    def emit_int(self, string, match, pattern, **_):
        return Token(name=pattern.label, value=int(string), start=match.start(),
                     end=match.end())

    def emit_int16(self, string, match, pattern, **_):
        return Token(name=pattern.label, value=int(string, 16),
                     start=match.start(), end=match.end())

    def emit_float(self, string, match, pattern, **_):
        return Token(name=pattern.label, value=float(string),
                     start=match.start(), end=match.end())

    # String parsing

    def string_start(self, match, **_):
        self.string = ""
        self.string_position = match.start()

    def string_escape(self, string, match, **_):
        if match.group(1) in "'\"rnbt":
            self.string += string.decode("string_escape")
        else:
            self.string += string

    def string_append(self, string="", **_):
        self.string += string

    def emit_string(self, pattern, match, **_):
        return Token(name=pattern.label, value=self.string,
                     start=self.string_position, end=match.end())


class Parser(object):
    """Parses the efilter language into the query AST.

    This is a basic precedence-climbing parser with support for prefix
    operators and a few special cases for list literals and such.
    """

    def __init__(self, query, params=None):
        self.tokenizer = Tokenizer(query)

        if isinstance(params, list):
            self.params = {}
            for idx, val in enumerate(params):
                self.params[idx] = val
        else:
            self.params = params

    @property
    def query(self):
        return self.tokenizer.buffer

    def _handle_expr(self, operator, *args, **kwargs):
        try:
            return operator.handler(*args, **kwargs)
        except ValueError as e:
            return self.error(e.message,
                              start_token=args[0])

    def _replace_param(self, token):
        param_name = token.value
        value = self.params.get(param_name, None)
        if value is None:
            return self.error("No value provided for param %s" % param_name,
                              token)

        return value

    def next_atom(self):
        token = self.tokenizer.next_token()

        if token is None:
            return self.error("Unexpected end of input.")

        if token.name == "infix":
            if token.value == "-":
                # As it turns out, minus signs can be prefix operators! Who
                # knew? Certainly not the tokenizer.
                token.name = "prefix"
            else:
                return self.error("Unexpected infix operator.", token)

        if token.name == "prefix":
            operator = PREFIX[token.value]
            lhs = self.next_atom()
            rhs = self.next_expression(lhs, operator.precedence)
            return self._handle_expr(operator, rhs, start=token.start,
                                     end=rhs.end)

        if token.name == "literal":
            return expression.Literal(token.value, start=token.start,
                                      end=token.end)

        if token.name == "param":
            return expression.Literal(self._replace_param(token),
                                      start=token.start, end=token.end)

        if token.name == "symbol":
            return expression.Binding(token.value, start=token.start,
                                      end=token.end)

        if token.name == "lparen":
            # Parentheses can denote subexpressions or lists. Lists have at
            # least one comma before rparen (just like Python).
            lhs = self.next_atom()
            expr = self.next_expression(lhs, 0)
            if self.tokenizer.current_token is None:
                return self.error("End of input before closing parenthesis.",
                                  token)

            if self.tokenizer.peek().name == "comma":
                # It's a list, not an expression. Build it out as a literal.
                if not isinstance(lhs, expression.Literal):
                    return self.error(
                        "Non-literal value in list.", lhs)

                self.tokenizer.next_token()
                vals = [lhs.value]

                while (self.tokenizer.current_token and
                       self.tokenizer.current_token.name == "comma"):
                    atom = self.next_atom()
                    if not isinstance(atom, expression.Literal):
                        return self.error(
                            "Non-literal value in list", atom)
                    vals.append(atom.value)
                    self.tokenizer.next_token()

                if (self.tokenizer.current_token is None or
                        self.tokenizer.current_token.name != "rparen"):
                    self.error("Lists must end with a closing paren.",
                               self.tokenizer.current_token)

                return expression.Literal(tuple(vals), start=token.start,
                                          end=self.tokenizer.position)

            elif self.tokenizer.peek().name != "rparen":
                # We got here because there's still some stuff left to parse
                # and the next token is not an rparen. That can mean that an
                # infix operator is missing or that the parens are unmatched.
                # Decide which is more likely and raise the appropriate error.
                lparens = 1
                rparens = 0
                lookahead = 2
                while self.tokenizer.peek(lookahead):
                    if self.tokenizer.peek(lookahead).name == "lparen":
                        lparens += 1
                    elif self.tokenizer.peek(lookahead).name == "rparen":
                        rparens += 1

                    lookahead += 1

                if lparens > rparens:
                    return self.error("Ummatched left parenthesis.", token)
                else:
                    next_token = self.tokenizer.peek()
                    return self.error(
                        "Was not expecting %s here." % next_token.value,
                        next_token)

            self.tokenizer.next_token()
            return expr

        return self.error("Cannot handle token %s." % token, token)

    def next_expression(self, lhs, min_precedence):
        # This loop will spin as long as:
        # 1: There is a next token.
        # 2: It is an infix operator.
        # 3: Its precedence is higher than min_precedence.
        while self.tokenizer.peek():
            token = self.tokenizer.peek()

            if token.name != "infix":
                break

            operator = INFIX[token.value]
            if operator.precedence < min_precedence:
                break

            # We're a match - consume the next token.
            self.tokenizer.next_token()

            rhs = self.next_atom()
            next_min_precedence = operator.precedence
            if operator.assoc == "LEFT":
                next_min_precedence += 1

            # Let's see if the next infix operator (if any) is of higher
            # precedence than we are.
            while (self.tokenizer.peek() and
                   self.tokenizer.peek().name == "infix"):
                next_token = self.tokenizer.peek()
                next_operator = INFIX[next_token.value]
                if next_operator.precedence < next_min_precedence:
                    break
                rhs = self.next_expression(rhs, next_operator.precedence)

            lhs = self._handle_expr(operator, lhs, rhs, start=lhs.start,
                                    end=rhs.end)

        return lhs

    def parse(self):
        result = self.next_expression(self.next_atom(), 0)
        # If we didn't consume the whole query then raise.
        if self.tokenizer.peek():
            token = self.tokenizer.peek()
            return self.error(
                "Unexpected %s '%s'. Were you looking for an operator?" %
                (token.name, token.value),
                token)

        return result

    def error(self, message, start_token=None, end_token=None):
        start = self.tokenizer.position
        end = start + 20
        if start_token:
            start = start_token.start
            end = start_token.end

        if end_token:
            end = end_token.end

        raise ParseError(query=self.query, start=start, end=end,
                         error=message, token=start_token)
