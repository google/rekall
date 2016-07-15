# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
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

"""Routines for manipulating yara rule definitions."""

import string
import sys
import yaml
import pyparsing


_RULE = pyparsing.Keyword("rule")
_KEYWORD = (pyparsing.Literal("wide") |
            pyparsing.Literal("fullword") |
            pyparsing.Literal("ascii") |
            pyparsing.Literal("nocase"))

_IDENTIFIER = pyparsing.Word(pyparsing.alphanums + '_' + "$")
_REGEX = (pyparsing.QuotedString("/", escChar="\\", unquoteResults=False) +
          pyparsing.Optional(pyparsing.Word("sig")))
_LEFT_CURLY = pyparsing.Literal("{")
_RIGHT_CURLY = pyparsing.Literal("}")
_COLON = pyparsing.Literal(':')
_EQUALS = pyparsing.Literal("=")


def anything_beetween(opener_and_closer):
    """Builds a (pyparsing) parser for the content inside delimiters.

    Args:
    opener_and_closer: a string containing two elements: opener and closer

    Returns:
      A (pyparsing) parser for the content inside delimiters.
    """
    opener = pyparsing.Literal(opener_and_closer[0])
    closer = pyparsing.Literal(opener_and_closer[1])
    char_removal_mapping = dict.fromkeys(map(ord, opener_and_closer))
    other_chars = unicode(string.printable).translate(char_removal_mapping)
    word_without_delimiters = pyparsing.Word(other_chars).setName(
        "other_chars")
    anything = pyparsing.Forward()
    delimited_block = opener + anything + closer
    # pylint: disable=expression-not-assigned
    anything << pyparsing.ZeroOrMore(
        word_without_delimiters.setName("word_without_delimiters")
        | delimited_block.setName("delimited_block")
    )

    # Combine all the parts into a single string.
    return pyparsing.Combine(anything)

def anything_in(opener_and_closer):
    opener = opener_and_closer[0]
    closer = opener_and_closer[1]
    anything = anything_beetween(opener_and_closer)
    return opener + anything + closer

def anything_in_curly():
    return anything_in('{}')

def meta_section():
    return pyparsing.Group(
        pyparsing.Literal("meta") +
        _COLON +
        pyparsing.OneOrMore(
            statement()
        ).setResultsName("statements")
    ).setResultsName("meta")

def statement():
    return pyparsing.Group(
        _IDENTIFIER.setResultsName("lhs") + _EQUALS +
        pyparsing.Combine(
            (anything_in_curly() |
             pyparsing.QuotedString("'", escChar="\\", unquoteResults=False) |
             pyparsing.QuotedString("\"", escChar="\\", unquoteResults=False) |
             _REGEX) +
            pyparsing.ZeroOrMore(_KEYWORD),
            adjacent=False,
            joinString=" ",
        ).setResultsName("rhs")
    )

def strings_section():
    return pyparsing.Group(
        pyparsing.Literal("strings") +
        _COLON +
        pyparsing.OneOrMore(statement()).setResultsName("statements")
    ).setResultsName("strings")

def condition_section():
    return (_IDENTIFIER +
            _COLON +
            pyparsing.SkipTo(_RIGHT_CURLY).setResultsName("statement")
    ).setResultsName("condition")

def section():
    return (strings_section() |
            meta_section() |
            condition_section())

def rule():
    return (_RULE +
            _IDENTIFIER.setResultsName("name") +
            _LEFT_CURLY +
            pyparsing.OneOrMore(section()) +
            _RIGHT_CURLY)

def yara_parser():
    return pyparsing.OneOrMore(rule())

def rule_to_ast(parsed_rule):
    condition = parsed_rule["condition"]["statement"]

    result = dict(name=parsed_rule["name"],
                  meta={},
                  strings=[],
                  condition=condition)

    for x in parsed_rule.get("meta", {}).get("statements", []):
        result["meta"][x["lhs"]] = x["rhs"]

    for x in parsed_rule.get("strings", {}).get("statements", []):
        result["strings"].append((x["lhs"], x["rhs"]))

    return result

def parse_yara_to_ast(yara_rules):
    """Parse a yara rules file into a python AST."""
    # Strip c like comments.
    yara_rules = pyparsing.cppStyleComment.suppress().transformString(
        yara_rules)

    result = []
    for rules, _, _ in rule().parseWithTabs().scanString(yara_rules):
        try:
            result.append(rule_to_ast(rules))
        except Exception:
            pass

    return result

def ast_to_yara(parsed_rules):
    result = []
    for rule_ast in parsed_rules:
        result.append("rule %s {" % rule_ast["name"])
        metadata = rule_ast.get("meta")
        if metadata:
            result.append("   meta:")
            for k, v in metadata.iteritems():
                result.append("       %s = %s" % (k, v))

        if rule_ast.get("strings"):
            result.append("   strings:")
            for k, v in sorted(rule_ast["strings"]):
                result.append("       %s = %s" % (k, v))

        result.append("   condition: %s" % rule_ast["condition"])
        result.append(" }")
    return "\n".join(result)


if __name__ == "__main__":
    action = sys.argv[1]
    filename = sys.argv[2]
    if action == "parse":
        data = open(filename).read()
        print yaml.safe_dump(
            parse_yara_to_ast(data),
            default_flow_style=False)
    elif action == "encode":
        data = open(filename).read()
        print ast_to_yara(yaml.safe_load(data))
    else:
        raise RuntimeError("Unknown action %s" % action)
