# Rekall Memory Forensics
#
# Copyright 2014 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@google.com>
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

"""This module generates types automatically by disassembling code.

Generally Rekall prefers to use publicly available debugging information for
building profiles for the different operating systems supported. However, in
many cases, the symbols we need are not publicly available.

We can, in theory distribute hand written profiles, for each OS version but this
has a number of disadvantages:

- It is very time intensive to prepare hand written profiles for each version of
  the operating system.

- It is not possible for us to test all possible versions (The Rekall profile
  repository has currently hundreds of windows kernel builds - we would need to
  maintain the profiles for each of these versions, and add new profiles each
  time a hotfix is released.

- We also need to document how we arrive at these offsets in order for others to
  verify our finding. It is important for a forensic application to be as
  transparent as possible without "magic numbers" in code.

An additional requirement is that the disassembly process be data driven. This
way we can update the exact algorithm within the Rekall profile repository if an
error or bug is discovered without needing to update all current users of the
tool.


How does it work?
=================

The DynamicProfile profile is loaded from the profile repository as normal. Like
in a regular profile, the profile is defined by a json object. A DynamicProfile
however, contains an additional section $DYNAMIC_STRUCT, which will be compiled
into overlays.


{
 "$METADATA": {
   .....
 }

 "$DYNAMIC_STRUCT": {
   "_TCP_LISTENER": {
     "Owner": [
       ["Disassembler", {
         "start": "tcpip.sys!_TcpCovetNetBufferList",
         "rule": [
           "MOV EAX, [ESI+$out]",
           "TEST EAX, EAX",
           "PUSH EAX",
           "CALL DWORD *__imp__PsGetProcessId",
         ],
         target="unsigned int"
       }]
      ]
    }
  }
}
"""

__author__ = "Michael Cohen <scudette@gmail.com>"

import re

from rekall import registry
from rekall import obj
from rekall import utils


class DynamicParser(object):
    """A dynamic profile processor base class."""

    __metaclass__ = registry.MetaclassRegistry

    def calculate(self, session):
        """Returns the expected value or a NoneObject."""
        _ = session
        return obj.NoneObject("No value found")


class Disassembler(DynamicParser):
    """A constant generator deriving values based on the disassembler."""

    def __init__(self, session=None, name=None, start=None, end=None,
                 length=300, rules=None, max_separation=10):
        """Derive a value from disassembly.

        Args:
          start: Where to start disassembly (Usually a symbol name).
          end: Where to stop disassembly.

          length: If end is not specified, we disassemble at most this many
            bytes.

          rules: A list of rules (see above).
        """
        self.session = session
        self.text_rules = rules
        self.rules = self.CompileRule(rules)
        self.start = start
        self.length = length
        self.end = end
        self.name = name
        self.cached_value = None
        self.max_separation = max_separation

    def __str__(self):
        return "Disassemble %s" % self.start

    def CompileRule(self, rule):
        """Convert the rule into a regular expression.

        Rules are a list of patterns. Each pattern corresponds to a single
        instruction. There can be an arbitrary number of instructions between
        each rule.

        Output is captured using $out (this can only be specified once). Wild
        cards are denoted by *. Wildcards only apply across a single instruction
        (and comment). The following is an example of a rule:

        MOV EAX, [ESI+$out]
        TEST EAX, EAX
        PUSH EAX
        CALL DWORD *__imp__PsGetProcessId
        """
        # Sanitize all regular expression chars in the rule.
        result = []
        for line in rule:
            # Escape regex sensitive chars.
            line = re.sub(r"([()\[\]\+])", r"\\\1", line)

            # Wildcards
            line = re.sub(r"\*", r".+?", line)

            # Capture variable. The same capture variable may be specified more
            # than once in the same rule, so we need to append the instance
            # number of the capture variable to make it unique.
            self.instance = 0
            def _ReplaceCaptureVars(match):
                self.instance += 1
                return r"(?P<%s_%s>[^ \[\]+-]+)" % (
                    match.group(1), self.instance)

            line = re.sub(r"\$([a-zA-Z0-9]+)", _ReplaceCaptureVars, line)
            result.append(re.compile(line, re.S | re.M))

        return result

    def calculate(self, session):
        if self.cached_value is not None:
            return self.cached_value

        self.cached_value = self._calculate(session)
        return self.cached_value

    def _FindRuleIndex(self, line):
        for i, rule in enumerate(self.rules):
            # At every line we check if the current rule can be matched - if
            # it can then it is a better match.
            m = rule.search(line)
            if m:
                yield i, m.groupdict()

    def _CheckCaptureVariables(self, vector, contexts):
        """Checks that capture variables are consistent in the vector.

        The vector is a list of disassembly lines which match the rules, e.g.

        [16, 60, 61]

        The context is the capture variables from these rules. In order
        to be valid, the capture variables must all be consistent. For
        example the following is not consistent (since var1 is RAX in
        the first rule and RCX in the second rule):

        contexts[16]
        {'var1': u'RAX'}

        contexts[60]
        {'var1': u'RCX', 'out': u'0x88'}

        contexts[61]
        {}
        """
        result = {}
        for rule_number, item in enumerate(vector):
            rule_context = contexts[rule_number]
            # The capture variables in this rule only.
            rule_capture_vars_values = {}

            for k, v in rule_context[item].iteritems():
                var_name = k.rsplit("_", 1)[0]

                # If this var is previously known, this match must be the same
                # as previously found.
                if var_name in result and v != result[var_name]:
                    return

                # If this capture variable's value is the same as another
                # capture variable's value in the same rule, exclude the
                # match. This means that an expression like:
                #
                #     MOV $var2, [$var1+$out]
                #
                # Necessarily implies that $var1 and $var2 must be different
                # registers.
                if (v in rule_capture_vars_values and
                        rule_capture_vars_values[v] != var_name):
                    return

                result[var_name] = v
                rule_capture_vars_values[v] = var_name

        return result

    def _GetMatch(self, hits, contexts):
        """Find the first vector that matches all the criteria."""
        for vector in self.GenerateVector(hits, [], 0):
            context = self._CheckCaptureVariables(vector, contexts)
            if not context:
                continue

            return (vector, context)

        return [], {}

    def GenerateVector(self, hits, vector, level):
        for item in hits.get(level, []):
            if vector:
                if item < vector[-1]:
                    continue

                if item > self.max_separation + vector[-1]:
                    break

            new_vector = vector + [item]

            if level + 1 == len(hits):
                yield new_vector

            elif level + 1 < len(hits):
                for result in self.GenerateVector(
                        hits, new_vector, level+1):

                    yield result

    def _calculate(self, session):
        # Try to cache disassembly to speed things up.
        try:
            disassembler_cache = self.session.GetParameter(
                "disassembler_cache", utils.FastStore())

            disassembly = disassembler_cache.Get(
                (self.start, self.length, self.end))

        except KeyError:
            disassembly = unicode(session.plugins.dis(
                offset=self.start, branch=True,
                length=self.length, end=self.end))

            disassembler_cache.Put(
                (self.start, self.length, self.end), disassembly)

            self.session.SetCache("disassembler_cache", disassembler_cache)

        hits = {}
        contexts = {}

        disassembly = disassembly.splitlines()
        for hit, line in enumerate(disassembly):
            for rule_idx, context in self._FindRuleIndex(line):
                hits.setdefault(rule_idx, []).append(hit)
                contexts.setdefault(rule_idx, {})[hit] = context

        # All the hits must match
        if len(hits) < len(self.rules):
            self.session.logging.error("Failed to find match for %s", self.name)

            # Add some debugging messages here to make diagnosing errors easier.
            for i, rule in enumerate(self.text_rules):
                if i not in hits:
                    self.session.logging.debug("Unable to match rule: %s", rule)

            return 0

        vector, context = self._GetMatch(hits, contexts)

        if len(vector) < len(self.rules):
            self.session.logging.error("Failed to find match for %s.",
                                       self.name)
            return 0

        self.session.logging.debug("Found match for %s", self.name)
        for x in vector:
            self.session.logging.debug(disassembly[x])

        return int(context.get("out", "0"), 0)


class DynamicProfile(obj.Profile):
    """A Dynamic profile which parses its overlays from $DYNAMIC_STRUCT."""




def GenerateOverlay(session, dynamic_definition):
    """Parse the definition and generate an overlay from it."""
    overlay = {}
    for type_name, definition in dynamic_definition.items():
        type_overlay = {}
        overlay[type_name] = [None, type_overlay]

        for field_name, attempts in definition.items():
            parsers = []
            for (parser_name, kwargs) in attempts:
                kwargs = kwargs.copy()
                target = kwargs.pop("target", None)
                target_args = kwargs.pop("target_args", {})
                name = "%s.%s" % (type_name, field_name)

                parsers.append(DynamicParser.classes.get(parser_name)(
                    session=session, name=name, **kwargs))

            # Make the offset a callable
            # Bind parameters in lambda:
            # pylint: disable=dangerous-default-value,cell-var-from-loop
            def offset_cb(x, parsers=parsers, field_name=field_name):
                for p in parsers:
                    result = p.calculate(x.obj_session)
                    if result:
                        return result
                    else:
                        session.logging.debug(
                            "Unable to find %s.%s via %s", x.obj_name,
                            field_name, p)

                return 0

            type_overlay[field_name] = [offset_cb, [target, target_args]]

    return overlay
