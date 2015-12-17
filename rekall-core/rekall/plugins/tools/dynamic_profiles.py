# Rekall Memory Forensics
#
# Copyright 2015 Google Inc. All Rights Reserved.
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

"""This module implements dynamic profiles.

A Dynamic profile is a way of discovering certain parameters via running a
matching signature.
"""
from rekall import obj
from rekall.plugins.tools import disassembler


class DisassembleMatcher(object):
    """A matching engine for disassembler rules.

    This matcher searcher for a sequence of rules in a disassmbly and tries to
    match a certain rule pattern to the assembly. Ultimately if the rules match,
    the rules may extract certain parameters from the patter.
    """

    def __init__(self, name="", mode="AMD64", rules=None, session=None,
                 max_separation=10):
        self.mode = mode
        self.name = name
        self.rules = rules
        self.session = session
        self.max_separation = max_separation
        self.dis = disassembler.Capstone(self.mode, session=self.session)

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

                # Only consider variables (start with $).
                if not var_name.startswith("$"):
                    continue

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

    def _FindRuleIndex(self, instruction):
        """Generate all rules that match the current instruction."""
        for i, rule in enumerate(self.rules):
            context = dict(instruction=instruction.text)
            if instruction.match_rule(rule, context):
                yield i, context

    def GenerateVector(self, hits, vector, level):
        """Generate possible hit vectors which match the rules."""
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
                for result in self.GenerateVector(hits, new_vector, level+1):
                    yield result

    def _GetMatch(self, hits, contexts):
        """Find the first vector that matches all the criteria."""
        for vector in self.GenerateVector(hits, [], 0):
            context = self._CheckCaptureVariables(vector, contexts)
            if not context:
                continue

            return (vector, context)

        return [], {}

    def MatchFunction(self, func, length=100):
        return self.Match(
            func.obj_offset, func.obj_vm.read(func.obj_offset, length))

    def Match(self, offset=0, data=""):
        hits = {}
        contexts = {}

        for hit, instruction in enumerate(self.dis.disassemble(data, offset)):
            for rule_idx, context in self._FindRuleIndex(instruction):
                hits.setdefault(rule_idx, []).append(hit)
                contexts.setdefault(rule_idx, {})[hit] = context

        # All the hits must match
        if len(hits) < len(self.rules):
            self.session.logging.error("Failed to find match for %s", self.name)

            # Add some debugging messages here to make diagnosing errors easier.
            for i, rule in enumerate(self.rules):
                if i not in hits:
                    self.session.logging.debug("Unable to match rule: %s", rule)

            return obj.NoneObject()

        vector, context = self._GetMatch(hits, contexts)

        if len(vector) < len(self.rules):
            self.session.logging.error("Failed to find match for %s.",
                                       self.name)
            return obj.NoneObject()

        self.session.logging.debug("Found match for %s", self.name)

        result = {}
        for i, hit in enumerate(vector):
            result.update(contexts[i][hit])
            self.session.logging.debug(contexts[i][hit]["instruction"])

        return result
