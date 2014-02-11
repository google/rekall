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
         "start": "tcpip.sys!_TcpCovetNetBufferList@20",
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
import logging
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


DISASSEMBLER_CACHE = utils.FastStore()


class Disassembler(DynamicParser):
    """A constant generator deriving values based on the disassembler."""

    def __init__(self, start=None, end=None, length=100,
                 rules=None):
        """Derive a value from disassembly.

        Args:
          start: Where to start disassembly (Usually a symbol name).
          end: Where to stop disassembly.

          length: If end is not specified, we disassemble at most this many
            bytes.

          rules: A list of rules (see above).
        """
        self.rules = self.CompileRule(rules)
        self.start = start
        self.length = length
        self.end = end
        self.cached_value = None

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
            line = re.sub(r"([()\[\]\+])", r"\\\1", line)
            line = re.sub(r"\*", r".+?", line)
            line = re.sub(r"\$out", r"(?P<out>[^ \[\]+-]+?)", line)
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
                out = m.groupdict().get("out")

                return i, out

        return None, None

    def _SmallestVector(self, hits):
        """Find the vector with the smallest distance."""
        distance = 1e6
        result = []
        for vector, vector_distance in self.CalcDistance(hits):
            if vector_distance < distance:
                result = vector
                distance = vector_distance

        return result

    def CalcDistance(self, hits):
        n_hits = len(hits)

        while hits[0]:
            for rule in range(1, n_hits):
                while hits[rule] and hits[rule][0] <= hits[rule - 1][0]:
                    hits[rule].pop(0)

                if not hits[rule]:
                    return

            vector = [hits[i][0] for i in hits]
            distance = hits[n_hits - 1][0] - hits[0][0]
            yield vector, distance

            hits[0].pop(0)

    def _calculate(self, session):
        # Try to cache disassembly to speed things up.
        try:
            disassembly = DISASSEMBLER_CACHE.Get(
                (self.start, self.length, self.end))
        except KeyError:
            disassembly = unicode(session.plugins.dis(
                    offset=self.start,
                    length=self.length, end=self.end))

            DISASSEMBLER_CACHE.Put(
                (self.start, self.length, self.end), disassembly)

        hits = {}
        outs = {}

        for hit, line in enumerate(disassembly.splitlines()):
            rule_idx, out = self._FindRuleIndex(line)

            if rule_idx is None:
                continue

            hits.setdefault(rule_idx, []).append(hit)
            if out:
                outs[hit] = out

        for item in self._SmallestVector(hits):
            out = outs.get(item)
            if out:
                return int(out, 0)

        return 0


class DynamicProfile(obj.Profile):
    """A Dynamic profile which parses its overlays from $DYNAMIC_STRUCT."""




def GenerateOverlay(dynamic_definition):
    """Parse the definition and generate an overlay from it."""
    overlay = {}
    for type_name, definition in dynamic_definition.items():
        type_overlay = {}
        overlay[type_name] = [None, type_overlay]

        for field_name, attempts in definition.items():
            parsers = []
            for (parser_name, kwargs) in attempts:
                target = kwargs.pop("target", None)
                target_args = kwargs.pop("target_args", {})

                parsers.append(DynamicParser.classes.get(parser_name)(
                        **kwargs))

            # Make the offset a callable
            # Bind parameters in lambda:
            # pylint: disable=dangerous-default-value
            def offset_cb(x, parsers=parsers, field_name=field_name):
                for p in parsers:
                    result = p.calculate(x.obj_session)
                    if result:
                        return result
                    else:
                        logging.debug(
                            "Unable to find %s.%s via %s", x.obj_name,
                            field_name, p)

                return 0

            type_overlay[field_name] = [offset_cb, [target, target_args]]

    return overlay
