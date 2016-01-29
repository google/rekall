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
            context = dict(
                instruction=instruction.text, offset=instruction.address)
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

    def MatchFunction(self, func, length=1000):
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
            self.session.logging.error(
                "Failed to find match for %s - Only matched %s/%s rules.",
                self.name, len(vector), len(self.rules))
            return obj.NoneObject()

        self.session.logging.debug("Found match for %s", self.name)

        result = {}
        for i, hit in enumerate(vector):
            hit_data = contexts[i][hit]
            result.update(hit_data)
            self.session.logging.debug(
                "%#x %s", hit_data["offset"], hit_data["instruction"])

        return result


class DisassembleConstantMatcher(object):
    """Search for the value of global constants using disassembly."""

    def __init__(self, session, profile, name, args):
        self.session = session
        self.profile = profile
        self.args = args
        self.name = name
        # Start address to disassemble - can be an exported function name.
        self.start_address = args["start"]

        # Disassemble capture rules.
        self.rules = args["rules"]

    def __call__(self):
        resolver = self.session.address_resolver
        func = self.session.profile.Function(resolver.get_address_by_name(
            self.start_address))

        matcher = DisassembleMatcher(
            mode=func.mode, rules=self.rules, name=self.name,
            session=self.session)

        result = matcher.MatchFunction(func)
        if result and "$out" in result:
            return result["$out"]


class FirstOf(object):
    """Try a list of callables until one works."""
    def __init__(self, list_of_callables, **kwargs):
        self.list_of_callables = list_of_callables
        self.kwargs = kwargs

    def __call__(self, *args):
        for func in self.list_of_callables:
            result = func(*args, **self.kwargs)
            if result != None:
                return result


class DynamicConstantProfileLoader(obj.ProfileSectionLoader):
    """Produce a callable for a constant."""
    name = "$DYNAMIC_CONSTANTS"

    def LoadIntoProfile(self, session, profile, constants):
        """Parse the constants detectors and make callables."""
        for constant_name, rules in constants.items():
            detectors = []

            # Each constant can have several different detectors.
            for rule in rules:
                detector_name = rule["type"]
                detector_arg = rule["args"]

                # We only support one type of detector right now.
                if detector_name != "DisassembleConstantMatcher":
                    session.logging.error(
                        "Unimplemented detector %s", detector_name)
                    continue

                detectors.append(
                    DisassembleConstantMatcher(
                        session, profile, constant_name, detector_arg))

            profile.add_constants({constant_name: FirstOf(detectors)},
                                  constants_are_absolute=True)

        return profile


class DisassembleStructMatcher(DisassembleConstantMatcher):
    """Match a struct based on rules."""

    def __call__(self, struct, member=None):
        resolver = struct.obj_session.address_resolver
        func = struct.obj_profile.Function(resolver.get_address_by_name(
            self.start_address))

        matcher = DisassembleMatcher(
            mode=func.mode, rules=self.rules, name=self.name,
            max_separation=self.args.get("max_separation", 10),
            session=struct.obj_session)

        struct.obj_session.logging.info(
            "DisassembleStructMatcher: %s %s", self.name,
            self.args.get("comment", ""))
        result = matcher.MatchFunction(func)
        if result:
            # Match succeeded - create a new overlay for the Struct.
            overlay = {self.name: [None, {}]}
            fields = overlay[self.name][1]
            for field, field_args in self.args["fields"].iteritems():
                fields[field] = [result["$" + field], field_args]

            # This should never happen?
            if member not in fields:
                return

            # We calculated the types, now we add them to the profile so the
            # next time a struct is instantiated it will be properly
            # initialized.
            struct.obj_profile.add_types(overlay)

            # Now take care of the current struct which has already been
            # initialized.
            struct.members.update(struct.obj_profile.Object(self.name).members)

            # Return the member from the current struct.
            return struct.m(member)


class DynamicStructProfileLoader(obj.ProfileSectionLoader):
    """Produce a callable for a constant."""
    name = "$DYNAMIC_STRUCTS"

    def LoadIntoProfile(self, session, profile, data):
        """Parse the constants detectors and make callables."""
        overlay = {}
        for struct_name, signatures in data.items():
            detectors = {}

            # Each field can have several different detectors.
            for rule in signatures:
                detector_name = rule["type"]
                detector_arg = rule["args"]

                # We only support one type of detector right now.
                if detector_name != "DisassembleStructMatcher":
                    session.logging.error(
                        "Unimplemented detector %s", detector_name)
                    continue

                detector = DisassembleStructMatcher(
                    None, None, struct_name, detector_arg)

                # Add the detector to each field. The initial detector is a
                # pass-through which returns the normal member if one is defined
                # in the conventional way. If None is defined, we launch our
                # dynamic detector - which will store the conventional member
                # definitions as a cache.
                def PassThrough(struct, member=None):
                    return struct.m(member)

                for field in detector_arg["fields"]:
                    detectors.setdefault(field, [PassThrough]).append(detector)

            # Install an overlay with the chain of detectors.
            overlay[struct_name] = [None, {}]
            for field in detectors:
                overlay[struct_name][1][field] = FirstOf(
                    detectors[field], member=field)

        profile.add_overlay(overlay)
        return profile
