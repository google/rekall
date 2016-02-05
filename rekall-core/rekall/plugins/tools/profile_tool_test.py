"""Tests for profile_tool."""

import logging
import unittest

from rekall import session
from rekall import testlib
from rekall.plugins.tools import profile_tool


class BuildIndexTester(profile_tool.BuildIndex):
    def __init__(self, profiles=None, **kwargs):
        super(BuildIndexTester, self).__init__(**kwargs)
        self.profiles = profiles

    def _LoadRawProfile(self, filepath):
        self.profiles[self._ProfileIdFromPath(filepath)]

    def _FindNewProfiles(self, *args, **kwargs):
        return self.profiles


class BuildSymbolOffsetIndexTest(testlib.RekallBaseUnitTestCase):
    def setUp(self):
        # This is the set of profiles we're trying to index. It covers all
        # the edge cases I've seen "in the wild" so far.
        self.raw_profiles = {
            # P1 is a profile that will have a single symbol trait = c:3 once
            # we remove duplicates.
            "P1": {
                "$CONSTANTS":
                {
                    "a": 1,
                    "b": 2,
                    "c": 3
                }
            },
            # P1-DUPLICATE is simply a duplicate profile from P1, to test that
            # we detect and discard profiles that are new and duplicates with
            # other new profiles.
            "P1-DUPLICATE": {
                "$CONSTANTS":
                {
                    "a": 1,
                    "b": 2,
                    "c": 3,
                }
            },
            # P1-1 is simply a newer version of P1. Simulates the usual
            # minor kernel version bump where some symbols are readjusted.
            # Single symbol traits = c:4
            "P1-1": {
                "$CONSTANTS":
                {
                    "a": 1,
                    "b": 2,
                    "c": 4
                }
            },

            # P1-2 simulates a slightly newer P1 profile that's virtually the
            # same but has an artifact of a static function that's been
            # chunked by GCC and its symbol made public.
            #
            # Real-world example:
            #   * Ubuntu precise 3.19.0-21-generic
            #   * Ubuntu precise 3.19.0-22-generic
            #
            # P1-2 should be considered a duplicate of P1.
            "P1-2": {
                        #
                        # function that's been chunked by GCC and its symbol
                        # made public.
                "$CONSTANTS":
                {
                    "a": 1,
                    "b": 2,
                    "c": 3,
                    "d.part.3": 4
                }
            },

            # P3 is a completely different profile.
            # Single symbol traits = b:3, c:5, d:6
            "P3": {
                "$CONSTANTS":
                {
                    "b": 3,
                    "c": 5,
                    "d": 6
                }
            },

            # Next is an example of profiles that collectively clash with
            # another profile. DOPPLE-1 and DOPPLE-2 make DOPPLE not have any
            # single-symbol trait. This forces us to compute traits with a
            # pair of symbols.
            #
            # Real-world example:
            #   * Ubuntu precise 3.2.0-72-generic
            #   * Ubuntu precise 3.2.0-73-generic
            #   * Ubuntu precise 3.2.0-74-generic
            # Single-symbol traits = d:9
            "DOPPLE-1": {
                "$CONSTANTS":
                {
                    "b": 7,
                    "c": 8,
                    "d": 9
                }
            },
            # The clashing profile.
            # Double-symbol trait = (b:7, d:10)
            "DOPPLE": {
                "$CONSTANTS":
                {
                    "b": 7,
                    "c": 8,
                    "d": 10
                }
            },
            # Single-symbol traits = b:1
            "DOPPLE-2": {
                "$CONSTANTS":
                {
                    "b": 1,
                    "c": 8,
                    "d": 10
                }
            },
        }

        self.build_index = BuildIndexTester(profiles=self.raw_profiles,
                                            session=session.Session())
        # A dict of profile_symbols.
        self.symbols_dict = dict([(x[0], x[1].get("$CONSTANTS"))
                                  for x in self.raw_profiles.iteritems()])

    def testFindTraits(self):
        traits = self.build_index._FindTraits(
            profile_id="P3",
            profiles=self.symbols_dict,
            num_traits=3, trait_length=1)
        self.assertListEqual(sorted(traits),
                             [
                                 [("b", 3)],
                                 [("c", 5)],
                                 [("d", 6)]
                             ])


        # We can't find any traits when there are duplicates
        traits = self.build_index._FindTraits(
            profile_id="P1",
            profiles=self.symbols_dict,
            num_traits=3, trait_length=1)
        self.assertListEqual(sorted(traits), [])

        # But if we remove duplicates, we find them.
        symbols_dict_nodups = self.symbols_dict.copy()
        symbols_dict_nodups.pop("P1-DUPLICATE")
        symbols_dict_nodups.pop("P1-2")
        traits = self.build_index._FindTraits(
            profile_id="P1",
            profiles=symbols_dict_nodups,
            num_traits=3, trait_length=1)
        self.assertListEqual(sorted(traits),
                             [
                                 [("c", 3)]
                             ])

        # Some profiles simply don't have single symbol traits..
        traits = self.build_index._FindTraits(
            profile_id="DOPPLE",
            profiles=self.symbols_dict,
            num_traits=3, trait_length=1)
        self.assertListEqual(sorted(traits), [])

        # But we can find 2-symbol traits.
        traits = self.build_index._FindTraits(
            profile_id="DOPPLE",
            profiles=self.symbols_dict,
            num_traits=3, trait_length=2)
        self.assertListEqual(sorted(traits),
                             [
                                 [("b", 7), ("d", 10)],
                             ])

    def testFindProfilesWithSymbolOffset(self):
        results = self.build_index._FindProfilesWithSymbolOffset(
            "b", 7, profiles=self.symbols_dict)
        self.assertEqual(results,
                         set(["DOPPLE-1", "DOPPLE"]))

        results = self.build_index._FindProfilesWithSymbolOffset(
            "NONEXISTING", 12, profiles=self.symbols_dict)
        self.assertEqual(results, set())



if __name__ == '__main__':
  logging.basicConfig(level=logging.DEBUG)
  unittest.main()
