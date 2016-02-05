"""Tests for profile_index."""

import logging
import unittest

from rekall import session
from rekall import testlib
from rekall.plugins.common import profile_index


class SymbolOffsetIndexTest(testlib.RekallBaseUnitTestCase):
    def setUp(self):

        self.test_index_data = {
            "$METADATA":
            {
                "ProfileClass": "SymbolOffsetIndex",
                "Type": "SymbolOffsetIndex",
                "Version": 1,
                "BaseSymbol": "c",
            },
            "$INDEX":
            {
                "$PROFILES":
                {
                    "P1": { "LastModified": 12345 },
                    "P1-1": { "LastModified": 12346 },
                    "P3": { "LastModified": 12347 },
                },
                "$TRAITS":
                {
                    "P1":
                    [
                        [["a", -2]],
                    ],
                    "P1-1":
                    [
                        [["a", -3]],
                    ],
                    "P3":
                    [
                        [["d", 1]],
                        [["e", 4]]
                    ],
                },
                "$HASHES":
                {
                }
            }
        }

        self.profiles = [
            ("P1", {
                "$CONSTANTS":
                {
                    "a": 1,
                    "b": 2,
                    "c": 3
                }
            }),
            ("P1-DUPLICATE", {  # This is a duplicate profile
                "$CONSTANTS":
                {
                    "a": 1,
                    "b": 2,
                    "c": 3,
                }
            }),
            ("P1-1", {  # P1-1 simulates a slightly newer P1 profile
                "$CONSTANTS":
                {
                    "a": 1,
                    "b": 2,
                    "c": 4
                }
            }),
            ("P3", {  # P3 simulated a completely different profile
                "$CONSTANTS":
                {
                    "b": 3,
                    "c": 5,
                    "d": 6,
                    "e": 9
                }
            }),
        ]

        self.dummy_index = profile_index.SymbolOffsetIndex.LoadProfileFromData(
            self.test_index_data, session=session.Session())

    def testHashingIsStable(self):
        """Test that hashing the same profile twice leads to the same hash."""
        hash1 = profile_index.SymbolOffsetIndex.CalculateRawProfileHash(
            self.profiles[0][1])
        hash2 = profile_index.SymbolOffsetIndex.CalculateRawProfileHash(
            self.profiles[0][1])
        self.assertEqual(hash1, hash2)

    def testLookupProfileWorksOnProfilesInTheIndex(self):
        # This emulates having parsed kallsyms
        # We fake-find a "P1" profile on a live machine
        symbols = self.profiles[0][1].get("$CONSTANTS")

        profiles = self.dummy_index.LookupProfile(symbols)
        self.assertEqual(len(profiles), 1)  # Only 1 profile matches
        self.assertEqual(profiles[0][0], "P1")  # It's "P1"
        self.assertEqual(profiles[0][1], 1)  # And only 1 trait matched

    def testLookupProfileWorksWithKaslr(self):
        # We're gonna SHIFT P1 by 0x20000, just like the Linux kernel does
        profile = self.profiles[0][1]
        symbols = dict([(i[0], i[1]+0x200000)
                        for i in profile["$CONSTANTS"].iteritems()])


        profiles = self.dummy_index.LookupProfile(symbols)
        self.assertEqual(len(profiles), 1)  # Only 1 profile matches
        self.assertEqual(profiles[0][0], "P1")  # It's "P1"
        self.assertEqual(profiles[0][1], 1)  # And only 1 trait matched

    def testLookupProfileDetectsUnknownProfiles(self):
        # We'll have at least 3 cases where profile matching will find new
        # profiles:
        #   1) No match. If no profile matches, this is clearly a new profile.
        #   2) Partial match. A profile that only matches some traits is a new
        #   profile that clashes with a known profile in the repository.
        #   3) Several matches. A profile that matches more than one profile in
        #   the index is a new profile that clashes with several profiles and
        #   affects the quality of the index.
        #
        # Additionally, there's a chance a new profile may remain undiscovered
        # when it matches all traits of a currently known profile, yet is
        # actually slightly different.

        # Unknown profile.
        symbols1 = { "x": 99, "c": 14}
        profiles = self.dummy_index.LookupProfile(symbols1)
        self.assertEqual(len(profiles), 0)

        # Partial match
        symbols2 = { "c": 5, "d": 6, "e": 20}
        profiles = self.dummy_index.LookupProfile(symbols2)
        self.assertEqual(len(profiles), 1)

        # Only 1 out of 2 traits matches from P3
        profile = profiles[0][0]
        num_matched_traits = profiles[0][1]
        total_traits = len(self.dummy_index.traits[profile])
        self.assertEqual(num_matched_traits, 1)
        self.assertEqual(total_traits, 2)

        # Several profile matches.
        #   a is at -2 from c (matching P1's trait)
        #   d is at +3 from c (matching one of P3's traits)
        symbols3 = { "a": 3, "c": 5, "d": 6 }
        profiles = self.dummy_index.LookupProfile(symbols3)
        # More than 1 profile matches will mean this profile is new and that we
        # need to recompute the index.
        self.assertEqual(len(profiles), 2)
        self.assertListEqual(sorted([p[0] for p in profiles]),
                             ["P1", "P3"])


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
