# Rekall Memory Forensics
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

"""This module implements profile indexing.

Rekall relies on accurate profiles for reliable analysis of memory artifacts. We
depend on selecting the correct profile from the profile repository, but
sometimes it's hard to determine the exact profile to use. The profile
repository has index files that are used to lookup the correct profile quickly,
based on a limited set of symbols and offsets that are known, or can be easily
detected, about the image.
"""

__author__ = (
    "Michael Cohen <scudette@google.com>",
    "Adam Sindelar <adamsh@google.com>",
)

import logging

from rekall import obj


class Index(obj.Profile):
    """A profile which contains an index to locate other profiles."""
    index = None
    base_offset = 0

    PERFECT_MATCH = 1.0
    GOOD_MATCH = 0.75

    def _SetupProfileFromData(self, data):
        super(Index, self)._SetupProfileFromData(data)
        self.index = data.get("$INDEX")

    def copy(self):
        result = super(Index, self).copy()
        result.index = self.index.copy()

        return result

    def _TestSymbols(self, address_space, offset, possible_values):
        """Match any of the possible_values at offset.

        Return True if there is a match.
        """
        for value in possible_values:
            value = value.decode("hex")
            data = address_space.read(offset, len(value))
            if value == data:
                return data

    def _TestProfile(self, address_space, image_base, profile, symbols,
                     minimal_match=1):
        """Match _all_ the symbols against this data."""
        count_matched = 0
        count_unmatched = 0

        for offset, possible_values in symbols:
            # The possible_values can be a single string which means there is
            # only one option. If it is a list, then any of the symbols may
            # match at this offset to be considered a match.
            if isinstance(possible_values, basestring):
                possible_values = [possible_values]

            # If the offset is not mapped in we can not compare it. Skip it.
            offset_to_check = image_base + offset
            if address_space.vtop(offset_to_check) == None:
                continue

            match = self._TestSymbols(
                address_space=address_space,
                offset=offset_to_check,
                possible_values=possible_values)

            if match:
                logging.debug(
                    "%s matched offset %#x+%#x=%#x (%r)",
                    profile, offset, image_base, offset+image_base, match)
                count_matched += 1

            else:
                # FIXME: We get here if the comparison point does not match -
                # does it make sense to allow some points to not match? Should
                # we consider these a failure to match?
                count_unmatched += 1

        # Require at least this many comparison points to be matched.
        if count_matched < minimal_match:
            return 0

        if count_matched > 0:
            logging.debug(
                "%s matches %d/%d comparison points",
                profile, count_matched, count_matched + count_unmatched)

            return float(count_matched) / (count_matched + count_unmatched)

        return 0

    def IndexHits(self, image_base, address_space=None, minimal_match=1):
        if address_space == None:
            address_space = self.session.GetParameter("default_address_space")

        for profile, symbols in self.index.iteritems():
            match = self._TestProfile(
                address_space=address_space,
                image_base=image_base,
                profile=profile,
                minimal_match=minimal_match,
                symbols=symbols)

            yield match, profile

    def LookupIndex(self, image_base, address_space=None, minimal_match=1):
        partial_matches = []
        for match, profile in self.IndexHits(image_base, address_space,
                                             minimal_match=minimal_match):
            if match == self.PERFECT_MATCH:
                # Yield perfect matches right away.
                yield (profile, self.PERFECT_MATCH)

            elif match > 0:
                # Imperfect matches will be saved and returned in order of
                # accuracy.
                partial_matches.append((match, profile))

        partial_matches.sort(reverse=True)
        for match, profile in partial_matches:
            yield (profile, match)
