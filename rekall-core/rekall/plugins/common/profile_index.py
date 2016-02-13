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
    "Jordi Sanchez <nop@google.com>"
)

import hashlib
from rekall import obj
from rekall import utils


class IndexProfileLoader(obj.ProfileSectionLoader):
    name = "$INDEX"

    def LoadIntoProfile(self, session, profile, index):
        profile.LoadIndex(index)
        return profile


class Index(obj.Profile):
    """A profile which contains an index to locate other profiles."""
    index = None
    base_offset = 0

    PERFECT_MATCH = 1.0
    GOOD_MATCH = 0.75

    def LoadIndex(self, index):
        self.index = index

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
                self.session.logging.debug(
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
            self.session.logging.debug(
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


class SymbolOffsetIndex(Index):
    """A specialized index that works on symbols-offsets."""

    def __init__(self, *args, **kwargs):
        super(SymbolOffsetIndex, self).__init__(*args, **kwargs)
        if not self.index:
            self.index = {}

    @utils.safe_property
    def hashes(self):
        return self.index.get("$HASHES", {})

    @utils.safe_property
    def traits(self):
        return self.index.get("$TRAITS", {})

    @utils.safe_property
    def profiles(self):
        return self.index.get("$PROFILES", {})

    @utils.safe_property
    def duplicates(self):
        return [p for p in self.index.get("$PROFILES") if p not in self.hashes]

    def LookupProfile(self, symbols):
        """Returns which profiles in the index match a dict of symbols.

        Returns:
            A list of tuples of (profile, num_matched_traits).
        """
        profiles = []
        try:
            relative_symbols = self.RelativizeSymbols(symbols.copy())
        except ValueError as e:
            self.session.logging.debug(str(e))

        for profile, traits in self.traits.iteritems():
            matched_traits = 0

            for trait in traits:
                # A trait is a list of symbol-offset tuples.
                match = all([relative_symbols.get(symbol) == offset
                             for (symbol, offset) in trait])
                if match:
                    matched_traits += 1

            if matched_traits > 0:
                profiles.append((profile, matched_traits))
        return profiles

    def LookupHash(self, profile_hash):
        """Returns the profile with hash profile_hash."""
        return self.hashes.get(profile_hash)

    @classmethod
    def FilterSymbols(cls, symbols):
        """Filters a dict of symbols, discarding irrelevant ones."""
        return symbols

    @classmethod
    def CalculateRawProfileHash(cls, profile):
        """Calculates a hash of a list of symbols."""

        # Skip superfluous symbols.
        symbols = profile["$CONSTANTS"]
        ordered_symbol_list = sorted(
            ["(%s, %d)" % (k, v)
             for (k, v) in cls.FilterSymbols(symbols).iteritems()])

        hasher = hashlib.sha256()
        hasher.update("|".join(ordered_symbol_list))
        return hasher.hexdigest()

    @classmethod
    def CalculateRawSymbolsHash(cls, profile):
        """Calculates a hash of a list of symbols."""

        # Skip superfluous symbols.
        symbols = profile["$CONSTANTS"]
        ordered_symbol_list = sorted(symbols.keys())
        hasher = hashlib.sha256()
        hasher.update("|".join(ordered_symbol_list))
        return hasher.hexdigest()

    def ProfileMetadata(self, profile_name):
        return self.profiles.get(profile_name)

    @classmethod
    def ProfileMatchesTrait(cls, profile, trait):
        """Whether a profile matches another profile's trait.

        A trait is a list of tuples (symbol, offset) that uniquely identify
        a profile.
        """
        return all([profile.get_constant(t[0]) == t[1] for t in trait])

    @classmethod
    def RawProfileMatchesTrait(cls, profile, trait):
        """Whether a raw profile (JSON) matches another profile's trait.

        A trait is a list of tuples (symbol, offset) that uniquely identify
        a profile.
        """
        return all([profile.get(t[0]) == t[1] for t in trait])

    @classmethod
    def BuildIndex(cls, hashes=None, traits=None, duplicates=None, spec=None,
                   iomanager=None):
        """Builds a SymbolOffset index from traits, profiles, hashes and a spec.

        Args:
            hashes: A dictionary of hash:profile_id. Hashes must be obtained via
            the SymbolOffsetIndex.CalculateRawProfileHash() method.

            traits: A dictionary of profile_id:traits. Traits are the result
            of calling the SymbolOffsetIndex.FindTraits() method.

            profiles: A dictionary of profile_id metadata. Profile metadata
            is obtained via SymbolOffsetIndex.GetProfileMetadata().

            duplicates: A list of newly found profile ids that are duplicate.
        """

        spec = spec or {}
        metadata = dict(Type="Index",
                        ProfileClass=spec.get("implementation", cls.__name__),
                        BaseSymbol=spec.get("base_symbol"))

        hashes = hashes or {}
        traits = traits or {}
        # Assert all profiles that have hashes have traits as well
        if not all([profile in hashes.values() for profile in traits]):
            raise ValueError("Not all profiles with traits have hashes")

        # Assert all profiles that have traits have hashes as well
        if not all([profile in traits for profile in hashes.values()]):
            raise ValueError("Not all profiles with hashes have traits")

        profiles = dict([(profile_id,
                          cls.GetProfileMetadata(
                              iomanager=iomanager, profile_id=profile_id))
                         for  profile_id in traits])

        duplicates = duplicates or []
        for duplicate_profile in duplicates:
            profiles[duplicate_profile] = cls.GetProfileMetadata(
                iomanager=iomanager, profile_id=duplicate_profile)

        index = {
            "$METADATA": metadata,
            "$INDEX": {
                "$TRAITS": traits or {},
                "$PROFILES": profiles or {},
                "$HASHES": hashes or {},
            }
        }

        return index

    @classmethod
    def GetProfileMetadata(cls, iomanager=None, profile_id=None):
        profile_metadata = dict()
        file_mtime = iomanager.Metadata(profile_id)["LastModified"]
        profile_metadata["LastModified"] = file_mtime
        return profile_metadata

    def __len__(self):
        return len(self.traits)

    def __iter__(self):
        """Yields tuples of profile_id, traits.

        Each trait is a list of tuples of (symbol, offset) that make this
        profile unique within the repository.
        """
        for profile, traits in self.index.get("$TRAITS").iteritems():
            yield profile, traits

    def RelativizeSymbols(self, symbols, base_symbol=None):
        """Modifies a dict of symbols so its offsets relative to base_symbol.
        If no base_symbol is provided and the index itself doesn't define one
        then returns the symbols as is.

        Args:
            symbols: A dictionary of symbol:value
            base_symbol: The name of the symbol to base others' values on.
        """

        if not base_symbol:
            base_symbol = self.metadata("BaseSymbol")

        if not base_symbol:
            return symbols

        base_value = symbols.get(base_symbol)
        if not base_value:
            raise ValueError("Symbol %s not found in profile", base_symbol)
        new_symbols = symbols.copy()
        for symbol, value in new_symbols.iteritems():
            new_symbols[symbol] = value - base_value
        return new_symbols


class LinuxSymbolOffsetIndex(SymbolOffsetIndex):
    """Specialized symbol-offset index for linux."""

    @classmethod
    def FilterSymbols(cls, symbols):
        """Filters a dict of symbols, discarding irrelevant ones."""
        return dict([(k, v) for (k, v) in symbols.iteritems()
                     if not "." in k and k != "__irf_end"])

    @classmethod
    def BuildIndex(cls, hashes=None, traits=None, duplicates=None, spec=None,
                   iomanager=None):
        index = super(LinuxSymbolOffsetIndex, cls).BuildIndex(
            hashes=hashes, traits=traits, spec=spec, duplicates=duplicates,
            iomanager=iomanager)
        # By default, we'll calculate KASLR from linux_proc_banner which is
        # present on all kernels.
        spec = spec or {}
        index["$METADATA"]["BaseSymbol"] = spec.get("base_symbol",
                                                    "linux_proc_banner")
        return index
