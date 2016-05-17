#!/usr/bin/env python2

# Rekall Memory Forensics
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Author: Michael Cohen scudette@google.com
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
Converts Volatility profile files into the Rekall format.

The Volatility profiles are derived by dumping debugging symbols using various
means into a zip file:

- On Linux the output of dwarfdump is stored and parsed on each execution. The
  constants are just copied from the System map.

- On OSX the symbols are produced using the dsymutil tool while the vtypes are
  python files.

- On Windows the vtypes are python files which must be executed.

Rekall profiles are more structured. All profiles contain a metadata file within
the zip archive called "metadata" which simply contains key value pairs encoded
using json. For example:

{
 # This must point at the implementation of this profile (i.e. the class which
 # should be created). Valid values include Linux32, Linux64, WinXPSP1x86
 # etc. You can use the 'info' plugin to see which classes already exist.

 "ProfileClass": "Linux64"

 # This is the name of a member inside this zip file which contains the
 # constant list.

 "Constants":  "System.map.json"

 # This points at a json file within this zip file which contains the vtype
 # definitions for this profile.

 "VTypes": "vtypes.json"
}

We chose to use json to store the vtype data structures because loading json
files in python is extremely quick and leads to much faster start up times than
having to parse the vtypes in other formats (We do not allow loading of vtypes
inside python files because this may lead to arbitrary code execution since the
vtype file needs to be evaluated.).

Often users already have profiles created for Volatility which they want to use
in Rekall. Rather than fall back to the slow and inefficient parsing of these
profiles, Rekall allows users to convert the old profile into a new, efficient
profile representation. This is what this module does with the convert command.

For example, suppose you have an existing profile created for use in Volatility,
you can just convert it to the rekall format:

./tools/profile_converter.py convert Ubuntu-3.0.0-32-generic-pae.zip \
   Ubuntu-3.0.0-32-generic-pae.rekall.json

$ ls -l Ubuntu-3.0.0-32-generic-pae.*
-rw-r----- 1 scudette g 643711 Dec 12 02:12 Ubuntu-3.0.0-32-generic-pae.rekall.json
-rw-r----- 1 scudette g 726480 Dec 12 00:30 Ubuntu-3.0.0-32-generic-pae.zip

Now simply specify the rekall profile using the --profile command line arg.
"""

__author__ = (
    "Michael Cohen <scudette@google.com>",
    "Jordi Sanchez <nop@google.com>"
)

import gzip
import itertools
import json
import os
import random
import re
import StringIO

from rekall import io_manager
from rekall import obj
from rekall import plugin
from rekall import registry
from rekall import testlib
from rekall import utils

from rekall.plugins import core
from rekall.plugins.common import profile_index
from rekall.plugins.overlays.linux import dwarfdump
from rekall.plugins.overlays.linux import dwarfparser
from rekall.plugins.windows import common


class ProfileConverter(object):
    """Base class for converters."""

    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    def __init__(self, input, profile_class=None, session=None):
        self.input = input
        self.session = session
        self.profile_class = profile_class

    def SelectFile(self, regex):
        """Reads the content of the first file which matches regex."""
        for f in self.input.ListFiles():
            if re.search(regex, f, re.I):
                return self.input.Open(f).read()

    def BuildProfile(self, system_map, vtypes, config=None):
        _ = config
        # Sorting the json keys usually achieves much smaller file size due to
        # better compression. Its worth doing it once on conversion.
        result = {
            "$METADATA": dict(ProfileClass=self.profile_class,
                              Type="Profile", Version=1),
            "$CONSTANTS": system_map,
            "$STRUCTS": vtypes
            }

        return result

    def Convert(self):
        raise RuntimeError("Unknown profile format.")


class LinuxConverter(ProfileConverter):
    """Convert an existing Linux profile zip file.

    Since building the linux profile often happens on the target system, where
    Rekall is not normall running, we just convert the result of running Make in
    the tools/linux/ directory. See tools/linux/README for details.

    In short:

    - Run make in tools/linux/ directory. This will build module_dwarf.ko with
      debugging symbols.

    - If you have zip installed, the above step will create the required zip
      file. Otherwise Create a zip file manually with module_dwarf.ko and
      /boot/System.map-`uname -r` (Sometimes when running make not as the root
      user, its not possible to read the System.map file).

    Finally use this tool to convert the profile to a Rekall compatible profile.
    """
    BASE_PROFILE_CLASS = "Linux"

    def ParseSystemMap(self, system_map):
        """Parse the system map and return a list of offset, symbol_name."""
        sys_map = {}
        # get the system map
        for line in system_map.splitlines():
            (address, _, symbol) = line.strip().split()
            try:
                sys_map[symbol] = long(address, 16) & 0xFFFFFFFFFFFF
            except ValueError:
                pass

        return sys_map

    def ParseConfigFile(self, config_file):
        """Parse the kernel .config file returning it as a dictionary."""
        config = {}
        for line in config_file.splitlines():
            if line.startswith("#"):
                continue
            try:
                (config_param, value) = line.strip().split("=")
                # Remove leading and trailing spaces from the config_param.
                config_param = config_param.lstrip(" \t").rstrip(" \t")
                # Massage the value a bit so plugins trying to use them get more
                # useful values. This deals with config options like
                # CONFIG_DEFAULT_HOSTNAME="(none)" having a value of
                # str("(none)") instead of str("\"(none)\"").
                value = value.rstrip(" \t").lstrip(" \t")
                value = value.rstrip('"\'').lstrip('"\'')
                config[config_param] = value
            except ValueError:
                pass

        return config

    def BuildProfile(self, system_map, vtypes, config=None):
        """Write all the components needed for the output profile."""
        # Try to guess the bit size of the system if not provided.
        if self.profile_class is None:
            self.profile_class = self.BASE_PROFILE_CLASS

        enums = vtypes.pop("$ENUMS", {})
        reverse_enums = vtypes.pop("$REVENUMS", {})

        result = super(LinuxConverter, self).BuildProfile(system_map, vtypes)
        result["$CONFIG"] = config or dict()
        result["$ENUMS"] = enums
        result["$REVENUMS"] = reverse_enums

        self.profile_class = self.BASE_PROFILE_CLASS
        largest_offset = max(system_map.values())
        if "CONFIG_CPU_MIPS32" in result["$CONFIG"]:
            result["$METADATA"]["arch"] = "MIPS"

        elif "arm_syscall" in result["$CONSTANTS"]:
            result["$METADATA"]["arch"] = "ARM"

        elif largest_offset > 2**32:
            result["$METADATA"]["arch"] = "AMD64"
        else:
            result["$METADATA"]["arch"] = "I386"
        return result

    def Convert(self):
        # Load the config file if it exists
        config = self.SelectFile("(^|/)config")
        if config:
            config = self.ParseConfigFile(config)

        # Check for a linux profile. It should have a System.map in it.
        system_map = self.SelectFile("(^|/)System.map")
        if system_map:
            # Parse the system map file.
            system_map = self.ParseSystemMap(system_map)

            ko_file = self.SelectFile(r"module.*\.ko$")
            if ko_file:
                self.session.logging.info(
                    "Converting Linux profile with ko module.")
                parser = dwarfparser.DWARFParser(StringIO.StringIO(ko_file),
                                                 session=self.session)

                profile_file = self.BuildProfile(system_map, parser.VType(),
                                                 config=config)
                return profile_file

            dwarf_file = self.SelectFile(r"\.dwarf$")
            if dwarf_file:
                self.session.logging.info(
                    "Converting Linux profile with dwarf dump output")
                parser = dwarfdump.DWARFParser()
                for line in dwarf_file.splitlines():
                    parser.feed_line(line)

                # The dwarfdump module returns python code so we must exec it.
                l = {}
                exec(parser.print_output(), {}, l)

                profile_file = self.BuildProfile(system_map, l["linux_types"],
                                                 config=config)
                return profile_file

        raise RuntimeError("Unknown profile format.")


class OSXConverter(LinuxConverter):
    """Automatic conversion from Volatility OSX style profiles.

    You can generate one of those using the instructions here:
    http://code.google.com/p/volatility/wiki/MacMemoryForensics#Building_a_Profile
    """
    BASE_PROFILE_CLASS = "Darwin"

    DLSYM_REGEX = re.compile("([^ ]+) '([^ ]+)'$")

    def ParseSystemMap(self, system_map):
        sys_map = {}
        for line in system_map.splitlines():
            if self.profile_class is None and "Symbol table for" in line:
                last_part = line.split()[-1]
                if last_part == "(x86_64)":
                    self.profile_class = "Darwin64"
                elif last_part == "(i386)":
                    self.profile_class = "Darwin32"
                else:
                    raise RuntimeError(
                        "Unknown Darwin Architecture %s" % last_part)

            # We only care about few things like functions and global symbols.
            if "N_FUN" in line or "EXT" in line or "N_STSYM" in line:
                m = self.DLSYM_REGEX.search(line)
                if m:
                    try:
                        sys_map[m.group(2)] = long(m.group(1), 16)
                    except ValueError:
                        pass

        return sys_map

    def Convert(self):
        # Check for an OSX profile.
        system_map = self.SelectFile("dsymutil$")
        if system_map:
            # Parse the system map file.
            system_map = self.ParseSystemMap(system_map)

            vtype_file = self.SelectFile(r"\.vtypes$")
            if vtype_file:
                self.session.logging.info(
                    "Converting Darwin profile with vtypes dump output")

                # The dwarfdump module returns python code so we must exec it.
                l = {}
                exec(vtype_file, {}, l)

                profile_file = self.BuildProfile(system_map, l["mac_types"])
                return profile_file

        raise RuntimeError("Unknown profile format.")


class ConvertProfile(plugin.TypedProfileCommand, plugin.Command):
    """Convert a profile from another program to the Rekall format.

    The Rekall profile format is optimized for loading at runtime. This plugin
    produces a Rekall profile from a variety of sources, including:

    - Linux debug compiled kernel module (see tool/linux/README)
    - OSX Dwarfdump outputs.
    """

    __name = "convert_profile"

    __args = [
        dict(name="profile_class",
             help="The name of the profile implementation to specify. "
             "If not specified, we autodetect."),

        dict(name="converter",
             help="The name of the converter to use. "
             "If not specified autoguess."),

        dict(name="source", positional=True, required=True,
             help="Filename of profile to read."),

        dict(name="out_file", positional=True, required=True,
             help="Path for output file."),
    ]

    def ConvertProfile(self, input):
        """Converts the input profile to a new standard profile in output."""
        # First detect what kind of profile the input profile is.
        for converter in (LinuxConverter, OSXConverter):
            try:
                profile = converter(input, session=self.session).Convert()
                return profile
            except RuntimeError:
                pass

        raise RuntimeError(
            "No suitable converter found - profile not recognized.")

    def render(self, renderer):
        if self.plugin_args.converter:
            cls = ProfileConverter.classes.get(self.plugin_args.converter)
            if not cls:
                raise IOError(
                    "Unknown converter %s" % self.plugin_args.converter)

            return cls(self.plugin_args.source,
                       profile_class=self.plugin_args.profile_class).Convert()

        try:
            input = io_manager.Factory(
                self.plugin_args.source, session=self.session, mode="r")
        except IOError:
            self.session.logging.critical(
                "Input profile file %s could not be opened.",
                self.plugin_args.source)
            return

        with input:
            profile = self.ConvertProfile(input)
            if profile:
                with renderer.open(
                    filename=self.plugin_args.out_file, mode="wb") as output:
                    output.write(utils.PPrint(profile))
                    self.session.logging.info("Converted %s to %s",
                                              input, output.name)


class TestConvertProfile(testlib.DisabledTest):
    PARAMETERS = dict(commandline="convert_profile")


class TestBuildIndex(testlib.DisabledTest):
    PARAMETERS = dict(commandline="build_index")


class BuildIndex(plugin.Command):
    """Generate a profile index file based on an index specification.

    The index specification is currently a yaml file with the following
    structure:

    ```
    base_symbol: (string) # OPTIONAL Compute ALL offsets as relative to this
        symbol. This includes MaxOffset and MinOffset.
    symbols: (array of dicts) # A list of symbols to index.
      -
        name: (string) # Symbol name
        data: (string) # Data that should be at the symbol's offset
        shift: (int) # OPTIONAL Adjust symbol offset by this number
    ```

    ## Example:

    ```
    path: win32k.sys
    symbols:
      -
        # The name of the symbol we test for.
        name: "??_C@_1BO@KLKIFHLC@?$AAG?$AAU?$AAI?$AAF?$AAo?$AAn?$AAt?$AA?4?$AAH?$AAe?$AAi?$AAg?$AAh?$AAt?$AA?$AA@"

        # The data we expect to find at that offset.
        data: "47005500490046006f006e0074002e00480065006900670068007400"

      -
        name: "wcschr"
        shift: -1
        data: "90"
    ```

    The result is an index profile. This has an $INDEX section which is a dict,
    with keys being the profile name, and values being a list of (offset, match)
    tuples. For example:

    ```
    {
     "$INDEX": {
      "tcpip.sys/AMD64/6.0.6001.18000/0C1A1EC1D61E4508A33F5212FC1B37202": [[1184600, "495053656344656c657465496e626f756e644f7574626f756e64536150616972"]],
      "tcpip.sys/AMD64/6.0.6001.18493/29A4DBCAF840463298F40190DD1492D02": [[1190376, "495053656344656c657465496e626f756e644f7574626f756e64536150616972"]],
      "tcpip.sys/AMD64/6.0.6002.18272/7E79532FC7E349C690F5FBD16E3562172": [[1194296, "495053656344656c657465496e626f756e644f7574626f756e64536150616972"]],
    ...

     "$METADATA": {
      "ProfileClass": "Index",
      "Type": "Profile"
      "MaxOffset": 546567
      "MinOffset": 0
      }
     }
    ```
    """

    __name = "build_index"

    @classmethod
    def args(cls, parser):
        super(BuildIndex, cls).args(parser)
        parser.add_argument(
            "spec", default=None,
            help="An Index specification file.")

        parser.add_argument(
            "--root", default="./",
            help="Repository root path.")

    def __init__(self, spec=None, root="./", manager=None, **kwargs):
        super(BuildIndex, self).__init__(**kwargs)
        self.spec = spec
        if manager is None:
            manager = io_manager.DirectoryIOManager(
                root, session=self.session)
        self.io_manager = manager

    @staticmethod
    def _decide_base(data, base_symbol):
        if base_symbol == None:
            return 0

        return data["$CONSTANTS"].get(base_symbol, None)

    def ValidateDataIndex(self, index):
        """Check the index for collisions.

        An index collision occurs when all the comparison points in one GUID are
        also contained in another GUID. If these points match it is impossible
        to distinguish between the two indexes. We need to issue a warning so
        the user can add additional comparison points to resolve the ambiguity.
        """
        errors = 0

        # The following algorithm is very slow O(n^2) but there aren't that many
        # profiles in the index.
        for profile, data in index.iteritems():
            for profile2, data2 in index.iteritems():
                overlap = []

                # Don't report collisions with the same profile.
                if profile == profile2:
                    continue

                for condition in data:
                    if condition in data2:
                        overlap.append(condition)

                if overlap == data:
                    # Some profiles are just rebuilt (so they have a new GUID)
                    # but they are otherwise identical. We can never distinguish
                    # between them so it does not matter.
                    if self._AreProfilesEquivalent(profile, profile2):
                        continue

                    errors += 1
                    self.session.logging.error(
                        "Profile %s and %s are ambiguous, please add more "
                        "comparison points.", profile, profile2)

                    self.session.logging.error(
                        "Run the following command:\nzdiff %s.gz %s.gz",
                        profile, profile2)

        if errors:
            self.session.logging.error("Index with errors: %s", errors)

    def _AreProfilesEquivalent(self, profile, profile2):
        # Check if the two profiles are equivalent:
        profile_obj = self.io_manager.GetData(profile)
        profile2_obj = self.io_manager.GetData(profile2)

        for section in ["$CONSTANTS", "$FUNCTIONS"]:
            if profile_obj.get(section) != profile2_obj.get(section):
                return False

        self.session.logging.info("Profile %s and %s are equivalent",
                                  profile, profile2)
        return True

    def BuildDataIndex(self, spec):
        """Builds a data index from the specification.

        A data index is an index which collates known data at known offsets
        in memory. We then apply the index to a memory location to discover
        the most likely match there.
        """
        index = {}
        metadata = dict(Type="Profile",
                        ProfileClass="Index")

        result = {"$METADATA": metadata,
                  "$INDEX": index}

        highest_offset = 0
        lowest_offset = 2 ** 64
        base_sym = spec.get("base_symbol", None)

        for relative_path, data in self._GetAllProfiles(spec["path"]):
            for sym_spec in spec["symbols"]:
                shift = sym_spec.get("shift", 0)

                if "$CONSTANTS" not in data:
                    continue

                offset = data["$CONSTANTS"].get(sym_spec["name"])
                if offset is None:
                    # Maybe its a function.
                    offset = data["$FUNCTIONS"].get(sym_spec["name"])
                    if offset is None:
                        continue

                # Offsets (as well as min/max offset) are computed
                # relative to base.
                base = self._decide_base(
                    data=data,
                    base_symbol=base_sym)

                # If we got a base symbol but it's not in the constants
                # then that means this profile is incompatible with this
                # index and should be skipped.
                if base == None:
                    continue

                # We don't record the offset as reported by the profile
                # but as the reader is actually going to use it.
                offset = offset + shift - base

                values = []
                # If a symbol's expected value is prefixed with
                # 'str:' then that means it was given to us as
                # human-readable and we need to encode it. Otherwise it
                # should already be hex-encoded.
                for value in sym_spec["data"]:
                    if value.startswith("lstr:"):
                        value = value[5:].encode("utf-16le").encode("hex")

                    elif value.startswith("str:"):
                        value = value[4:].encode("hex")

                    else:
                        try:
                            value.decode("hex")
                        except TypeError:
                            raise ValueError(
                                "String %r must be encoded in hex, "
                                "or prefixed by str: or lstr:" % value)

                    values.append(value)

                index.setdefault(relative_path, []).append((offset, values))

                # Compute the lowest and highest offsets so the reader
                # can optimize reading the image.
                lowest_offset = min(lowest_offset, offset)
                highest_offset = max(
                    highest_offset, offset + len(sym_spec["data"]))

        metadata["BaseSymbol"] = base_sym
        metadata["MaxOffset"] = highest_offset
        metadata["MinOffset"] = lowest_offset

        # Make sure to issue warnings if the index is not good enough.
        self.ValidateDataIndex(index)

        return result

    def BuildStructIndex(self, spec):
        """Builds a Struct index from specification.

        A Struct index is a collection of struct offsets for certain members
        over all available versions.
        """
        index = {}
        metadata = dict(Type="Profile",
                        ProfileClass=spec.get("implementation", "Index"))

        result = {"$METADATA": metadata,
                  "$INDEX": index}

        for relative_path, data in self._GetAllProfiles(spec["path"]):
            try:
                structs = data["$STRUCTS"]
            except KeyError:
                continue

            metadata = index[relative_path] = data["$METADATA"]
            offsets = metadata["offsets"] = {}
            for struct, fields in spec["members"].items():
                for field in fields:
                    try:
                        offsets["%s.%s" % (struct, field)] = (
                            structs[struct][1][field][0])
                    except KeyError:
                        continue

        return result

    def _SymbolIsUnique(self,  profile_id, symbol, profiles):
      """Returns True if symbol uniquely identifies profile_id within profiles.

      Args:
        profile_id: The unique identifier of symbol's profile.
        symbol: The symbol to test.
        profiles: A dictionary of profile_id:symbol_dict entries where
          symbol_dict is a dictionary of symbol:offset entries.

          Every profile in profiles must be unique. That is, two entries must
          not share the exact same set of symbol:offset pairs.
      """

      offset = profiles[profile_id].get(symbol)

      # If the symbol doesn't exist it can't be unique
      if offset is None:
          return False

      unique = True

      for other_id, other_symbols in profiles.iteritems():
          # Skip comparing this profile against itself.
          if profile_id == other_id:
            continue

          # Find duplicates
          if offset == other_symbols.get(symbol):
            unique = False
            break

      return unique

    def _FindNewProfiles(self, index, target):
        """Finds new profiles in the repository that were not in the index."""

        new_profiles = 0

        # Walk all files to find new profiles
        for profile_id in self.io_manager.ListFiles():
            if not profile_id.startswith(target):
                continue

            # Skip known duplicates.
            # Skip profiles that haven't changed.
            file_mtime = self.io_manager.Metadata(profile_id)["LastModified"]

            try:
                profile_mtime = index.ProfileMetadata(
                    profile_id)["LastModified"]

                # If the current file is not fresher than the old file, we
                # just copy the metadata from the old profile. Allow 1
                # second grace for float round ups.
                if profile_mtime+1 >= file_mtime:
                    continue
            except (KeyError, TypeError):
                # Profile doesn't exist in the index yet.
                # See if it was a duplicate.
                pass

            try:
                data = self.io_manager.GetData(profile_id)
                if "$CONSTANTS" not in data:
                    self.session.logging.debug(
                        "File %s doesn't look like a profile, skipping...",
                        profile_id)
                    continue
                data["$CONSTANTS"] = index.RelativizeSymbols(
                    data["$CONSTANTS"], "linux_proc_banner")
                # Free up some memory
                del data["$CONFIG"]
                del data["$STRUCTS"]
            except ValueError as e:
                self.session.logging.error("ERROR loading %s: %s",
                                           profile_id, e)
                continue

            new_profiles += 1
            self.session.report_progress(
                "[STEP 1/6] Found %d new profiles: %s",
                new_profiles, profile_id)
            yield profile_id, data


    def _FindProfilesWithSymbolOffset(self, symbol_name, symbol_offset,
                                      profiles=None):
      """Returns a set of profile_ids that have symbol_name: symbol_offset."""

      matching_profiles = set()
      for profile_id, symbols in profiles.iteritems():
          if symbols.get(symbol_name) == symbol_offset:
              matching_profiles.add(profile_id)
      return matching_profiles

    def _FindTraits(self, profile_id=None, profiles=None, num_traits=1,
                    trait_length=1, first_try_symbols=None):
        """Finds traits of profile against other_profiles.

        Args:
            profile_id: The id of the profile to find traits for within profiles
            profiles: A dict of profile:symbols tuples where symbols is a dict
              of symbol:value.
            num_traits: How many traits to find.
            trait_length: How many symbols to consider per trait.
            first_try_symbols: A list of symbols to try first.
        """
        found_traits = []
        profile_symbols = profiles.get(profile_id)

        # The set we're looking for.
        exit_set = set([profile_id])

        # Store a pool of symbols
        symbol_pool = profile_symbols.keys()
        if first_try_symbols:
            # Reorder these symbols so they are tried first
            for symbol in reversed(first_try_symbols):
                try:
                    symbol_pool.remove(symbol)
                except ValueError:
                    pass
                symbol_pool.insert(0, symbol)

        for trait_symbols in itertools.combinations(symbol_pool, trait_length):

            symbol = trait_symbols[0]
            offset = profile_symbols.get(symbol)
            intersection_set = self._FindProfilesWithSymbolOffset(
                symbol, offset,  profiles=profiles)

            for next_symbol in trait_symbols[1:]:
                next_offset = profile_symbols.get(next_symbol)
                next_set = self._FindProfilesWithSymbolOffset(
                    next_symbol, next_offset,
                    profiles=profiles)

                # For a trait to be unique, the resulting set of performing
                # the intersection of the sets of profiles containing the
                # symbol-offset tuples must be the original profile_id.
                intersection_set &= next_set

                # If the comparison set is empty, we're done
                if intersection_set == exit_set:
                    break

            if intersection_set == exit_set:
                # Found a trait
                trait = [(s, profile_symbols.get(s)) for s in trait_symbols]
                found_traits.append(trait)
                if len(found_traits) == num_traits:
                    break
        return found_traits

    def BuildSymbolsIndex(self, spec):
        """Builds an index to identify profiles based on their symbols-offsets.

        The index stores traits for each profile. A trait is a combination of
        1 or more symbol-offset pairs that uniquely identify it within the
        current profile repository.

        The code handles:
          - Incremental updates of the index. Adding a new profile to the index
          doesn't trigger recomputing the entire index.
          - Detection of duplicates. If a profile is to be added that's already
          in the index, it will be detected and skipped.
          - Clash detection. If a new profile has some symbol-offsets that were
          traits of other profiles, the profile whose traits are not unique
          anymore will be found and its index rebuilt.
        """

        directory_to_index = spec.get("path", "Linux")
        index_path = os.path.join(directory_to_index, "index")

        # Load the current index from the index directory.
        #index = self.session.LoadProfile(index_path, use_cache=False)
        index = obj.Profile.LoadProfileFromData(
            self.io_manager.GetData(index_path), name=index_path,
            session=self.session)

        # A list of duplicate profiles to update the index
        new_duplicate_profiles = []


        # If we don't yet have an index, we start with a blank one.
        if not index:
            dummy_index = profile_index.LinuxSymbolOffsetIndex.BuildIndex(
                iomanager=self.io_manager)
            index = obj.Profile.LoadProfileFromData(
                data=dummy_index, session=self.session)

        if not isinstance(index, profile_index.SymbolOffsetIndex):
            raise ValueError(
                "The index should be a SymbolOffsetIndex but found %s instead" %
                (index.___class__.__name__))
        self.session.logging.debug("Index is a %s", index.__class__.__name__)

        # STEP 1. Find new profiles. New profiles are profiles not in the
        # index or profiles that have been updated.
        self.session.report_progress("[STEP 1/6] Finding new profiles...",
                                     force=True)
        new_profile_candidates = list(self._FindNewProfiles(index,
                                                            spec["path"]))

        # STEP 2. Determine how many of the new profiles are duplicates.
        # New profiles can be duplicates because they already exist in the index
        # with another name or because they clash with some other new profile.
        self.session.report_progress("[STEP 2/6] Finding duplicate profiles...",
                                     force=True)
        new_hashes_dict = dict()
        new_profiles = dict()
        for i, (profile_id, data) in enumerate(sorted(new_profile_candidates)):
            self.session.report_progress(
                "[STEP 2/6][%d/%d] Finding if %s is duplicate.",
                i, len(new_profile_candidates), profile_id)
            profile_hash = index.CalculateRawProfileHash(data)
            existing_profile = index.LookupHash(profile_hash)

            if existing_profile == profile_id:
                # This is a profile already in the index that's been updated.
                # But if the profile still has the same hash, we have to do
                # nothing as the index is still good.
                # This wil be the case when touch()ing profiles or probably
                # copying them over.
                continue

            # If it's identical to a profile we already have indexed, this is a
            # duplicate.
            #
            # TODO: We should remove the profile and make it a Symlink.
            if existing_profile:
                self.session.logging.info(
                    ("New profile %s is equivalent to %s, which is already "
                     "in the index."),
                    profile_id, existing_profile)
                new_duplicate_profiles.append(profile_id)
                continue

            # Otherwise it may clash with another new profile. This can easily
            # happen when we add more than one profile at a time, with minor
            # version increases.
            #
            # Example: Ubuntu Trusty 3.13.0-54-generic vs 3.13.0-55-generic.
            if profile_hash in new_hashes_dict:
                # This is a duplicate. Discard.
                # TODO: Remove the profile and make it a Symlink.
                self.session.logging.info(
                    "New profile %s is equivalent to another new profile %s.",
                    profile_id,
                    new_hashes_dict.get(profile_hash))
                new_duplicate_profiles.append(profile_id)
                continue

            # If it was not a duplicate,
            symbols = data.get("$CONSTANTS")
            symbols = index.FilterSymbols(symbols)
            new_profiles[profile_id] = symbols
            new_hashes_dict[profile_hash] = profile_id

        # Inform of how many profiles we skipped indexing.
        if len(new_profile_candidates) > len(new_profiles):
            self.session.logging.info(
                "Skipped indexing %d profiles, since they were duplicates.",
                len(new_profile_candidates) - len(new_profiles))


        # STEP 3. Find if any of the new profiles forces us to recompute
        # traits for profiles already in the repository. This can happen if
        # the trait that's in the index now appears in one of the
        # new profiles.
        #
        # Since we calculate more than one trait per profile the index may
        # still work for other traits. But we want healthy indexes, so we
        # recalculate all the traits.

        num_clashing_profiles = 0
        self.session.report_progress(
            "[STEP 3/6] Finding index clashes with new profiles", force=True)

        for i, (profile_id, traits_dict) in enumerate(sorted(index)):
            self.session.report_progress(
                "[STEP 3/6][%d/%d] Finding index clashes with new profiles",
                i, len(index))
            profile_needs_rebuild = False

            for trait in traits_dict:
                for new_profile_id, symbols in new_profiles.iteritems():
                    if index.RawProfileMatchesTrait(symbols, trait):
                        self.session.logging.warn(
                          "New profile %s clashes with %s, will recalculate.",
                          new_profile_id, profile_id)
                        profile_needs_rebuild = True
                        break

                # Leave the loop early if a trait is not unique anymore.
                if profile_needs_rebuild:
                    break

            if profile_needs_rebuild:
                num_clashing_profiles += 1
                data = self.io_manager.GetData(profile_id)
                data["$CONSTANTS"] = index.RelativizeSymbols(
                    data["$CONSTANTS"])
                new_profiles[profile_id] = data["$CONSTANTS"]

        if not new_profiles:
            self.session.logging.info("No new profiles found. Exitting.")
            return profile_index.LinuxSymbolOffsetIndex.BuildIndex(
                hashes=index.hashes,
                traits=index.traits,
                spec=spec,
                duplicates=index.duplicates + new_duplicate_profiles,
                iomanager=self.io_manager)

        self.session.logging.info(
            ("Will regenerate an index for %d profiles. %d are new and %d "
             "were in the index but now have clashes"),
            len(new_profiles),
            len(new_profiles) - num_clashing_profiles,
            num_clashing_profiles)

        # STEP 4. Find unique symbols for all new profiles. We need to open
        # all the profiles in the repo
        # additionally to the new ones which we opened earlier.

        self.session.report_progress(
            "[STEP 4/6] Opening all profiles in the repository.", force=True)
        # Start by opening all profiles in the index.
        index_profiles = dict()
        for i, (profile_id, _) in enumerate(index):
            self.session.report_progress(
                "[STEP 4/6][%d/%d] Opening %s...",
                i, len(index), profile_id)
            profile = self.io_manager.GetData(profile_id)
            profile["$CONSTANTS"] = index.RelativizeSymbols(
                profile["$CONSTANTS"])
            # Free up some memory
            del profile["$STRUCTS"]
            del profile["$CONFIG"]
            symbols = profile.get("$CONSTANTS")
            symbols = index.FilterSymbols(symbols)
            index_profiles[profile_id] = symbols

        all_profiles = index_profiles.copy()
        # Any profile that was in the index but has been updated on disk will
        # be overriden here, which is what we want.
        all_profiles.update(dict(new_profiles))

        self.session.report_progress(
            "[STEP 4/6] Finding single-symbol traits.", force=True)
        # A list of profiles we haven't found traits for.
        retry_profiles = []
        # Maximum number of traits to find.
        min_traits = spec.get("min_traits", 5)
        self.session.report_progress(
            "[STEP 4/6] Finding single-symbol traits. Opening all, done.",
            force=True)

        # A dictionary of traits per profile_id
        traits_dict = dict()
        for i, (profile_id, symbols) in enumerate(
            sorted(new_profiles.iteritems())):

            self.session.report_progress(
                "[STEP 4/6][%d/%d] Finding %d traits for %s",
                i, len(new_profiles), min_traits, profile_id)

            traits = self._FindTraits(profile_id,
                                      profiles=all_profiles,
                                      num_traits=min_traits,
                                      trait_length=1)
            traits_dict[profile_id] = traits

            if not traits_dict.get(profile_id):
                self.session.logging.warning(
                    "Profile %s has no single-symbol trait.", profile_id)
                retry_profiles.append(profile_id)
            elif len(traits_dict.get(profile_id)) < min_traits:
                self.session.logging.info(
                    "[STEP 4/6][%d/%d] Found %d/%d traits for %s. Queueing...",
                    i, len(new_profiles), len(traits), min_traits,
                    profile_id)
                retry_profiles.append(profile_id)
            else:
                self.session.logging.info(
                    "[STEP 4/6][%d/%d] Found %d/%d traits for %s",
                    i, len(new_profiles), len(traits), min_traits,
                    profile_id)


        self.session.report_progress(
            "[STEP 5/6] Finding unique 2-symbol traits...", force=True)

        # STEP 5. Process the remaining profiles to find unique pairs.
        for i, profile_id in enumerate(retry_profiles):
            self.session.report_progress(
                "[STEP 5/6][%d/%d] Finding unique 2-symbol pairs for %s",
                i, len(retry_profiles), profile_id, force=True)

            # We have to find only the remaining number of traits to reach
            # min_traits.
            num_traits_to_find = (min_traits -
                                  len(traits_dict.get(profile_id, [])))

            first_try_symbols  = None
            if len(traits_dict.get(profile_id, [])) == 1:
                first_try_symbols = [trait[0] for trait
                                      in traits_dict.get(profile_id)]

            traits = self._FindTraits(profile_id,
                                      profiles=all_profiles,
                                      num_traits=num_traits_to_find,
                                      trait_length=2,
                                      first_try_symbols=first_try_symbols)
            traits_dict[profile_id] = traits

            if traits_dict.get(profile_id) is None:
                self.session.logging.error(
                    "Profile %s has no 2-symbol trait.", profile_id)
            else:
                self.session.logging.info(
                    "[STEP 5/6][%d/%d] Found %d/%d 2-symbol traits for %s",
                    i, len(retry_profiles),
                    len(traits_dict.get(profile_id, [])),
                    min_traits,
                    profile_id)

        # LAST STEP: Build the index augmenting the previous index.
        self.session.report_progress(
            "[STEP 6/6] Building index...", force=True)
        new_index_hashes = index.hashes.copy()
        new_index_hashes.update(new_hashes_dict)

        new_index_traits = index.traits.copy()
        new_index_traits.update(traits_dict)

        # Update the profile metadata with the new and updated profiles.
        new_index_profile_metadata =  index.profiles.copy()
        for profile_id in new_profiles:
            file_mtime = self.io_manager.Metadata(profile_id)["LastModified"]
            metadata_dict = new_index_profile_metadata.get(profile_id, {})
            metadata_dict["LastModified"] = file_mtime

        return profile_index.LinuxSymbolOffsetIndex.BuildIndex(
            hashes=new_index_hashes,
            traits=new_index_traits,
            duplicates=index.duplicates + new_duplicate_profiles,
            spec=spec,
            iomanager=self.io_manager)

    def _GetProfile(self, name):
        path = "%s.gz" % name
        file_data = gzip.open(path).read()
        return json.loads(file_data)

    def _GetAllProfiles(self, path):
        """Iterate over all paths and get the profiles."""
        for profile_name in self.io_manager.ListFiles():
            if profile_name.startswith(path):
                self.session.report_progress("Processing %s", profile_name)
                data = self.io_manager.GetData(profile_name)

                yield profile_name, data

    def build_index(self, spec):
        if spec.get("type") == "struct":
            return self.BuildStructIndex(spec)
        elif spec.get("type") == "symbol_offset":
            return self.BuildSymbolsIndex(spec)
        else:
            return self.BuildDataIndex(spec)

    def render(self, renderer):
        spec = self.io_manager.GetData(self.spec)
        renderer.write(utils.PPrint(self.build_index(spec)))


class BuildProfileLocally(plugin.Command):
    """Download and builds a profile locally in one step.

    We store the profile in the first repository in the profile_path which must
    be writable. Usually this is a caching repository so the profile goes in the
    local cache.
    """

    name = "build_local_profile"

    @classmethod
    def args(cls, parser):
        super(BuildProfileLocally, cls).args(parser)
        parser.add_argument(
            "module_name",
            help="The name of the module (without the .pdb extensilon).",
            required=True)

        parser.add_argument(
            "guid",
            help="The guid of the module.",
            required=False)

        parser.add_argument("--dumpfile",
                            help="If specified also dump the json file here.")

    def __init__(self, module_name=None, guid=None, dumpfile=None, **kwargs):
        super(BuildProfileLocally, self).__init__(**kwargs)
        self.module_name = module_name
        self.guid = guid
        self.dumpfile = dumpfile

    def _fetch_and_parse(self, module_name, guid):
        """Fetch the profile from the symbol server.

        Raises:
          IOError if the profile is not found on the symbol server or can not be
          retrieved.

        Returns:
           the profile data.
        """
        with utils.TempDirectory() as dump_dir:
            pdb_filename = "%s.pdb" % module_name
            fetch_pdb_plugin = self.session.plugins.fetch_pdb(
                pdb_filename=pdb_filename,
                guid=guid, dump_dir=dump_dir)

            # Store the PDB file somewhere.
            pdb_pathname = os.path.join(dump_dir, pdb_filename)
            with open(pdb_pathname, "wb") as outfd:
                outfd.write(fetch_pdb_plugin.FetchPDBFile(
                    module_name, guid))

            parse_pdb = self.session.plugins.parse_pdb(
                pdb_filename=pdb_pathname,
                dump_dir=dump_dir)

            return parse_pdb.parse_pdb()

    def fetch_and_parse(self, module_name=None, guid=None, renderer=None):
        if module_name is None:
            module_name = self.module_name

        if guid is None:
            guid = self.guid

        # Allow the user to specify the required profile by name.
        m = re.match("([^/]+)/GUID/([^/]+)$", module_name)
        if m:
            module_name = m.group(1)
            guid = m.group(2)

        if not guid or not module_name:
            raise TypeError("GUID not specified.")

        profile_name = "{0}/GUID/{1}".format(module_name.lower(), guid)

        # Get the first repository to write to.
        repository = self.session.repository_managers[0][1]
        if module_name != "nt":
            data = self._fetch_and_parse(module_name, guid)

            if self.dumpfile:
                with renderer.open(filename=self.dumpfile, mode="wb") as fd:
                    fd.write(utils.PPrint(data))

            return repository.StoreData(profile_name, data)

        for module_name in common.KERNEL_NAMES:
            if module_name.endswith(".pdb"):
                module_name, _ = os.path.splitext(module_name)
            try:
                data = self._fetch_and_parse(module_name, guid)
                self.session.logging.warning(
                    "Profile %s fetched and built. Please "
                    "consider reporting this profile to the "
                    "Rekall team so we may add it to the public "
                    "profile repository.", profile_name)

                return repository.StoreData(profile_name, data)
            except IOError, e:
                self.session.logging.error("Error: %s", e)

        raise IOError("Profile not found")

    def render(self, renderer):
        self.fetch_and_parse(self.module_name, self.guid, renderer=renderer)


class TestBuildProfileLocally(testlib.HashChecker):
    PARAMETERS = dict(
        commandline=("build_local_profile %(pdb_name)s %(guid)s "
                     "--dumpfile %(tempdir)s/output"),
        pdb_name="ntkrnlpa",
        guid="BD8F451F3E754ED8A34B50560CEB08E31"
    )
