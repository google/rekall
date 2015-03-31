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

__author__ = "Michael Cohen <scudette@google.com>"

import logging
import gzip
import json
import os
import re
import StringIO
import yaml

from rekall import io_manager
from rekall import plugin
from rekall import registry
from rekall import testlib
from rekall import utils

from rekall.plugins import core
from rekall.plugins.overlays.linux import dwarfdump
from rekall.plugins.overlays.linux import dwarfparser
from rekall.plugins.windows import common


class ProfileConverter(object):
    """Base class for converters."""

    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    def __init__(self, input, output, profile_class=None, session=None):
        self.input = input
        self.output = output
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

    def WriteProfile(self, profile_file):
        self.output.write(utils.PPrint(profile_file))


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
                sys_map[symbol] = long(address, 16)
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

            ko_file = self.SelectFile(r"\.ko$")
            if ko_file:
                logging.info("Converting Linux profile with ko module.")
                parser = dwarfparser.DWARFParser(StringIO.StringIO(ko_file),
                                                 session=self.session)

                profile_file = self.BuildProfile(system_map, parser.VType(),
                                                 config=config)
                return self.WriteProfile(profile_file)

            dwarf_file = self.SelectFile(r"\.dwarf$")
            if dwarf_file:
                logging.info("Converting Linux profile with dwarf dump output")
                parser = dwarfdump.DWARFParser()
                for line in dwarf_file.splitlines():
                    parser.feed_line(line)

                # The dwarfdump module returns python code so we must exec it.
                l = {}
                exec(parser.print_output(), {}, l)

                profile_file = self.BuildProfile(system_map, l["linux_types"],
                                                 config=config)
                return self.WriteProfile(profile_file)

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
                logging.info(
                    "Converting Darwin profile with vtypes dump output")

                # The dwarfdump module returns python code so we must exec it.
                l = {}
                exec(vtype_file, {}, l)

                profile_file = self.BuildProfile(system_map, l["mac_types"])
                return self.WriteProfile(profile_file)

        raise RuntimeError("Unknown profile format.")


class ConvertProfile(core.OutputFileMixin, plugin.Command):
    """Convert a profile from another program to the Rekall format.

    The Rekall profile format is optimized for loading at runtime. This plugin
    produces a Rekall profile from a variety of sources, including:

    - Linux debug compiled kernel module (see tool/linux/README)
    - OSX Dwarfdump outputs.
    """

    __name = "convert_profile"

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        parser.add_argument(
            "--profile_class", default=None,
            help="The name of the profile implementation to specify. "
            "If not specified, we autodetect.")

        parser.add_argument(
            "--converter", default=None,
            help="The name of the converter to use. "
            "If not specified autoguess.")

        parser.add_argument("source",
                            help="Filename of profile to read.")

        super(ConvertProfile, cls).args(parser)

    def __init__(self, source=None, out_file=None,
                 profile_class=None, converter=None, **kwargs):
        super(ConvertProfile, self).__init__(out_file=out_file, **kwargs)
        self.profile_class = profile_class
        self.converter = converter
        self.source = source

    def ConvertProfile(self, input, output):
        """Converts the input profile to a new standard profile in output."""
        # First detect what kind of profile the input profile is.
        for converter in (LinuxConverter, OSXConverter):
            try:
                converter(input, output, session=self.session).Convert()
                logging.info("Converted %s to %s", input, output.name)
                return
            except RuntimeError:
                pass

        raise RuntimeError(
            "No suitable converter found - profile not recognized.")

    def render(self, renderer):
        with renderer.open(filename=self.out_file, mode="wb") as output:
            if self.converter:
                cls = ProfileConverter.classes.get(self.converter)
                if not cls:
                    raise IOError("Unknown converter %s" % self.converter)

                return cls(self.source, output,
                           profile_class=self.profile_class).Convert()

            try:
                input = io_manager.Factory(self.source, session=self.session,
                                           mode="r")
            except IOError:
                logging.critical("Input profile file %s could not be opened.",
                                 self.source)
                return

            with input, output:
                self.ConvertProfile(input, output)


class TestConvertProfile(testlib.DisabledTest):
    PARAMETERS = dict(commandline="convert_profile")


class TestBuildIndex(testlib.DisabledTest):
    PARAMETERS = dict(commandline="build_index")


class BuildIndex(plugin.Command):
    """Generate a profile index file based on an index specification.

    The index specification is currently a yaml file with the following
    structure:

    Structure:
    ==========

    base_symbol: (string) # OPTIONAL Compute ALL offsets as relative to this
        symbol. This includes MaxOffset and MinOffset.
    symbols: (array of dicts) # A list of symbols to index.
      -
        name: (string) # Symbol name
        data: (string) # Data that should be at the symbol's offset
        shift: (int) # OPTIONAL Adjust symbol offset by this number

    Example:
    ========

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

    The result is an index profile. This has an $INDEX section which is a dict,
    with keys being the profile name, and values being a list of (offset, match)
    tuples. For example:

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

    def __init__(self, spec=None, root="./", **kwargs):
        super(BuildIndex, self).__init__(**kwargs)
        self.spec = spec
        self.root = root

    @staticmethod
    def _decide_base(data, base_symbol):
        if base_symbol == None:
            return 0

        return data["$CONSTANTS"].get(base_symbol, None)

    def ValidateDataIndex(self, index, spec):
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
                    logging.error(
                        "Profile %s and %s are ambiguous, please add more "
                        "comparison points.", profile, profile2)

                    logging.error(
                        "Run the following command:\nzdiff %s.gz %s.gz",
                        profile, profile2)

        if errors:
            logging.error("Index with errors: %s", errors)

    def _AreProfilesEquivalent(self, profile, profile2):
        # Check if the two profiles are equivalent:
        profile_obj = self._GetProfile(profile)
        profile2_obj = self._GetProfile(profile2)
        for section in ["$CONSTANTS", "$FUNCTIONS"]:
            if profile_obj.get(section) == profile2_obj.get(section):
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
        lowest_offset = float("inf")
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
        self.ValidateDataIndex(index, spec)

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

    def _GetProfile(self, name):
        path = "%s.gz" % name
        file_data = gzip.open(path).read()
        return json.loads(file_data)

    def _GetAllProfiles(self, path):
        """Iterate over all paths and get the profiles."""
        for root, _, files in os.walk(os.path.join(self.root, path)):
            for name in files:
                path = os.path.join(root, name)
                relative_path = os.path.splitext(path[len(self.root):])[0]

                if path.endswith(".gz"):
                    self.session.report_progress("Processing %s", relative_path)
                    file_data = gzip.open(path).read()
                    data = json.loads(file_data)

                    yield relative_path, data

    def render(self, renderer):
        with renderer.open(filename=self.spec, mode="rb") as fd:
            spec = yaml.safe_load(fd)


        if spec.get("type") == "struct":
            result = self.BuildStructIndex(spec)
        else:
            result = self.BuildDataIndex(spec)

        renderer.write(utils.PPrint(result))


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

    def __init__(self, module_name=None, guid=None, **kwargs):
        super(BuildProfileLocally, self).__init__(**kwargs)
        self.module_name = module_name
        self.guid = guid

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

    def fetch_and_parse(self, module_name=None, guid=None):
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

        profile_name = "{0}/GUID/{1}".format(module_name, guid)

        # Get the first repository to write to.
        repository = self.session.repository_managers[0][1]
        if module_name != "nt":
            data = self._fetch_and_parse(module_name, guid)
            return repository.StoreData(profile_name, data)

        for module_name in common.KERNEL_NAMES:
            if module_name.endswith(".pdb"):
                module_name, _ = os.path.splitext(module_name)
            try:
                data = self._fetch_and_parse(module_name, guid)
                logging.warning(
                    "Profile %s fetched and built. Please "
                    "consider reporting this profile to the "
                    "Rekall team so we may add it to the public "
                    "profile repository.", profile_name)

                return repository.StoreData(profile_name, data)
            except IOError, e:
                logging.error("Error: %s", e)

        raise IOError("Profile not found")

    def render(self, renderer):
        self.fetch_and_parse(self.module_name, self.guid)
