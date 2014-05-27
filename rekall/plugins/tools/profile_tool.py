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
   Ubuntu-3.0.0-32-generic-pae.rekall.zip

$ ls -l Ubuntu-3.0.0-32-generic-pae.*
-rw-r----- 1 scudette g 643711 Dec 12 02:12 Ubuntu-3.0.0-32-generic-pae.rekall.zip
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
        if largest_offset > 2**32:
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
    """Automatic converted for Volatility OSX style profiles.

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


class WindowsConverter(ProfileConverter):
    """A converter from Volatility windows profiles.

    This converter must be manually specified.
    """

    def Convert(self):
        if not self.profile_class:
            raise RuntimeError("Profile class implementation not provided.")

        # The input file is a python file with a data structure in it.
        with open(self.input, "rb") as fd:
            l = {}
            exec(fd.read(), {}, l)

        profile_file = self.BuildProfile({}, l["ntkrnlmp_types"])
        self.WriteProfile(profile_file)


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
        if self.converter:
            cls = ProfileConverter.classes.get(self.converter)
            if not cls:
                raise IOError("Unknown converter %s" % self.converter)

            return cls(self.source, self.output,
                       profile_class=self.profile_class).Convert()

        try:
            input = io_manager.Factory(self.source, mode="r")
        except IOError:
            logging.critical("Input profile file %s could not be opened.",
                             self.source)
            return

        with input, self.output:
            self.ConvertProfile(input, self.output)


class TestConvertProfile(testlib.DisabledTest):
    PARAMETERS = dict(commandline="convert_profile")


class BuildIndex(plugin.Command):
    """Generate a profile index file based on an index specification.

    The index specification is currently a yaml file with the following
    structure:

    - repository_path: The path to the repository to index.
    - symbols: # A list of symbols to index.
       name: Symbol name.
       data: Data that should be found in the image.

    Example:

    repository_root: ./
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
      }
     }
    """

    __name = "build_index"

    @classmethod
    def args(cls, parser):
        super(BuildIndex, cls).args(parser)
        parser.add_argument(
            "--spec", default=None, required=True,
            help="An Index specification file.")

    def __init__(self, spec=None, **kwargs):
        super(BuildIndex, self).__init__(**kwargs)
        self.spec = spec

    def render(self, renderer):
        spec = yaml.safe_load(open(self.spec))
        index = {}
        metadata = dict(Type="Profile",
                        ProfileClass="Index")

        result = {"$METADATA": metadata,
                  "$INDEX": index}

        repository_root = spec["repository_root"]
        highest_offset = 0

        for root, _, files in os.walk(
            os.path.join(repository_root, spec["path"])):
            for name in files:
                path = os.path.join(root, name)
                relative_path = os.path.splitext(
                    path[len(repository_root):])[0]

                if path.endswith(".gz"):
                    self.session.report_progress("Processing %s", relative_path)
                    try:
                        file_data = gzip.open(path).read()
                        data = json.loads(file_data)
                    except Exception:
                        continue

                    index[relative_path] = []
                    for sym_spec in spec["symbols"]:
                        shift = sym_spec.get("shift", 0)
                        if "$CONSTANTS" not in data:
                            continue

                        offset = data["$CONSTANTS"].get(sym_spec["name"])

                        if not offset:
                            continue

                        index[relative_path].append(
                            (offset + shift, sym_spec["data"]))

                        # Store the highest offset, so the reader can optimize
                        # their reading.
                        highest_offset = max(
                            highest_offset,
                            offset + shift + len(sym_spec["data"]))

        metadata["max_offset"] = highest_offset
        renderer.write(utils.PPrint(result))
