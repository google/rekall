# Rekall Memory Forensics
# Copyright (c) 2012, Michael Cohen <scudette@gmail.com>
# Copyright (c) 2010, 2011, 2012 Michael Ligh <michael.ligh@mnin.org>
# Copyright 2013 Google Inc. All Rights Reserved.
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


"""A Rekall Memory Forensics scanner which uses yara."""
import yara

from rekall import scan
from rekall import testlib
from rekall import plugin
from rekall import utils


class BaseYaraASScanner(scan.BaseScanner):
    """An address space scanner for Yara signatures."""
    overlap = 1024

    def __init__(self, rules=None, **kwargs):
        super(BaseYaraASScanner, self).__init__(**kwargs)
        self.rules = rules
        self.hits = []
        self.base_offset = None

    def check_addr(self, scan_offset, buffer_as=None):
        # The buffer was changed - we scan the entire buffer and record the
        # hits - then we can feed it to the Rekall scan framework.
        if self.base_offset != buffer_as.base_offset:
            self.base_offset = buffer_as.base_offset
            self.hits = []

            matches = self.rules.match(data=buffer_as.data)
            for match in matches:
                for buffer_offset, name, value in match.strings:
                    hit_offset = buffer_offset + buffer_as.base_offset
                    self.hits.append(
                        (match.rule, hit_offset, name, value))

        if self.hits and scan_offset == self.hits[0][1]:
            return self.hits.pop(0)

    def skip(self, buffer_as, offset):
        # Skip the entire buffer.
        if not self.hits:
            return len(buffer_as.data)

        next_hit = self.hits[0][1]
        return next_hit - offset


class YaraScanMixin(object):
    """A common implementation of yara scanner.

    This should be mixed with the OS specific Scanner (e.g. WinScanner) and
    plugin.TypedProfileCommand.
    """

    name = "yarascan"

    table_header = plugin.PluginHeader(
        dict(name="Owner", width=20),
        dict(name="Rule", width=10),
        dict(name="Offset", style="address"),
        dict(name="HexDump", style="hexdump", hex_width=16),
        dict(name="Context"),
    )

    __args = [
        plugin.CommandOption("hits", default=10, type="IntParser",
                             help="Quit after finding this many hits."),

        plugin.CommandOption("string", default=None,
                             help="A verbatim string to search for."),

        plugin.CommandOption("binary_string", default=None,
                             help="A binary string (encoded as hex) to search "
                             "for. e.g. 000102[1-200]0506"),

        plugin.CommandOption("yara_file", default=None,
                             help="The yara signature file to read."),

        plugin.CommandOption("yara_expression", default=None,
                             help="If provided we scan for this yara "
                             "expression."),

        plugin.CommandOption("context", default=0x40, type="IntParser",
                             help="Context to print after the hit."),

        plugin.CommandOption("pre_context", default=0, type="IntParser",
                             help="Context to print before the hit."),

    ]

    scanner_defaults = dict(
        scan_physical=True
    )

    def __init__(self, *args, **kwargs):
        """Scan using yara signatures."""
        super(YaraScanMixin, self).__init__(*args, **kwargs)

        # Compile the yara rules in advance.
        if self.plugin_args.yara_expression:
            self.rules_source = self.plugin_args.yara_expression
            self.rules = yara.compile(source=self.rules_source)

        elif self.plugin_args.binary_string:
            self.compile_rule(
                'rule r1 {strings: $a = {%s} condition: $a}' %
                self.plugin_args.binary_string)

        elif self.plugin_args.string:
            self.compile_rule(
                'rule r1 {strings: $a = "%s" condition: $a}' %
                self.plugin_args.string)

        elif self.plugin_args.yara_file:
            self.compile_rule(open(self.plugin_args.yara_file).read())

        elif not self.ignore_required:
            raise plugin.PluginError("You must specify a yara rule file or "
                                     "string to match.")

    def compile_rule(self, rule):
        self.rules_source = rule
        try:
            self.rules = yara.compile(source=rule)
        except Exception as e:
            raise plugin.PluginError(
                "Failed to compile yara expression: %s" % e)

    def generate_hits(self, run):
        scanner = BaseYaraASScanner(
            session=self.session,
            address_space=run.address_space,
            rules=self.rules)

        for hit in scanner.scan(offset=run.start, maxlen=run.length):
            yield hit

    def collect(self):
        """Render output."""
        count = 0
        for run in self.generate_memory_ranges():
            for rule, address, _, _ in self.generate_hits(run):
                count += 1
                if count >= self.plugin_args.hits:
                    break

                # Result hit the physical memory - Get some context on this hit.
                if run.data.get("type") == "PhysicalAS":
                    rammap_plugin = self.session.plugins.rammap(
                        start=address, end=address+1)
                    symbol = rammap_plugin.summary()[0]
                else:
                    symbol = self.session.address_resolver.format_address(
                        address)

                yield (run.data.get("task") or run.data.get("type"),
                       rule, address,
                       utils.HexDumpedString(
                           run.address_space.read(
                               address - self.plugin_args.pre_context,
                               self.plugin_args.context +
                               self.plugin_args.pre_context)),
                       symbol)


class SimpleYaraScan(YaraScanMixin, plugin.TypedProfileCommand,
                     plugin.PhysicalASMixin, plugin.ProfileCommand):
    """A Simple plugin which only yarascans the physical Address Space.

    This plugin should not trigger profile autodetection and therefore should be
    usable on any file at all.
    """

    name = "simple_yarascan"
    __args = [
        plugin.CommandOption("start", default=0, type="IntParser",
                             help="Start searching from this offset."),

        plugin.CommandOption("limit", default=2**64, type="IntParser",
                             help="The length of data to search."),
    ]

    table_header = plugin.PluginHeader(
        dict(name="Rule", width=10),
        dict(name="Offset", style="address"),
        dict(name="HexDump", style="hexdump", hex_width=16),
    )

    PROFILE_REQUIRED = False

    def collect(self):
        """Render output."""
        count = 0
        scanner = BaseYaraASScanner(
            session=self.session,
            address_space=self.session.physical_address_space,
            rules=self.rules)

        for rule, address, _, _ in scanner.scan(
                offset=self.plugin_args.start, maxlen=self.plugin_args.limit):
            count += 1
            if count >= self.plugin_args.hits:
                break

            yield (rule, address,
                   utils.HexDumpedString(
                       self.session.physical_address_space.read(
                           address - self.plugin_args.pre_context,
                           self.plugin_args.context +
                           self.plugin_args.pre_context)))



class TestYara(testlib.SimpleTestCase):
    """Test the yarascan module."""

    PARAMETERS = dict(commandline="yarascan --string %(string)s --hits 10")
