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

from rekall.plugins.common import pfn


class YaraScanMixin(object):
    """A common implementation of yara scanner.

    This should be mixed with the OS specific Scanner (e.g. WinScanner) and
    plugin.TypedProfileCommand.
    """

    name = "yarascan"

    table_header = [
        dict(name="Owner", width=20),
        dict(name="Rule", width=10),
        dict(name="Offset", style="address"),
        dict(name="hexdump", hex_width=16, width=67),
        dict(name="run", hidden=True),
        dict(name="address_space", hidden=True),
        dict(name="Context"),
    ]

    __args = [
        dict(name="hits", default=10, type="IntParser",
             help="Quit after finding this many hits."),

        dict(name="string", default=None,
             help="A verbatim string to search for."),

        dict(name="binary_string", default=None,
             help="A binary string (encoded as hex) to search "
             "for. e.g. 000102[1-200]0506"),

        dict(name="yara_file", default=None,
             help="The yara signature file to read."),

        dict(name="yara_expression", default=None,
             help="If provided we scan for this yara "
             "expression."),

        dict(name="context", default=0x40, type="IntParser",
             help="Context to print after the hit."),

        dict(name="pre_context", default=0, type="IntParser",
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
        for buffer_as in scan.BufferASGenerator(
                self.session, run.address_space, run.start, run.end):
            self.session.logging.debug(
                "Scanning buffer %#x->%#x (length %#x)",
                buffer_as.base_offset, buffer_as.end(),
                buffer_as.end() - buffer_as.base_offset)

            for match in self.rules.match(data=buffer_as.data):
                for buffer_offset, name, value in match.strings:
                    hit_offset = buffer_offset + buffer_as.base_offset
                    yield match.rule, hit_offset

    def collect(self):
        """Render output."""
        count = 0
        for run in self.generate_memory_ranges():
            for rule, address in self.generate_hits(run):
                count += 1
                if count >= self.plugin_args.hits:
                    break

                # Result hit the physical memory - Get some context on this hit.
                if run.data.get("type") == "PhysicalAS":
                    symbol = pfn.PhysicalAddressContext(self.session, address)
                else:
                    symbol = utils.FormattedAddress(
                        self.session.address_resolver, address,
                        max_distance=2**64)

                yield dict(
                    Owner=run.data.get("task") or run.data.get("type"),
                    Rule=rule,
                    Offset=address,
                    hexdump=utils.HexDumpedString(
                        run.address_space.read(
                            address - self.plugin_args.pre_context,
                            self.plugin_args.context +
                            self.plugin_args.pre_context)),
                    Context=symbol,
                    # Provide the address space where the hit is reported.
                    address_space=run.address_space,
                    run=run)


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

    table_header = [
        dict(name="Rule", width=10),
        dict(name="Offset", style="address"),
        dict(name="hexdump", hex_width=16, width=67),
    ]

    PROFILE_REQUIRED = False

    def collect(self):
        """Render output."""
        count = 0
        address_space = self.session.physical_address_space
        for buffer_as in scan.BufferASGenerator(
                self.session, address_space,
                self.plugin_args.start,
                self.plugin_args.start + self.plugin_args.limit):
            self.session.report_progress(
                "Scanning buffer %#x->%#x (%#x)",
                buffer_as.base_offset, buffer_as.end(),
                buffer_as.end() - buffer_as.base_offset)

            for match in self.rules.match(data=buffer_as.data):
                for buffer_offset, _, _ in match.strings:
                    hit_offset = buffer_offset + buffer_as.base_offset
                    count += 1
                    if count >= self.plugin_args.hits:
                        break

                    yield dict(
                        Rule=match.rule,
                        Offset=hit_offset,
                        hexdump=utils.HexDumpedString(
                            self.session.physical_address_space.read(
                                hit_offset - self.plugin_args.pre_context,
                                self.plugin_args.context +
                                self.plugin_args.pre_context)))


class TestYara(testlib.SimpleTestCase):
    """Test the yarascan module."""

    PARAMETERS = dict(commandline="yarascan --string %(string)s --hits 10")
