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

    def _match_rules(self, buffer_as):
        """Compatibility for yara modules.

        Unfortunately there are two different implementations of the yara python
        bindings:

        # The original upstream source.
        http://plusvic.github.io/yara/

        # The version which is installed using pip install.
        https://github.com/mjdorma/yara-ctypes

        These do not work the same and so we need to support both.

        Yields:
          a tuple of (offset, rule_name, name, value)
        """
        matches = self.rules.match(data=buffer_as.data)
        # yara-cpython bindings from pip.
        if type(matches) is dict:
            for _, matches in matches.items():
                for match in matches:
                    for string in match["strings"]:
                        hit_offset = string["offset"] + buffer_as.base_offset

                        yield (match["rule"], hit_offset,
                               string["identifier"], string["data"])

        else:
            # native bindings from http://plusvic.github.io/yara/
            for match in matches:
                for buffer_offset, name, value in match.strings:
                    hit_offset = buffer_offset + buffer_as.base_offset
                    yield (match.rule, hit_offset, name, value)

    def check_addr(self, scan_offset, buffer_as=None):
        # The buffer was changed - we scan the entire buffer and record the
        # hits - then we can feed it to the Rekall scan framework.
        if self.base_offset != buffer_as.base_offset:
            self.base_offset = buffer_as.base_offset
            self.hits = []

            for rule, offset, name, value in self._match_rules(buffer_as):
                self.hits.append((rule, offset, name, value))

        if self.hits and scan_offset == self.hits[0][1]:
            return self.hits.pop(0)

    def skip(self, buffer_as, offset):
        # Skip the entire buffer.
        if not self.hits:
            return len(buffer_as.data)

        next_hit = self.hits[0][1]
        return next_hit - offset


class YaraScanMixin(plugin.TypedProfileCommand):
    """A common implementation of yara scanner.

    This should be mixed with the process filter.
    """

    name = "yarascan"

    table_header = plugin.PluginHeader(
        dict(name="Owner"),
        dict(name="Rule", width=10),
        dict(name="Offset", style="address"),
        dict(name="HexDump", style="hexdump", hex_width=16),
        dict(name="Symbol"),
    )

    @classmethod
    def args(cls, parser):
        super(YaraScanMixin, cls).args(parser)

        parser.add_argument("--hits", default=1E8, type="IntParser",
                            help="Quit after finding this many hits.")


        parser.add_argument("--string", default=None,
                            help="A verbatim string to search for.")

        parser.add_argument("--binary_string", default=None,
                            help="A binary string (encoded as hex) to search "
                            "for. e.g. 000102[1-200]0506")

        parser.add_argument("--yara_file", default=None,
                            help="The yara signature file to read.")

        parser.add_argument("--yara_expression", default=None,
                            help="If provided we scan for this yara "
                            "expression.")

        parser.add_argument(
            "--scan_physical", default=False, type="Boolean",
            help="If specified we scan the physcial address space. Note that "
            "by default we scan the address space of the specified processes "
            "(or if no process selectors are specified, the default AS).")

        parser.add_argument("--start", default=0, type="IntParser",
                            help="Start searching from this offset.")

        parser.add_argument("--context", default=0x40, type="IntParser",
                            help="Context to print after the hit.")

        parser.add_argument("--pre_context", default=0, type="IntParser",
                            help="Context to print before the hit.")

        parser.add_argument("--limit", default=2**64,
                            help="The length of data to search.")

    def __init__(self, string=None, scan_physical=False,
                 yara_file=None, yara_expression=None, binary_string=None,
                 hits=10, context=0x40, start=0, limit=2**64, pre_context=0,
                 **kwargs):
        """Scan using yara signatures."""
        super(YaraScanMixin, self).__init__(**kwargs)
        self.context = context
        self.pre_context = pre_context
        self.start = self.session.address_resolver.get_address_by_name(start)
        self.end = self.start + limit
        self.hits = hits
        if yara_expression:
            self.rules_source = yara_expression
            self.rules = yara.compile(source=self.rules_source)

        elif binary_string:
            self.compile_rule(
                'rule r1 {strings: $a = {%s} condition: $a}' % binary_string
                )
        elif string:
            self.compile_rule(
                'rule r1 {strings: $a = "%s" condition: $a}' % string
                )

        elif yara_file:
            self.compile_rule(open(yara_file).read())
        else:
            raise plugin.PluginError("You must specify a yara rule file or "
                                     "string to match.")

        self.scan_physical = scan_physical

    def compile_rule(self, rule):
        self.rules_source = rule
        try:
            self.rules = yara.compile(source=rule)
        except Exception as e:
            raise plugin.PluginError(
                "Failed to compile yara expression: %s" % e)

    def generate_hits(self, address_space, end=None):
        count = 0
        scanner = BaseYaraASScanner(
            profile=self.profile, session=self.session,
            address_space=address_space,
            rules=self.rules)

        for hit in scanner.scan(offset=self.start, maxlen=end):
            yield hit

            count += 1
            if count >= self.hits:
                break

    def collect_scan_physical(self):
        """This method scans the physical memory."""
        for rule, address, _, _ in self.generate_hits(
                self.physical_address_space):
            if address > self.end:
                return

            yield (None, rule, address, utils.HexDumpedString(
                self.physical_address_space.read(
                    address - self.pre_context,
                    self.context + self.pre_context)))

    def collect_kernel_scan(self):
        for rule, address, _, _ in self.generate_hits(
                self.session.default_address_space):
            if address > self.end:
                return

            symbol = self.session.address_resolver.format_address(address)
            yield (None, rule, address, utils.HexDumpedString(
                self.session.default_address_space.read(
                    address - self.pre_context,
                    self.context + self.pre_context)), symbol)

    def collect_task_scan(self, task):
        """Scan a task's address space."""
        end = min(self.session.GetParameter("highest_usermode_address"),
                  self.end)
        task_as = task.get_process_address_space()

        for rule, address, _, _ in self.generate_hits(task_as, end=end):
            if address > self.end:
                return

            symbol = self.session.address_resolver.format_address(address)
            yield (task, rule, address, utils.HexDumpedString(
                task_as.read(
                    address - self.pre_context,
                    self.context + self.pre_context)), symbol)

    def collect(self):
        """Render output."""
        cc = self.session.plugins.cc()
        with cc:
            if self.scan_physical:
                for row in self.collect_scan_physical():
                    yield row

            elif self.filtering_requested:
                for task in self.filter_processes():
                    cc.SwitchProcessContext(task)

                    for row in self.collect_task_scan(task):
                        yield row

            # We are searching the kernel address space
            else:
                for row in self.collect_kernel_scan():
                    yield row


class TestYara(testlib.SimpleTestCase):
    """Test the yarascan module."""

    PARAMETERS = dict(commandline="yarascan --string %(string)s --hits 10")
