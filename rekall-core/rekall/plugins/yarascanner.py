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


class YaraScanMixin(object):
    """A common implementation of yara scanner.

    This should be mixed with the process filter.
    """

    name = "yarascan"

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
                            help="If provided we scan for this yarra "
                            "expression.")

        parser.add_argument(
            "--scan_physical", default=False, type="Boolean",
            help="If specified we scan the physcial address space. Note that "
            "by default we scan the address space of the specified processes "
            "(or if no process selectors are specified, the kernel).")

    def __init__(self, string=None, scan_physical=False,
                 yara_file=None, yara_expression=None, binary_string=None, hits=10,
                 **kwargs):
        """Scan using yara signatures."""
        super(YaraScanMixin, self).__init__(**kwargs)
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

        for hit in scanner.scan(maxlen=end):
            yield hit

            count += 1
            if count >= self.hits:
                break

    def render_scan_physical(self, renderer):
        """This method scans the physical memory."""
        for rule, address, _, _ in self.generate_hits(
                self.physical_address_space):
            renderer.format("Rule: {0}\n", rule)

            context = self.physical_address_space.read(address, 0x40)
            utils.WriteHexdump(renderer, context, base=address)

    def render_kernel_scan(self, renderer):
        for rule, address, _, _ in self.generate_hits(
                self.kernel_address_space):
            renderer.format("Rule: {0}\n", rule)
            owner = self.session.address_resolver.format_address(address)
            if not owner:
                owner = "Unknown"

            renderer.format("Owner: {0}\n", owner)

            context = self.kernel_address_space.read(address, 0x40)
            utils.WriteHexdump(renderer, context, base=address)

    def render_task_scan(self, renderer, task):
        """Scan a task's address space."""
        end = self.session.GetParameter("highest_usermode_address")
        task_as = task.get_process_address_space()

        for rule, address, _, _ in self.generate_hits(task_as, end=end):
            renderer.format("Rule: {0}\n", rule)

            renderer.format(
                "Owner: {0} ({1})\n", task,
                self.session.address_resolver.format_address(address))

            context = task_as.read(address, 0x40)
            utils.WriteHexdump(renderer, context, base=address)

    def render(self, renderer):
        """Render output."""
        cc = self.session.plugins.cc()
        with cc:
            if self.scan_physical:
                return self.render_scan_physical(renderer)

            elif self.filtering_requested:
                for task in self.filter_processes():
                    cc.SwitchProcessContext(task)

                    self.render_task_scan(renderer, task)

            # We are searching the kernel address space
            else:
                return self.render_kernel_scan(renderer)


class TestYara(testlib.SimpleTestCase):
    """Test the yarascan module."""

    PARAMETERS = dict(commandline="yarascan --string %(string)s --hits 10")
