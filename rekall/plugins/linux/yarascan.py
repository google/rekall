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

import yara

from rekall import plugin
from rekall import utils
from rekall.plugins import yarascanner
from rekall.plugins.linux import common



class LinYaraScan(common.LinProcessFilter):
    """Scan using yara signatures."""

    __name = "yarascan"

    @classmethod
    def args(cls, parser):
        super(LinYaraScan, cls).args(parser)
        parser.add_argument("--string", default=None,
                            help="A verbatim string to search for.")

        parser.add_argument("--yara_file", default=None,
                            help="The yara signature file to read.")

        parser.add_argument("--yara_expression", default=None,
                            help="If provided we scan for this yarra "
                            "expression.")

        parser.add_argument(
            "--scan_physical", default=False, type="Boolean",
            help="If specified we scan the physcial address space.")

    def __init__(self, string=None, scan_physical=False, yara_file=None,
                 yara_expression=None, **kwargs):
        """Scan using yara signatures.

        Args:
          string: A verbatim string to search for.
            we scan their entire address spaces.
          scan_physical: If true we scan the physical address space.
          yara_file: The yara file to read.
          yara_expression: If provided we scan for this yarra expression.
        """
        super(LinYaraScan, self).__init__(**kwargs)
        if yara_expression:
            self.rules_source = yara_expression
            self.rules = yara.compile(source=self.rules_source)

        elif string:
            self.rules_source = (
                'rule r1 {strings: $a = "%s" condition: $a}' % string
                )
            self.rules = yara.compile(source=self.rules_source)

        elif yara_file:
            self.rules = yara.compile(yara_file)
        else:
            raise plugin.PluginError("You must specify a yara rule file or "
                                     "string to match.")

        self.scan_physical = scan_physical

    def generate_hits(self, address_space):
        scanner = yarascanner.BaseYaraASScanner(
            profile=self.profile, session=self.session,
            address_space=address_space,
            rules=self.rules)

        return scanner.scan()

    def render_scan_physical(self, renderer):
        """This method scans the process memory using the VAD."""
        for rule, address, _, _ in self.generate_hits(
                self.physical_address_space):
            renderer.format("Rule: {0}\n", rule)

            context = self.physical_address_space.read(address, 0x40)
            utils.WriteHexdump(renderer, context, base=address)

    def render_kernel_scan(self, renderer):
        modules = self.session.plugins.lsmod()

        for rule, address, _, _ in self.generate_hits(
                self.kernel_address_space):
            renderer.format("Rule: {0}\n", rule)

            # Find out who owns this hit.
            owner = modules.find_module(address)
            if owner:
                renderer.format("Owner: {0}\n", owner.name)
            else:
                renderer.format("Owner: (Unknown Kernel Memory)\n")

            context = self.kernel_address_space.read(address, 0x40)
            utils.WriteHexdump(renderer, context, base=address)

    def render_task_scan(self, renderer, task):
        task_as = task.get_process_address_space()

        for rule, address, _, _ in self.generate_hits(task_as):
            renderer.format("Rule: {0}\n", rule)

            renderer.format("Owner: {0}\n", task.comm)

            context = task_as.read(address, 0x40)
            utils.WriteHexdump(renderer, context, base=address)


    def render(self, renderer):
        """Render output."""
        if self.scan_physical:
            return self.render_scan_physical(renderer)

        elif self.filtering_requested:
            for task in self.filter_processes():
                self.render_task_scan(renderer, task)

        # We are searching the kernel address space
        else:
            return self.render_kernel_scan(renderer)
