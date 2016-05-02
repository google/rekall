# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
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


__author__ = "Michael Cohen <scudette@google.com>"

"""A Common mixin for implementing plugins based on scanning."""

from rekall import addrspace


class BaseScannerPlugin(object):
    """A mixin that implements scanner memory region selectors.

    Most scanners are very similar - they search for specific byte patterns over
    some sections of memory, validate those and present the results. Depending
    on the type of structures searched for, different regions of memory need to
    be looked at.

    This mixin attempts to present a common interface to all scanning plugins,
    where users may select different regions using common selector options, and
    those will be generated automatically.

    The plugin may select a set of default regions to scan, which are most
    relevant to the specific data searched for, but the user may override the
    defaults at all times.

    NOTE: This plugin must be mixed with the specific OS's ProcessFilter
    implementation in order to bring in standard process selectors.
    """

    __args = [
        dict(name="scan_physical", default=False, type="Boolean",
             help="Scan the physical address space only."),

        dict(name="scan_kernel", default=False, type="Boolean",
             help="Scan the entire kernel address space."),

        # Process Scanning options.
        dict(name="scan_process_memory", default=False, type="Boolean",
             help="Scan all of process memory. Uses process selectors to "
             "narrow down selections."),
    ]

    scanner_defaults = {}

    def scan_specification_requested(self):
        """Return True if the user requested any specific regions."""
        for k, v in self.plugin_args.items():
            if k.startswith("scan_") and v:
                return True

        return False

    def generate_memory_ranges(self):
        """Parse the plugin args and generate memory ranges.

        Yields rekall.addrspace.Run objects.
        """
        if not self.scan_specification_requested():
            # Copy the plugin defaults into the args.
            for k in self.plugin_args:
                if k.startswith("scan_"):
                    self.plugin_args[k] = self.scanner_defaults.get(k, False)

        # Physical address space requested.
        if self.plugin_args.scan_physical:
            yield addrspace.Run(
                start=0, end=self.session.physical_address_space.end(),
                address_space=self.session.physical_address_space,
                data=dict(type="PhysicalAS"))

        # Scan all of the kernel address space.
        if self.plugin_args.scan_kernel:
            yield addrspace.Run(
                start=0, end=self.session.kernel_address_space.end(),
                address_space=self.session.kernel_address_space,
                data=dict(type="KernelAS"))

        # Scan the complete process memory, not including the kernel.
        if self.plugin_args.scan_process_memory:
            # We use direct inheritance here so we can support process
            # selectors.
            for task in self.filter_processes():
                cc = self.session.plugins.cc()
                with cc:
                    # Switch to the process address space.
                    cc.SwitchProcessContext(task)
                    end = self.session.GetParameter("highest_usermode_address")
                    resolver = self.session.address_resolver
                    for module in sorted(resolver.GetAllModules(),
                                         key=lambda x: x.start):

                        # Skip modules in kernel space.
                        if module.start > end:
                            break

                        comment = "%s (%s), %s" % (
                            task.name, task.pid, module.name)

                        self.session.logging.info(
                            "Scanning %s (%s) in: %s [%#x-%#x]" % (
                                task.name, task.pid, comment,
                                module.start, module.end))

                        yield addrspace.Run(
                            start=module.start, end=module.end,
                            address_space=self.session.default_address_space,
                            data=dict(type=comment, module=module, task=task))
