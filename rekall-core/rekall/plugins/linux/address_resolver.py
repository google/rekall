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

"""The module implements the linux specific address resolution plugin."""

__author__ = "Michael Cohen <scudette@gmail.com>"
from rekall import obj
from rekall.plugins.common import address_resolver
from rekall.plugins.linux import common

class LKMModule(address_resolver.Module):
    """A Linux kernel module."""

    def __init__(self, module, **kwargs):
        self.module = module
        super(LKMModule, self).__init__(
            name=unicode(module.name),
            start=module.base,
            end=module.end,
            **kwargs)


class MapModule(address_resolver.Module):
    """A module representing a memory mapping."""


class KernelModule(address_resolver.Module):
    """A Fake object which makes the kernel look like a module.

    This removes the need to treat kernel addresses any different from module
    addresses, and allows them to be resolved by this module.
    """

    def __init__(self, session=None, **kwargs):
        super(KernelModule, self).__init__(
            # Check if the address appears in the kernel binary.
            start=obj.Pointer.integer_to_address(
                session.profile.get_constant("_text")),
            end=session.profile.get_constant("_end"),
            name="linux",
            profile=session.profile,
            session=session, **kwargs)


class LinuxAddressResolver(address_resolver.AddressResolverMixin,
                           common.LinuxPlugin):
    """A Linux specific address resolver plugin."""

    def _EnsureInitialized(self):
        if self._initialized:
            return

        # Insert a psuedo module for the kernel
        self.AddModule(KernelModule(session=self.session))

        # Add LKMs.
        for kmod in self.session.plugins.lsmod().get_module_list():
            self.AddModule(LKMModule(kmod, session=self.session))

        task = self.session.GetParameter("process_context")

        for vma in task.mm.mmap.walk_list("vm_next"):
            start = vma.vm_start
            end = vma.vm_end
            self.AddModule(MapModule(
                name="map_%#x" % start,
                start=start, end=end, session=self.session))

        self._initialized = True
