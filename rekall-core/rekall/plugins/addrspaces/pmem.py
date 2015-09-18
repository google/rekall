# Rekall Memory Forensics
#
# Copyright 2015 Google Inc. All Rights Reserved.
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

"""Address spaces specific to pmem live here."""
__author__ = "Adam Sindelar <adamsh@google.com>"

from os import path

from rekall import addrspace
from rekall import yaml_utils
from rekall.plugins.addrspaces import standard


class _StreamWrapper(object):
    def __init__(self, stream):
        self.stream = stream

    def read(self, offset, length):
        self.stream.seek(offset)
        return self.stream.read(length)

    def write(self, offset, length):
        self.stream.seek(offset)
        return self.stream.write(length)


class MacPmemAddressSpace(addrspace.RunBasedAddressSpace):
    """Implements an address space to overlay the new MacPmem device."""

    name = "MacPmem"
    order = standard.FileAddressSpace.order - 2
    __image = True
    volatile = True
    fd = None
    fname = None
    _writable = True

    def _ensure_fd_writable(self):
        """Reopen the device if necessary.

        /dev/pmem is open read-only by default. This reopens it if writes are
        requested.
        """
        if self.session.GetParameter("writable_physical_memory"):
            expected_mode = "r+"
        else:
            raise RuntimeError(
                "writable_physical_memory is not set in the Session.")

        if self.fd.mode != expected_mode:
            self.fd.close()
            self.fd = open(self.fname, expected_mode)

    def __init__(self, base=None, filename=None, **kwargs):
        super(MacPmemAddressSpace, self).__init__(**kwargs)

        self.as_assert(base == None,
                       "Must be mapped directly over a raw device.")
        self.fname = filename or (self.session and self.session.GetParameter(
            "filename"))

        self.as_assert(self.fname, "Filename must be specified.")

        # Open as read-only even if writes are supported and allowed, because
        # permissions may be set up such that opening for writing would be
        # disallowed.
        self.fd = open(self.fname, "r")

        self.fname_info = "%s_info" % self.fname
        self.as_assert(path.exists(self.fname_info),
                       "MacPmem would declare a YML device at %s" %
                       self.fname_info)

        self._load_yml(self.fname_info)

    def _get_readable_runs(self, records):
        """Yields all the runs that are safe to read.

        This just trusts the EFI bootmap at the moment.
        """
        for record in records:
            if record["type"] == "efi_range":
                if efi_type_readable(record["efi_type"]):
                    yield (record["start"], record["start"], record["length"],
                           _StreamWrapper(self.fd))

    def ConfigureSession(self, session_obj):
        session_obj.SetCache("dtb", self.pmem_metadata["meta"]["dtb_off"],
                             volatile=False)
        session_obj.SetCache("vm_kernel_slide",
                             self.pmem_metadata["meta"]["kaslr_slide"],
                             volatile=False)

    def _load_yml(self, yml_path):
        with open(yml_path) as fp:
            data = self.pmem_metadata = yaml_utils.decode(fp.read())

        for run in self._get_readable_runs(data["records"]):
            self.add_run(*run)

    def close(self):
        self.fd.close()


# See http://wiki.phoenix.com/wiki/index.php/EFI_MEMORY_TYPE for list of
# segment types that become conventional memory after ExitBootServices()
# is sent to EFI.
EFI_SEGMENTS_SAFETY = {
    "EfiReservedMemoryType": "",
    "EfiLoaderCode": "rw",  # General use.
    "EfiLoaderData": "rw",  # General use.
    "EfiBootServicesCode": "rw",  # General use.
    "EfiBootServicesData": "rw",  # General use.
    "EfiRuntimeServicesCode": "r",  # Memory to be preserved.
    "EfiRuntimeServicesData": "r",  # Memory to be preserved.
    "EfiConventionalMemory": "r",  # General use.
    "EfiUnusableMemory": "",  # (Hardware) errors - don't use.
    "EfiACPIReclaimMemory": "rw",  # General use after ACPI enabled.
    "EfiACPIMemoryNVS": "r",  # Memory to be preserved.
    "EfiMemoryMappedIO": "",  # ACPI tables.
    "EfiMemoryMappedIOPortSpace": "",  # ACPI tables.
    "EfiPalCode": "r",  # OS-dependent. Largely read-only.
    "EfiMaxMemoryType": "rw",  # No idea (adamsh). Looks like general use?
}


def efi_type_readable(efi_type):
    return "r" in EFI_SEGMENTS_SAFETY[str(efi_type)]
