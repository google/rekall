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

import array
import ctypes
import fcntl

from rekall import addrspace
from rekall import session as rekall_session

from rekall.plugins.addrspaces import standard

from rekall.plugins.overlays import basic

# The following are directly adapted from the macros used by both XNU and
# Linux kernels for ioctl. Ioctl commands are encoded bitwise as follows:
#
# - The low 16 bits are are the command.
# - 13 bits for parameter (in/out) size.
# - 3 bits parameter flags (see below IOC_VOID, IOC_OUT, IOC_IN).
#
# See:
# XNU: https://github.com/opensource-apple/xnu/blob/10.10/bsd/sys/ioccom.h
# Linux: http://unix.superglobalmegacorp.com/Net2/newsrc/sys/ioctl.h.html


IOCPARM_MASK = 0x1fff  # Parameter length - up to 13 bits.


def IOCPARM_LEN(x):
    return(x >> 16) & IOCPARM_MASK


def IOCBASECMD(x):
    return x & ~(IOCPARM_MASK << 16)


def IOCGROUP(x):
    return (x >> 8) & 0xff


IOCPARM_MAX = IOCPARM_MASK + 1
IOC_VOID = 0x20000000  # No parameters.
IOC_OUT = 0x40000000  # Parameters copy out.
IOC_IN = 0x80000000  # Parameters copy in.
IOC_INOUT = IOC_IN | IOC_OUT  # Parameters copy in and out.
IOC_DIRMASK = 0xe0000000


def _IOC(inout, group, num, length):
    return (inout |
            ((length & IOCPARM_MASK) << 16) |
            (group << 8) |
            num)


def _IO(g, n):
    return _IOC(IOC_VOID, g, n, 0)


def _IOR(g, n, size):
    return _IOC(IOC_OUT, g, n, size)


def _IOW(g, n, size):
    return _IOC(IOC_IN, g, n, size)


def _IOWR(g, n, size):
    return _IOC(IOC_INOUT, g, n, size)


# IOCTLs specific to pmem below. This is the same as the pmem driver.
# Pmem for Linux and XNU use the exact same header file for these macros,
# making things much easier.

PMEM_GET_MMAP = 0
PMEM_GET_MMAP_SIZE = 1
PMEM_GET_MMAP_DESC_SIZE = 2
PMEM_GET_DTB = 3
PMEM_SET_MMAP_METHOD = 4
PMEM_IOCTL_BASE = ord("p")


PMEM_MMAP_TYPE = 8  # uint64_t
PMEM_MMAP_SIZE_TYPE = 4  # uint32_t
PMEM_MMAP_DESC_SIZE_TYPE = 4  # uint32_t
PMEM_DTB_TYPE = 8  # uint64_t
PMEM_MMAP_METHOD_TYPE = 4  # int32_t


# Fills in buffer at pointer with the mmap.
PMEM_IOCTL_GET_MMAP = _IOW(PMEM_IOCTL_BASE,
                           PMEM_GET_MMAP,
                           PMEM_MMAP_TYPE)


# Fills buffer with mmap size.
PMEM_IOCTL_GET_MMAP_SIZE = _IOR(PMEM_IOCTL_BASE,
                                PMEM_GET_MMAP_SIZE,
                                PMEM_MMAP_SIZE_TYPE)


# Fills buffer with mmap descriptor size (0x30 unless you're from the future).
PMEM_IOCTL_GET_MMAP_DESC_SIZE = _IOR(PMEM_IOCTL_BASE,
                                     PMEM_GET_MMAP_DESC_SIZE,
                                     PMEM_MMAP_DESC_SIZE_TYPE)


# Fills the buffer with the address of the DTB.
PMEM_IOCTL_GET_DTB = _IOR(PMEM_IOCTL_BASE,
                          PMEM_GET_DTB,
                          PMEM_DTB_TYPE)


# Changes the method used by the Pmem driver. (PTE is the default.)
PMEM_IOCTL_SET_MMAP_METHOD = _IOW(PMEM_IOCTL_BASE,
                                  PMEM_SET_MMAP_METHOD,
                                  PMEM_MMAP_METHOD_TYPE)


def pmem_get_mmap_size(fd):
    """Ask the Pmem driver for mmap size (number of entries)."""
    buf = array.array("I", [0])
    err = fcntl.ioctl(fd, PMEM_IOCTL_GET_MMAP_SIZE, buf, True)
    if err:
        raise IOError("Error (%d) getting mmap size." % err)

    return buf[0]


def pmem_get_mmap_desc_size(fd):
    """Ask the Pmem driver for size of an efi descriptor.

    Note that this must absolutely ALWAYS return 0x30, otherwise we're
    dealing with some future version fo EFI we know nothing about.
    """
    buf = array.array("I", [0])
    err = fcntl.ioctl(fd, PMEM_IOCTL_GET_MMAP_DESC_SIZE, buf, True)
    if err:
        raise IOError("Error (%d) getting mmap desc size." % err)

    return buf[0]


def pmem_get_mmap(fd):
    """Ask the Pmem driver for the physical address map.

    Returns:
    ========

    Tuple of (mmap, no_entries, entry_size).

    Each multiple of entry_size in the mmap_buffer is a valid
    EFI_MEMORY_DESCRIPTOR (defined below).

    Raises:
    =======

    IOError: If ioctl fails for whatever reason.
    AssertionError: If you're using this code to hack an alien mothership
                    and their EFI uses a different descriptor size than 0x30
                    this will blow up.
    """
    mmap_size = pmem_get_mmap_size(fd)
    mmap_desc_size = pmem_get_mmap_desc_size(fd)
    mmap = ctypes.create_string_buffer(mmap_size * mmap_desc_size)

    err = fcntl.ioctl(fd, PMEM_IOCTL_GET_MMAP, ctypes.pointer(mmap), True)
    if err:
        raise IOError("Error (%d) filling mmap buffer." % err)

    if mmap_desc_size != 0x30:
        raise AssertionError(
            ("EFI reports descriptor size of 0x%x. This code only knows how "
             "to handle descriptors 0x30 bytes in length.") % mmap_desc_size)

    return mmap, mmap_size, mmap_desc_size


def pmem_get_profile(fd):
    mmap, size, desc_size = pmem_get_mmap(fd)
    session = rekall_session.Session()
    buffer_as = addrspace.BufferAddressSpace(data=mmap.raw, session=session)
    session.SetCache("default_address_space", buffer_as)

    return EFIProfile(session=session)


def pmem_parse_mmap(fd):
    """Retrieve and parse the physical memory map from the Pmem driver.

    Yields: tuples of (start, number of pages, type)
    """
    mmap, size, desc_size = pmem_get_mmap(fd)
    session = rekall_session.Session()
    buffer_as = addrspace.BufferAddressSpace(data=mmap.raw, session=session)
    session.SetCache("default_address_space", buffer_as)
    profile = EFIProfile(session=session)

    for descriptor in profile.Array(
            offset=0, target="EFI_MEMORY_DESCRIPTOR", size=size):
        yield (descriptor.PhysicalStart,
               descriptor.NumberOfPages,
               descriptor.Type)

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


def efi_type_writable(efi_type):
    return "w" in EFI_SEGMENTS_SAFETY[str(efi_type)]


def efi_type_readable(efi_type):
    return "r" in EFI_SEGMENTS_SAFETY[str(efi_type)]


# Adapted from http://wiki.phoenix.com/wiki/index.php/EFI_MEMORY_DESCRIPTOR
#
# Every kernel that supports EFI will have a similar struct, but called
# something else. For example, on XNU this is called EfiMemoryRange, but
# XNU's definition doesn't account for the trailing 8-byte padding.
EFI_VTYPES = {
    "EFI_MEMORY_DESCRIPTOR": [0x30, {
        "Type": [0x0, ["Enumeration", dict(
            choices={
                # See typedef here:
                # http://wiki.phoenix.com/wiki/index.php/EFI_MEMORY_TYPE
                0: "EfiReservedMemoryType",
                1: "EfiLoaderCode",
                2: "EfiLoaderData",
                3: "EfiBootServicesCode",
                4: "EfiBootServicesData",
                5: "EfiRuntimeServicesCode",
                6: "EfiRuntimeServicesData",
                7: "EfiConventionalMemory",
                8: "EfiUnusableMemory",
                9: "EfiACPIReclaimMemory",
                10: "EfiACPIMemoryNVS",
                11: "EfiMemoryMappedIO",
                12: "EfiMemoryMappedIOPortSpace",
                13: "EfiPalCode",
                14: "EfiMaxMemoryType"},
            target="unsigned int")]],
        "PhysicalStart": [0x8, ["unsigned long"]],
        "VirtualStart": [0x10, ["unsigned long"]],
        "NumberOfPages": [0x18, ["unsigned long"]],
        "Attribute": [0x20, ["unsigned long"]]}]}


class EFIProfile(basic.ProfileLP64, basic.BasicClasses):
    """Profile for EFI types. Used for staging."""

    @classmethod
    def Initialize(cls, profile):
        super(EFIProfile, cls).Initialize(profile)
        profile.add_types(EFI_VTYPES)


class PmemAddressSpace(addrspace.RunBasedAddressSpace):
    """Address space specific to the pmem device."""

    __name = "pmem"
    order = standard.FileAddressSpace.order -1
    __image = True

    def __init__(self, base=None, filename=None, **kwargs):
        self.as_assert(base == None,
                       "Must be mapped directly over a raw device.")
        super(PmemAddressSpace, self).__init__(**kwargs)
        self.phys_base = self

        path = filename or (self.session and self.session.GetParameter(
            "filename"))

        self.as_assert(path, "Filename must be specified.")
        self.fname = path

        # See if the device is writable.
        self.write_enabled = False
        try:
            self.fd = open(path, "rw")
            self.write_enabled = True
        except IOError:
            self.fd = open(path, "r")

        # Reading from some offsets in the device can crash the system.
        # Let's make sure we don't do that.
        try:
            for offset, pages, efi_type in pmem_parse_mmap(self.fd):
                if efi_type_readable(efi_type):
                    self.runs.insert((offset, offset, pages * 0x1000))
        except IOError:
            # Apparently we're not dealing with Pmem.
            raise addrspace.ASAssertionError(
                "File at %s is not a pmem device." % path)

    def write(self, *_, **__):
        raise NotImplementedError("Writes to Pmem aren't supported yet.")

    def _read_chunk(self, addr, length):
        offset, available_length = self._get_available_buffer(addr, length)

        # We're not allowed to read from the offset, so just return zeros.
        if offset is None:
            return "\x00" * min(length, available_length)

        self.fd.seek(offset)
        return self.fd.read(min(length, available_length))

    def close(self):
        self.fd.close()
