"""Implements scanners and plugins to find hypervisors in memory."""

from rekall import addrspace
from rekall import config
from rekall import plugin
from rekall import scan
from rekall.plugins.addrspaces import amd64
from rekall.plugins.overlays import basic

import struct


KNOWN_REVISION_IDS = {
    # Intel VT-x microarchitectures.
    0x0d: "PENRYN",
    0x0e: "NEHALEM",
    0x0f: "WESTMERE",
    0x10: "SANDYBRIDGE",
    }


# TODO: Find more abort codes.
KNOWN_ABORT_INDICATOR_CODES = {
    '\x00\x00\x00\x00': "NO ABORT",
    '\x05\x00\x00\x00': "MACHINE CHECK DURING VM EXIT",
    '\x0d\x00\x00\x00': "TXT SHUTDOWN",
    }


class VMCSProfile(basic.ProfileLP64):
    """Profile to parse hypervisor control structures.

    We use the basic profile for 64 bit Linux systems to get the expected width
    for each data type.
    """

    vmcs_vtype_64 = {
        # The base VMCS structure
        "VMCS": [0x0, {
            "REVISION_ID": [0, ["BitField", {
                "start_bit": 0,
                "end_bit": 30,
                "target": "unsigned int"
                }]],
            "IS_SHADOW_VMCS": [0, ["BitField", {
                "start_bit": 31,
                "end_bit": 32,
                "target": "unsigned int",
                }]],
            "ABORT_INDICATOR": [4, ["unsigned int"]],
            }],
        "PENRYN_VMCS": [0x0, {
            "REVISION_ID": [0, ["BitField", {
                "start_bit": 0,
                "end_bit": 30,
                "target": "unsigned int",
                }]],
            "IS_SHADOW_VMCS": [0, ["BitField", {
                "start_bit": 31,
                "end_bit": 32,
                "target": "unsigned int",
                }]],
            "ABORT_INDICATOR": [4, ["unsigned int"]],
            "GUEST_CR4": [784, ["unsigned long long"]],
            "HOST_CR3": [904, ["unsigned long long"]],
            "HOST_CR4": [912, ["unsigned long long"]],
            "VMCS_LINK_POINTER": [32, ["unsigned int"]],
            "VMCS_LINK_POINTER_HIGH": [36, ["unsigned int"]],
            }],
        "NEHALEM_VMCS": [0x0, {
            "REVISION_ID": [0, ["BitField", {
                "start_bit": 0,
                "end_bit": 30,
                "target": "unsigned int",
                }]],
            "IS_SHADOW_VMCS": [0, ["BitField", {
                "start_bit": 31,
                "end_bit": 32,
                "target": "unsigned int",
                }]],
            "ABORT_INDICATOR": [4, ["unsigned int"]],
            "GUEST_CR4": [744, ["unsigned long long"]],
            "HOST_CR3": [832, ["unsigned long long"]],
            "HOST_CR4": [840, ["unsigned long long"]],
            "VMCS_LINK_POINTER": [248, ["unsigned int"]],
            "VMCS_LINK_POINTER_HIGH": [252, ["unsigned int"]],
            "EPT_POINTER": [232, ["unsigned long long"]],
            }],
        "WESTMERE_VMCS": [0x0, {
            "REVISION_ID": [0, ["BitField", {
                "start_bit": 0,
                "end_bit": 30,
                "target": "unsigned int",
                }]],
            "IS_SHADOW_VMCS": [0, ["BitField", {
                "start_bit": 31,
                "end_bit": 32,
                "target": "unsigned int",
                }]],
            "ABORT_INDICATOR": [4, ["unsigned int"]],
            "GUEST_CR4": [744, ["unsigned long long"]],
            "HOST_CR3": [832, ["unsigned long long"]],
            "HOST_CR4": [840, ["unsigned long long"]],
            "VMCS_LINK_POINTER": [248, ["unsigned int"]],
            "VMCS_LINK_POINTER_HIGH": [252, ["unsigned int"]],
            "EPT_POINTER": [320, ["unsigned long long"]],
            }],
        "SANDYBRIDGE_VMCS": [0x0, {
            "REVISION_ID": [0, ["BitField", {
                "start_bit": 0,
                "end_bit": 30,
                "target": "unsigned int",
                }]],
            "IS_SHADOW_VMCS": [0, ["BitField", {
                "start_bit": 31,
                "end_bit": 32,
                "target": "unsigned int",
                }]],
            "ABORT_INDICATOR": [4, ["unsigned int"]],
            "GUEST_CR4": [744, ["unsigned long long"]],
            "HOST_CR3": [832, ["unsigned long long"]],
            "HOST_CR4": [840, ["unsigned long long"]],
            "VMCS_LINK_POINTER": [248, ["unsigned int"]],
            "VMCS_LINK_POINTER_HIGH": [252, ["unsigned int"]],
            "EPT_POINTER": [232, ["unsigned long long"]],
            }],
    }

    def __init__(self, **kwargs):
        super(VMCSProfile, self).__init__(**kwargs)
        self.add_types(self.vmcs_vtype_64)


class VMCSScanner(scan.BaseScanner):
    """Scans the memory attempting to find VMCS structures.

    Uses the techniques discussed on "Hypervisor Memory Forensics"
    (http://s3.eurecom.fr/docs/raid13_graziano.pdf) with slight changes
    to identify VT-x hypervisors.
    """

    def __init__(self, **kwargs):
        super(VMCSScanner, self).__init__(**kwargs)
        # Temporary address space
        self._buffer_as = addrspace.BufferAddressSpace()
        self.profile = VMCSProfile()

    def scan(self, offset=0, **_):
        """We overwrite scan to achieve maximum scanning speed."""

        maxlen = list(self.address_space.get_available_addresses())[-1][1]
        for cur_offset in range(offset, maxlen, 0x1000):
            current_hypervisor = self.address_space.read(cur_offset, 0x1000)
            # Update our temporary buffer address space
            self._buffer_as.assign_buffer(current_hypervisor,
                                         base_offset=cur_offset)

           # CHECK 1: Verify that the VMX-Abort indicator has a known value.
           #
           # The VMX-Abort indicator field is always at offset 4 in the VMCS
           # and is a 32-bit field.
           # This field should be 0 unless the memory image was taken while a
           # VMX-abort occurred, which is fairly unlikely. Also, if a VMX-abort
           # occurs, only a set of values are supposed to be set.
           #
            if not current_hypervisor[4:8] in KNOWN_ABORT_INDICATOR_CODES:
                continue

            # Obtain the Revision ID
            (revision_id,) = struct.unpack_from("<I", current_hypervisor)
            revision_id = revision_id & 0x7FFFFFFF

            # Obtain a VMCS object based on the revision_id
            try:
                platform = KNOWN_REVISION_IDS.get(revision_id)
                if platform is None:
                    continue
                vmcs_obj = self.profile.Object("%s_VMCS" % platform,
                                               offset=cur_offset,
                                               vm=self._buffer_as)
            except (AttributeError, TypeError):
                continue

            # CHECK 2: Verify that the VMCS has the VMX flag enabled.
            if not vmcs_obj.HOST_CR4 & 0x2000:
                continue

            # CHECK 3: Verify that the VMCS_LINK_POINTER is 0xFFFFFFFFFFFFFFFF.
            if (vmcs_obj.VMCS_LINK_POINTER ==
                vmcs_obj.VMCS_LINK_POINTER_HIGH == 0xFFFFFFFF):
                # Assign the proper address_space for the candidate.
                vmcs_obj.obj_vm = self.address_space

                # VALIDATION: Verify that the EPT translation works.
                # Note that this validation may fail for nested VMCS.
                validation_as = amd64.VTxPagedMemory(ept=vmcs_obj.EPT_POINTER,
                                                     base=self.address_space)
                validated = False
                for _ in validation_as.get_available_addresses():
                    validated = True
                    break

                yield vmcs_obj, cur_offset, validated


    def skip(self, buffer_as, offset):
        return 0x1000


class VmScan(plugin.PhysicalASMixin, plugin.Command):
    """Scan the physical memory attempting to find hypervisors.

    Once EPT values are found, you can use them to inspect virtual machines
    with any of the rekall modules by using the --ept parameter and
    specifying the guest virtual machine profile.

    Supports the detection of the following virtualization techonlogies:
      * Intel VT-X with EPT. Microarchitectures:
        + Westmere
        + Nehalem
        + Sandybridge

      * Intel VT-X without EPT (unsupported page translatioa in rekall).
        + Penryn

    For the specific processor models that support EPT, please check:
    http://ark.intel.com/products/virtualizationtechnology.
    """
    __name = "vmscan"

    @classmethod
    def args(cls, parser):
        """Declare the command line args we accept."""
        super(VmScan, cls).args(parser)
        parser.add_argument(
            "--hypervisor_details", default=False,
            action="store_true", help="Show details about each hypervisor.")
        parser.add_argument(
            "--offset", action=config.IntParser, default=0,
            help="Offset in the physical image to start the scan.")

    def __init__(self, offset=0, hypervisor_details=False, **kwargs):
        super(VmScan, self).__init__(**kwargs)
        self._offset = offset
        self._hypervisor_details = hypervisor_details

    def render(self, renderer=None):
        scanner = VMCSScanner(address_space=self.physical_address_space,
                              session=self.session)
        renderer.table_header([("Offset", "offset", "[addrpad]"),
                               ("Type", "type", ">20s"),
                               ("EPT", "ept", "[addrpad]"),
                               ("Valid", "valid", ">6s"),
                               ])
        hypervisors = [hypervisor for hypervisor in
                       scanner.scan(offset=self._offset)]

        for (vmcs, vmcs_offset, valid) in hypervisors:
            renderer.table_row(vmcs.obj_offset, vmcs.obj_name,
                               vmcs.m("EPT_POINTER"), valid)

        if self._hypervisor_details:
            for (vmcs, vmcs_offset, valid) in hypervisors:
                renderer.section("Hypervisor @ %#x" % vmcs_offset)
                self.session.plugins.p(vmcs).render(renderer)
