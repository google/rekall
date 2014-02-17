"""Implements scanners and plugins to find hypervisors in memory."""

from rekall import addrspace
from rekall import config
from rekall import plugin
from rekall import scan
from rekall.plugins.addrspaces import amd64
from rekall.plugins.addrspaces import intel
from rekall.plugins.overlays import basic

import struct


ONE_GB = 1024 * 1024 * 1024

KNOWN_REVISION_IDS = {
    # Intel VT-x microarchitectures.
    0x0d: "PENRYN",
    0x0e: "NEHALEM",
    0x0f: "WESTMERE",
    0x10: "SANDYBRIDGE",
    0x12: "HASWELL",
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


class VMCSCheck(scan.ScannerCheck):
    def check(self, buffer_as, offset):
        # CHECK 1: Verify that the VMX-Abort indicator has a known value.
        #
        # The VMX-Abort indicator field is always at offset 4 in the VMCS
        # and is a 32-bit field.
        # This field should be 0 unless the memory image was taken while a
        # VMX-abort occurred, which is fairly unlikely. Also, if a VMX-abort
        # occurs, only a set of values are supposed to be set.
        if buffer_as.read(offset+4, 4) in KNOWN_ABORT_INDICATOR_CODES:
            # Obtain the Revision ID
            (revision_id,) = struct.unpack_from("<I", buffer_as.read(offset, 4))
            revision_id = revision_id & 0x7FFFFFFF

            # Obtain a VMCS object based on the revision_id
            try:
                platform = KNOWN_REVISION_IDS.get(revision_id)
                if platform is not None:
                    vmcs_obj = self.profile.Object("%s_VMCS" % platform,
                                                   offset=offset,
                                                   vm=buffer_as)
                    # CHECK 2: Verify that the VMCS has the VMX flag enabled.
                    if vmcs_obj.HOST_CR4 & 0x2000:
                        # CHECK 3: Verify that VMCS_LINK_POINTER is
                        # 0xFFFFFFFFFFFFFFFF.
                        if (vmcs_obj.VMCS_LINK_PTR_FULL == 0xFFFFFFFFFFFFFFFF):
                            return True
            except (AttributeError, TypeError):
                pass
        return False


class VMCSScanner(scan.BaseScanner):
    """Scans the memory attempting to find VMCS structures.

    Uses the techniques discussed on "Hypervisor Memory Forensics"
    (http://s3.eurecom.fr/docs/raid13_graziano.pdf) with slight changes
    to identify VT-x hypervisors.
    """

    overlap = 0

    checks = [["VMCSCheck", {}]]

    def __init__(self, **kwargs):
        super(VMCSScanner, self).__init__(**kwargs)
        self.profile = self.session.LoadProfile("VMCS")

    def scan(self, offset=0, **_):
        """Returns instances of VMCS objects found."""

        for offset in super(VMCSScanner, self).scan(offset=offset):
            (revision_id,) = struct.unpack("<I",
                                           self.address_space.read(offset, 4))
            revision_id = revision_id & 0x7FFFFFFF
            vmcs_obj = self.profile.Object(
                "%s_VMCS" % KNOWN_REVISION_IDS.get(revision_id),
                offset=offset, vm=self.address_space)

            yield vmcs_obj

    def validate_vmcs(self, vmcs_obj):
      """Validates that the VMCS is mapped in the page tables of HOST_CR3.

      Returns a tuple of (validates, host_as_type, host_as_size).
      """
      validated = False
      if not vmcs_obj.HOST_CR4 & (1 << 5):  # PAE bit
          # No PAE
          validation_as = intel.IA32PagedMemory(
              dtb=vmcs_obj.HOST_CR3, base=self.address_space)
          host_as_type = "32bit"

      elif not vmcs_obj.EXIT_CONTROLS & (1 << 9):  # long mode bit
          # PAE and no long mode = 32bit PAE
          validation_as = intel.IA32PagedMemoryPae(
              dtb=vmcs_obj.HOST_CR3, base=self.address_space)
          host_as_type = "32bit+PAE"

      elif vmcs_obj.EXIT_CONTROLS & (1 << 9):  # long mode bit
          # Long mode AND PAE = IA-32e
          validation_as = amd64.AMD64PagedMemory(
              dtb=vmcs_obj.HOST_CR3, base=self.address_space)
          host_as_type = "64bit"
      else:
          # We don't have an address space for other paging modes
          return validated, None, None

      # The size of the AS of the host
      as_size = 0
      for vaddr, paddr, size in validation_as.get_available_addresses():
          as_size += size

          if self.session:
              self.session.report_progress("Validating VMCS %08X @ %08X" %
                  (vmcs_obj.obj_offset, vaddr))
          if (paddr <= vmcs_obj.obj_offset and
              vmcs_obj.obj_offset < paddr + size):
              validated = True
              break
      return validated, host_as_type, as_size

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
        + Ivy Bridge
        + Haswell

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
            "--no_validation", default=False,
            action="store_true", help="Validate each VMCS.")
        parser.add_argument(
            "--hypervisor_details", default=False,
            action="store_true", help="Show details about each hypervisor.")
        parser.add_argument(
            "--offset", action=config.IntParser, default=0,
            help="Offset in the physical image to start the scan.")

    def __init__(self, offset=0, hypervisor_details=False, no_validation=False,
                 **kwargs):
        super(VmScan, self).__init__(**kwargs)
        self._offset = offset
        self._hypervisor_details = hypervisor_details
        self._validate = not no_validation

    def render(self, renderer=None):
        scanner = VMCSScanner(address_space=self.physical_address_space,
                              session=self.session)
        renderer.table_header([("Offset", "offset", "[addrpad]"),
                               ("Type", "type", ">20s"),
                               ("EPT", "ept", "[addrpad]"),
                               ("Valid", "valid", ">10s"),
                               ("Host AS type", "valid", ">14s"),
                               ("Host AS size (GB)", "valid", ">17s"),
                               ])
        hypervisors = [hypervisor for hypervisor in
                       scanner.scan(offset=self._offset)]

        for vmcs in hypervisors:
            valid = as_type = as_size = None

            if self._validate:
                valid, as_type, as_size = scanner.validate_vmcs(vmcs)
                try:
                    as_size = '%12.02f' % (as_size / float(ONE_GB))
                except TypeError:
                    pass

            renderer.table_row(vmcs.obj_offset, vmcs.obj_name,
                               vmcs.m("EPT_POINTER_FULL"), valid,
                               as_type, as_size)

        if self._hypervisor_details:
            for vmcs, valid in hypervisors:
                renderer.section("Hypervisor @ %#x" % vmcs_offset)
                self.session.plugins.p(vmcs).render(renderer)
