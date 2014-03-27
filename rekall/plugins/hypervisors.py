"""Implements scanners and plugins to find hypervisors in memory."""

from rekall import config
from rekall import plugin
from rekall import scan
from rekall import session
from rekall.plugins.addrspaces import amd64
from rekall.plugins.addrspaces import intel
from rekall.plugins.overlays import basic

from itertools import groupby
import struct


KNOWN_REVISION_IDS = {
    # Nested hypervisors
    # VMware Workstation 10.X
    0x01: "VMWARE_NESTED",
    # KVM
    0x11e57ed0: "KVM_NESTED",
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


vmcs_overlay = {
    'NEHALEM_VMCS' : [None, {
        'IS_NESTED': lambda x: False,
        }],
    'SANDYBRIDGE_VMCS' : [None, {
        'IS_NESTED': lambda x: False,
        }],
    'HASWELL_VMCS' : [None, {
        'IS_NESTED': lambda x: False,
        }],
    'WESTMERE_VMCS' : [None, {
        'IS_NESTED': lambda x: False,
        }],
    'PENRYN_VMCS' : [None, {
        'IS_NESTED': lambda x: False,
        }],
    'VMWARE_NESTED_VMCS' : [None, {
        'IS_NESTED': lambda x: True,
        }],
    'KVM_NESTED_VMCS' : [None, {
        'IS_NESTED': lambda x: True,
        }],
    }


class Error(Exception):
    """Base exception."""


class UnrelatedVmcsError(Error):
    """The provided VMCS is unrelated to the VM."""


class IncompatibleASError(Error):
    """An attempt was done at comparing VMCS from different address spaces."""


class InvalidVM(Error):
    """The provided VM is invalid."""


class VMCSProfile(basic.ProfileLP64):
    """Profile to parse hypervisor control structures.

    We use the basic profile for 64 bit Linux systems to get the expected width
    for each data type.
    """

    @classmethod
    def Initialize(cls, profile):
        super(VMCSProfile, cls).Initialize(profile)
        profile.add_overlay(vmcs_overlay)


class VMCSCheck(scan.ScannerCheck):
    def check(self, buffer_as, offset):
        # CHECK 1: Verify that the VMX-Abort indicator has a known value.
        #
        # The VMX-Abort indicator field is always at offset 4 in the VMCS
        # and is a 32-bit field.
        # This field should be 0 unless the memory image was taken while a
        # VMX-abort occurred, which is fairly unlikely. Also, if a VMX-abort
        # occurs, only a set of values are supposed to be set.
        if buffer_as.read(offset+4, 4) not in KNOWN_ABORT_INDICATOR_CODES:
            return False

        # Obtain the Revision ID
        (revision_id,) = struct.unpack_from("<I", buffer_as.read(offset, 4))
        revision_id = revision_id & 0x7FFFFFFF

        # Obtain a VMCS object based on the revision_id
        platform = KNOWN_REVISION_IDS.get(revision_id)
        if platform is None:
            return False

        try:
            vmcs_obj = self.profile.Object("%s_VMCS" % platform,
                                           offset=offset,
                                           vm=buffer_as)
        except (AttributeError, TypeError):
            return False

        # CHECK 2: Verify that the VMCS has the VMX flag enabled.
        if not vmcs_obj.HOST_CR4 & 0x2000:
            return False

        # CHECK 3: Verify that VMCS_LINK_POINTER is
        # 0xFFFFFFFFFFFFFFFF.
        if vmcs_obj.VMCS_LINK_PTR_FULL != 0xFFFFFFFFFFFFFFFF:
            return False

        return True


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


    def skip(self, buffer_as, offset):
        return 0x1000


class VirtualMachine(object):
    """Represents a virtual machine.

    A virtual machine is made of VMCS. In Intel processors, each CPU that runs
    a VM will have its own VMCS.
    """

    def __init__(self, host_rip=None, ept=None, parent=None, name=None,
                 session=None):
        self.ept = long(ept)
        self.host_rip = long(host_rip)
        self.parent = parent
        self.name = name
        self.base_session = session
        self.vmcss = set()
        # Dictionary where the key is a VMCS object and the value
        # represents whether the VMCS is valid, or not.
        self.vmcs_validation = dict()
        self.virtual_machines = []

    @property
    def is_valid(self):
        """A VM is valid if at least one of its VMCS is valid."""
        if any([self.vmcs_validation.get(vmcs, False) for vmcs in self.vmcss]):
            return True
        return False

    @property
    def is_nested(self):
        """A VM is nested if it has a parent or all its VMCS are nested."""
        return self.parent != None

    @property
    def num_cores(self):
        """The number of virtual cores of this VM."""
        valid_vmcss = filter(self.is_valid_vmcs, self.vmcss)
        # Count only unique VPIDs if the hypervisor uses them.
        uniq_vpids = set([v.VPID for v in valid_vmcss])
        if len(uniq_vpids) != 1:
            return len(uniq_vpids)
        else:
            return len(valid_vmcss)

    @property
    def host_arch(self):
        """The architecture of the host that started this VM."""
        all_host_as = set([self.get_vmcs_host_as_type(v) for v in self.vmcss
                           if self.is_valid_vmcs(v)])
        if len(all_host_as) == 1:
            return all_host_as.pop()
        return "???"

    @property
    def guest_arch(self):
        """The architecture of the guest OS of the VM."""
        all_guest_as = set([self.get_vmcs_guest_as_type(v) for v in self.vmcss
                           if self.is_valid_vmcs(v)])
        if len(all_guest_as) == 1:
            return all_guest_as.pop()
        return "???"

    @property
    def ept_list(self):
        """The list of EPT values needed to instantiate VM guest physical AS.

        This is used in conjunction with the VTxPagedMemory AS.
        """

        if isinstance(self.parent, VirtualMachine):
            ept_list = self.parent.ept_list
            ept_list.extend([self.ept])
        else:
            ept_list = [self.ept]
        return ept_list

    @property
    def physical_address_space(self):
        """The physical address space of this VM's guest."""

        if self.is_nested:
            base_as = self.parent.physical_address_space
        else:
            base_as = self.base_session.physical_address_space

        return amd64.VTxPagedMemory(
            session=self.base_session, ept=self.ept_list, base=base_as)


    @classmethod
    def get_vmcs_guest_as_type(cls, vmcs):
        """Returns the address space type of the guest of a VMCS.

        One of I386, I386+PAE, AMD64 or None.
        """
        if not vmcs.GUEST_CR4 & (1 << 5):  # PAE bit
            # No PAE
            return "I386"
        elif not vmcs.ENTRY_CONTROLS & (1 << 9):  # long mode bit
            # PAE and no long mode = 32bit PAE
            return "I386+PAE"
        elif vmcs.ENTRY_CONTROLS & (1 << 9):  # long mode bit
            # Long mode AND PAE = IA-32e
            return "AMD64"
        else:
            # We don't have an address space for other paging modes
            return None

    @classmethod
    def get_vmcs_host_as_type(cls, vmcs):
        """Returns the address space type of the host of a VMCS.

        One of I386, I386+PAE, AMD64 or None.
        """
        if not vmcs.HOST_CR4 & (1 << 5):  # PAE bit
            # No PAE
            return "I386"
        elif not vmcs.EXIT_CONTROLS & (1 << 9):  # long mode bit
            # PAE and no long mode = 32bit PAE
            return "I386+PAE"
        elif vmcs.EXIT_CONTROLS & (1 << 9):  # long mode bit
            # Long mode AND PAE = IA-32e
            return "AMD64"
        else:
            # We don't have an address space for other paging modes
            return None

    @classmethod
    def get_vmcs_host_address_space(cls, vmcs, base_as=None):
        """Returns the address_space of the host of the VMCS."""
        return cls.get_vmcs_address_space(vmcs, host=True, base_as=base_as)

    @classmethod
    def get_vmcs_guest_address_space(cls, vmcs, base_as=None):
        """Returns the address_space of the guest of the VMCS."""
        return cls.get_vmcs_address_space(vmcs, host=False, base_as=base_as)

    @classmethod
    def get_vmcs_address_space(cls, vmcs, host=True, base_as=None):
        """Returns the address_space of the host or guest of a VMCS."""
        address_space = None
        base_as = base_as or vmcs.obj_vm

        if host:
            cr4 = vmcs.HOST_CR4
            cr3 = vmcs.HOST_CR3
            controls = vmcs.EXIT_CONTROLS
        else:
            cr4 = vmcs.GUEST_CR4
            cr3 = vmcs.GUEST_CR3
            controls = vmcs.ENTRY_CONTROLS

        if not cr4 & (1 << 5):  # PAE bit
            # No PAE
            address_space = intel.IA32PagedMemory(dtb=cr3, base=base_as)

        elif not controls & (1 << 9):  # long mode bit
            # PAE and no long mode = 32bit PAE
            address_space = intel.IA32PagedMemoryPae(dtb=cr3, base=base_as)

        elif controls & (1 << 9):  # long mode bit
            # Long mode AND PAE = IA-32e
            address_space = amd64.AMD64PagedMemory(dtb=cr3, base=base_as)
        return address_space

    def add_vmcs(self, vmcs, validate=True):
        """Add a VMCS to this virtual machine.

        Raises:
          UnrelatedVmcsError if the VMCS doesn't match the VM's HOST_RIP or EPT.
        """
        if self.host_rip == None:
            self.host_rip = long(vmcs.HOST_RIP)

        if self.ept == None:
            self.ept = long(vmcs.EPT_POINTER_FULL)

        if self.host_rip != vmcs.HOST_RIP:
            raise UnrelatedVmcsError("VMCS HOST_RIP differ from the VM's")

        if vmcs.EPT_POINTER_FULL != self.ept:
            raise UnrelatedVmcsError("VMCS EPT differs from the VM's")

        if validate:
            self.validate_vmcs(vmcs)

        self.vmcss.add(vmcs)

    def add_nested_vm(self, vm):
        """Adds a nested VM to this VM."""

        if vm.parent != self:
            vm.set_parent(self)

        self.virtual_machines.append(vm)

    def remove_nested_vm(self, vm):
        """Removes a VM from the list of nested VMs."""
        if vm in self.virtual_machines:
            self.virtual_machines.remove(vm)
            vm.unset_parent()
        raise InvalidVM("This VM is unknown.")

    def set_parent(self, parent):
        """Sets the parent of this VM and resets the validation cache."""
        if self.parent != parent:
            self.parent = parent
            self.vmcs_validation.clear()

    def unset_parent(self, parent):
        _ = parent
        self.parent = None

    def validate_vmcs(self, vmcs):
        """Validates a VMCS and returns if it's valid in this VM's context.

        A VMCS is valid if the page where it's mapped is found in the HOST_CR3
        that it points to. The result of this validation is cached. Use
        the _reset_validation_state method if you need to invalidate cache
        entries.
        """
        if vmcs in self.vmcs_validation:
            return self.vmcs_validation.get(vmcs)

        if self.is_nested:
            return self._validate_nested_vmcs(vmcs)

        validated = False

        # If we are dealing with L1 VMCS, the address space to validate
        # is the same as the VMCS.
        validation_as = self.get_vmcs_host_address_space(vmcs)

        for vaddr, paddr, size in validation_as.get_available_addresses():
            if self.base_session:
                self.base_session.report_progress(
                    "Validating VMCS %08X @ %08X" % (
                        vmcs.obj_offset, vaddr))
            if paddr <= vmcs.obj_offset and vmcs.obj_offset < paddr + size:
                validated = True
                break
        self.vmcs_validation[vmcs] = validated
        return validated

    def is_valid_vmcs(self, vmcs):
        """Returns whether the vmcs is valid or None if it wasn't validated.

        Doesn't force validation.
        """
        return self.vmcs_validation.get(vmcs)

    def GetSession(self):
        """Returns a session valid for this VM."""

        if not self.is_valid:
            raise InvalidVM()

        session_override = {
            "ept": self.ept_list,
            "no_autodetect": False,
            "profile": None,
            "module": None,
            "run": None,
        }

        sess = session.Session()
        with sess.state as state:
            for k, v in self.base_session.state.iteritems():
                if k in session_override:
                    state.Set(k, session_override.get(k))
                elif k == "cache":
                    continue
                else:
                    state.Set(k, v)

        return sess

    def RunPlugin(self, plugin_name, *args, **kwargs):
        """Runs a plugin in the context of this virtual machine."""
        vm_sess = self.GetSession()
        return vm_sess.RunPlugin(plugin_name, *args, **kwargs)

    def _validate_nested_vmcs(self, vmcs):
        """Validates a VMCS as a nested VMCS in this VM's context."""
        if vmcs in self.vmcs_validation:
            return self.vmcs_validation.get(vmcs)

        validated = False

        # VMCS that are nested in nature cannot be validated against VMs that
        # are not nested and viceversa.
        if ((self.is_nested and not vmcs.IS_NESTED)
            or (not self.is_nested and vmcs.IS_NESTED)):
            return False

        # We validate nested VMCS by walking the HOST_CR3 of the VMCS and
        # then the EPT page tables of the parent.

        # We need to make sure the vmcs's AS is in this VM's AS chain, so
        # we can eventually validate it.
        parent_as = self.parent.physical_address_space
        while parent_as != vmcs.obj_vm and parent_as != parent_as.base:
            parent_as = parent_as.base
        if parent_as != vmcs.obj_vm:
            raise IncompatibleASError(
                "Unable to validate VMCS. Incompatible address spaces.")

        # We cannot validate PENRYN or previous microarchitectures
        # that don't support EPT translation.
        if vmcs.v("EPT_POINTER_FULL") == None:
            return False

        # Now we create an address space that translates from the parent's
        # physical AS to the parent's parent physical AS.
        # This is VMCS01.
        parent_as = self.parent.physical_address_space

        # And now we stack the VMCS12 HOST_CR3 AS on top of the VMCS01
        # address space.
        validation_as = self.get_vmcs_host_address_space(
            vmcs, base_as=parent_as)

        for vaddr, paddr, size in validation_as.get_available_addresses():
            # Now note that this paddr isn't a real physical
            # address. This is the parent VM physical address.
            # So we now need to do EPT translation to get the
            # actual physical address.
            test_as = validation_as
            while test_as.base != vmcs.obj_vm:
                test_as = test_as.base
                paddr = test_as.vtop(paddr)
                # Because we may be validating invalid VMCS, it's
                # likely we will get invalid addresses.
                if paddr == None:
                    break
            if paddr == None:
                continue
            paddr = test_as.base.vtop(paddr)
            if paddr == None:
                continue

            if self.base_session:
                self.base_session.report_progress(
                    "Validating NESTED VMCS %08X @ %08X" % (
                        vmcs.obj_offset, vaddr))

            if paddr <= vmcs.obj_offset and vmcs.obj_offset < paddr + size:
                validated = True
                break

        self.vmcs_validation[vmcs] = validated
        return validated


    def _reset_validation_state(self, vmcs):
        """Invalidates the vmcs validation cache entry for vmcs."""
        self.vmcs_validation.pop(vmcs, None)

    def __str__(self):
        return "VirtualMachine(Hypervisor=%#X, EPT=%#X)" % (
            self.host_rip, self.ept)


class VmScan(plugin.PhysicalASMixin, plugin.VerbosityMixIn, plugin.Command):
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
            "--offset", action=config.IntParser, default=0,
            help="Offset in the physical image to start the scan.")
        parser.add_argument(
            "--show_all", default=False,
            action="store_true", help="Also show VMs that failed validation.")
        parser.add_argument(
            "--no_validation", default=False,
            action="store_true",
            help=("[DEBUG SETTING] Disable validation of VMs."))

    def __init__(self, offset=0, no_validation=False, show_all=False, **kwargs):
        super(VmScan, self).__init__(**kwargs)
        self._offset = offset
        self._validate = not no_validation
        self._show_all = show_all
        if not self._validate:
            self._show_all = True

    def get_vms(self):
        """Finds virtual machines in physical memory and returns a list of them.
        """

        all_vmcs = VMCSScanner(address_space=self.physical_address_space,
                               session=self.session).scan(offset=self._offset)

        host_vms = []
        nested_vms = []

        # == HOST VM validation
        # Group the host VMCSs by (HOST_RIP, EPTP) and validate if requested.
        # You could use (HOST_RIP, HOST_CR3), but VMWare 10.X uses a different
        # HOST_CR3 per core. The EPTP, however, is the same and hardly any
        # virtualization product would ever want to have different EPTP's per
        # core.
        for host_rip, rip_vmcs_list in groupby(
            sorted(all_vmcs, key=lambda x: long(x.HOST_RIP)),
            lambda x: long(x.HOST_RIP)):

            for ept, rip_ept_vmcs_list in groupby(
                sorted(rip_vmcs_list, key=lambda x: long(x.EPT_POINTER_FULL)),
                lambda x: long(x.EPT_POINTER_FULL)):

                vm = VirtualMachine(host_rip=host_rip, ept=ept,
                                    session=self.session)
                for vmcs in rip_ept_vmcs_list:
                    try:
                        # If a VMCS is nested we cannot do validation at this
                        # step. However, if the physical address_space is a
                        # VTxPagedMemory, as if you had run vmscan inside a VM,
                        # by specifying the --ept parameter on the command line,
                        # we can and should do validation here.
                        if (vmcs.IS_NESTED
                            and not isinstance(self.physical_address_space,
                                               amd64.VTxPagedMemory)):
                            # We cannot do validation yet for nested VMs
                            vm.add_vmcs(vmcs, validate=False)
                        else:
                            vm.add_vmcs(vmcs, validate=self._validate)
                    except UnrelatedVmcsError:
                        # This may happen when we analyze our own memory, when
                        # the HOST_RIP/EPT that we grouped with has changed.
                        # Not much we can do other than skipping this VMCS.
                        continue

                # Skip adding empty VMs, which can happen if we skipped vmcss.
                if vm.vmcss:
                    # We need to split nested and host VMs here. However, we
                    # cannot use the is_nested method of vm, because the
                    # potential nested VMs aren't technically nested yet
                    # (i.e: don't have a parent) so we resort to checking if
                    # all the VMCSs are of nested-type.
                    may_be_nested = all([v.IS_NESTED for v in vm.vmcss])
                    if self._validate and may_be_nested:
                        nested_vms.append(vm)
                    else:
                        host_vms.append(vm)

        # == NESTED VM validation
        # To validate nested VMs and, in the process, discover their hierarchy,
        # we need to try each logical combination with the identified host VMs
        # as parents.
        #
        # TODO: Detect turtles-type VMCSs and relate them to the proper VM.
        # https://www.usenix.org/event/osdi10/tech/full_papers/Ben-Yehuda.pdf
        #
        # These should, at the moment, show up as another valid VM.
        if self._validate:
            candidate_hosts = [vm for vm in host_vms if vm.is_valid]
        else:
            candidate_hosts = []

        for candidate_host_vm in candidate_hosts:
            for nested_vm in nested_vms:
                old_parent = nested_vm.parent
                nested_vm.set_parent(candidate_host_vm)
                valid_combo = False

                # TODO: This could be optimized so we only do one pass per
                # candidate_host and nested_vm for these VMCS in the nested VM
                # that share the same HOST_CR3. In practice, it seems it will
                # only be an improvement for just a few hypervisors.
                for vmcs in nested_vm.vmcss:
                    # Need to reset the validation status every round if we
                    # didn't find a candidate host for this VM or else
                    # validation will always fail after 1 attempt.
                    nested_vm._reset_validation_state(vmcs)
                    if nested_vm.validate_vmcs(vmcs):
                        valid_combo = True
                        break

                if valid_combo:
                    # Add this VM to the list of child VMs of the host VM
                    candidate_host_vm.add_nested_vm(nested_vm)
                else:
                    # Reset the parent to leave the nested_vm untouched.
                    nested_vm.set_parent(old_parent)

            # Remove validated VMs from the list of nested_vms that still need
            # discovering of their herarchy.
            for vm in candidate_host_vm.virtual_machines:
                nested_vms.remove(vm)

        # Add all remaining VMs that werent able to guess the hierarchy of to
        # the output vm list.
        host_vms.extend(nested_vms)
        return host_vms


    def render(self, renderer=None):
        renderer.table_header([("Virtual machines", "description", "<36s"),
                               ("Type", "type", ">20s"),
                               ("Valid", "valid", ">8s"),
                               ("EPT", "ept", "s")
                               ])
        virtual_machines = self.get_vms()

        # At this point the hierarchy has been discovered.
        for vm_idx, vm in enumerate(virtual_machines):
            # Skip invalid VMs.
            if not self._show_all and not vm.is_valid:
                continue
            self.render_vm(renderer, vm, vm_idx, indent_level=0)
            # Separate each top-level VM
            renderer.section()

        if self.verbosity > 1:
            for vm in virtual_machines:
                for vmcs in vm.vmcss:
                    if not self._show_all and not vm.is_valid_vmcs(vmcs):
                        continue
                    renderer.section("VMCS @ %#x" % vmcs.obj_offset)
                    self.session.plugins.p(vmcs).render(renderer)

                for nested_vm in vm.virtual_machines:
                    for vmcs in nested_vm.vmcss:
                        if not self._show_all and not vm.is_valid_vmcs(vmcs):
                            continue
                        renderer.section("VMCS @ %#x" % vmcs.obj_offset)
                        self.session.plugins.p(vmcs).render(renderer)

    def render_vm(self, renderer, vm, vm_index, indent_level=0):
        indentation = "  " * indent_level
        vm_description = "{0:s}VM #{1:d} [{2:d} vCORE, {3:s}]"
        vm_description = vm_description.format(
            indentation, vm_index, vm.num_cores, vm.guest_arch)
        vm_ept = ','.join(["0x%X" % e for e in vm.ept_list])
        renderer.table_row(vm_description, 'VM', vm.is_valid, vm_ept)

        if self.verbosity > 1:
            for vmcs in sorted(vm.vmcss,
                               key=lambda x: x.m("VPID")):
                if not self._show_all and not vm.is_valid_vmcs(vmcs):
                    continue

                valid = vm.is_valid_vmcs(vmcs)
                renderer.table_row(
                    "{0:s}VMCS @ {1:#x} vCORE {2:X}".format(
                        "  " * (indent_level+1), vmcs.obj_offset, vmcs.VPID),
                    vmcs.obj_name, valid, '')

        for nested_vm_idx, nested_vm in enumerate(vm.virtual_machines):
            if not self._show_all and not nested_vm.is_valid:
                continue
            self.render_vm(renderer, nested_vm, nested_vm_idx,
                      indent_level=indent_level+2)
