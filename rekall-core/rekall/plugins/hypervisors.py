"""Implements scanners and plugins to find hypervisors in memory."""

from itertools import groupby
import struct

from rekall import plugin
from rekall import obj
from rekall import utils
from rekall import scan
from rekall import session as session_module
from rekall.plugins.addrspaces import amd64
from rekall.plugins.addrspaces import intel
from rekall.plugins.overlays import basic


KNOWN_REVISION_IDS = {
    # Nested hypervisors
    # VMware Workstation 10.X
    0x01: "VMWARE_NESTED",
    # KVM
    0x11e57ed0: "KVM_NESTED",
    # XEN
    0xda0400: "XEN_NESTED",
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
    'XEN_NESTED_VMCS' : [None, {
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

    def scan(self, offset=0, end=None, **_):
        """Returns instances of VMCS objects found."""
        for offset in super(VMCSScanner, self).scan(offset=offset, end=end):
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
        self.virtual_machines = set()

    @utils.safe_property
    def is_valid(self):
        """A VM is valid if at least one of its VMCS is valid."""
        if any([self.vmcs_validation.get(vmcs, False) for vmcs in self.vmcss]):
            return True
        return False

    @utils.safe_property
    def is_nested(self):
        """A VM is nested if it has a parent or all its VMCS are nested."""
        return self.parent != None

    @utils.safe_property
    def hostname(self):
        try:
            session = self.GetSession()
            return session.plugins.hostname().get_hostname()
        except AttributeError:
            return obj.NoneObject()
        except InvalidVM:
            return obj.NoneObject("**INVALID VM**")

    @utils.safe_property
    def num_cores(self):
        """The number of virtual cores of this VM."""
        valid_vmcss = filter(self.is_valid_vmcs, self.vmcss)
        # Count only unique VPIDs if the hypervisor uses them.
        uniq_vpids = set([v.VPID for v in valid_vmcss])
        if len(uniq_vpids) != 1:
            return len(uniq_vpids)
        else:
            return len(valid_vmcss)

    @utils.safe_property
    def host_arch(self):
        """The architecture of the host that started this VM."""
        all_host_as = set([self.get_vmcs_host_as_type(v) for v in self.vmcss
                           if self.is_valid_vmcs(v)])
        if len(all_host_as) == 1:
            return all_host_as.pop()
        return "???"

    @utils.safe_property
    def guest_arch(self):
        """The architecture of the guest OS of the VM."""
        all_guest_as = set([self.get_vmcs_guest_as_type(v) for v in self.vmcss
                            if self.is_valid_vmcs(v)])
        if len(all_guest_as) == 1:
            return all_guest_as.pop()
        return "???"

    @utils.safe_property
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

    @utils.safe_property
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
        """Returns the address_space of the host or guest process of a VMCS."""
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
            self.ept = long(vmcs.m("EPT_POINTER_FULL"))

        if self.host_rip != vmcs.HOST_RIP:
            raise UnrelatedVmcsError("VMCS HOST_RIP differ from the VM's")

        if vmcs.m("EPT_POINTER_FULL") != self.ept:
            raise UnrelatedVmcsError("VMCS EPT differs from the VM's")

        if validate:
            self.validate_vmcs(vmcs)

        self.vmcss.add(vmcs)

    def set_parent(self, parent):
        """Sets the parent of this VM and resets the validation cache."""
        if self.parent != parent:
            self.parent = parent
            self.vmcs_validation.clear()

    def unset_parent(self):
        self.set_parent(None)

    def validate_vmcs(self, vmcs):
        """Validates a VMCS and returns if it's valid in this VM's context.

        A VMCS is valid if the page where it's mapped is found in the HOST_CR3
        that it points to. The result of this validation is cached. Use
        the _reset_validation_state method if you need to invalidate cache
        entries.

        A VMCS object will only validate properly if its defined in the context
        of the address space of the physical AS of the parent of the VM.
        """
        if vmcs in self.vmcs_validation:
            return self.vmcs_validation.get(vmcs)

        validated = False


        # EPTP bits 11:6 are reserved and must be set to 0
        # and the page_walk_length, bits 5:3, must be 3 (4 - 1)
        #
        # Ref: Intel(r) 64 and IA-32 Architectures Software Developer's Manual -
        # System Programming Guide Volume 3B, 21-20, 21.6.11

        page_walk_length = (vmcs.EPT_POINTER_FULL & 0b111000) >> 3

        if (vmcs.EPT_POINTER_FULL & 0b111111000000 or
                page_walk_length != 3):
            self.vmcs_validation[vmcs] = validated
            return validated

        # If we are dealing with L1 VMCS, the address space to validate
        # is the same as the VMCS.
        try:
            validation_as = self.get_vmcs_host_address_space(vmcs)
        except TypeError:
            return False

        for run in validation_as.get_mappings():
            if self.base_session:
                self.base_session.report_progress(
                    "Validating VMCS %08X @ %08X" % (
                        vmcs.obj_offset, run.start))
            if (vmcs.obj_offset >= run.file_offset and
                    vmcs.obj_offset < run.file_offset + run.length):
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
            "profile": None,
            "session_name": u"VM %s" % u','.join(
                [u'0x%X' % s for s in self.ept_list]),
        }

        return self.base_session.clone(**session_override)

    def RunPlugin(self, plugin_name, *args, **kwargs):
        """Runs a plugin in the context of this virtual machine."""
        vm_sess = self.GetSession()
        return vm_sess.RunPlugin(plugin_name, *args, **kwargs)

    def add_nested_vms(self, vm_list, validate_all=True):
        """Tries to add the list of VMs as nested VMs of this one.

        To validate nested VMs, we need to see if its identifying VMCS are
        mapped in our physical AS and then try to validate them via HOST_CR3
        in our context.
        """
        _ = validate_all   # TODO: Not currently implemented.
        if not vm_list:
            return

        # If a VM is running under us, its VMCS has to be mapped in our
        # physical address space.
        phys_as = self.physical_address_space
        for run in phys_as.get_mappings():
            for vm in vm_list:
                if self.base_session:
                    self.base_session.report_progress(
                        u"Validating VM(%X) > VM(%X) @ %#X",
                        self.ept, vm.ept, run.file_offset)

                for vmcs in vm.vmcss:
                    # Skip VMCS that we already validated
                    if vm.is_valid_vmcs(vmcs):
                        continue

                    # This step makes sure the VMCS is mapped in the
                    # Level1 guest physical memory (us).
                    if (run.file_offset <= vmcs.obj_offset and
                            vmcs.obj_offset < run.file_offset + run.length):
                        # Now we need to validate the VMCS under our context.
                        # For this we need to fix the VMCS AS and its offset.
                        vm.set_parent(self)
                        vmcs_stored_vm = vmcs.obj_vm
                        vmcs_stored_offset = vmcs.obj_offset
                        # Change the VMCS to be mapped in this VM's physical AS.
                        vmcs.obj_vm = self.physical_address_space

                        # The new offset is the run.start + the offset within
                        # the physical page. We need to do this when we're
                        # dealing with large/huge pages.

                        # Note that run.start here really means the physical
                        # address of the L1 guest. run.file_offset means the
                        # physical address of the base AS (the host).
                        vmcs.obj_offset = (run.start +
                                           (run.file_offset - vmcs.obj_offset))
                        if vm.validate_vmcs(vmcs):
                            # This steps validates that the VMCS is mapped in
                            # the Level1 guest hypervisor AS.
                            self.virtual_machines.update([vm])
                        else:
                            # Reset the VMCS settings
                            vmcs.obj_vm = vmcs_stored_vm
                            vmcs.obj_offset = vmcs_stored_offset

        # If any of the VMs was found to be nested, remove it from the vm_list
        for vm in self.virtual_machines:
            try:
                vm_list.remove(vm)
            except ValueError:
                pass

    def _reset_validation_state(self, vmcs):
        """Invalidates the vmcs validation cache entry for vmcs."""
        self.vmcs_validation.pop(vmcs, None)

    def __str__(self):
        return "VirtualMachine(Hypervisor=%#X, EPT=%#X)" % (
            self.host_rip, self.ept)


class VmScan(plugin.PhysicalASMixin,
             plugin.TypedProfileCommand, plugin.Command):
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

      * Intel VT-X without EPT (unsupported page translation in rekall).
        + Penryn

    For the specific processor models that support EPT, please check:
    http://ark.intel.com/products/virtualizationtechnology.
    """
    __name = "vmscan"

    __args = [
        dict(name="quick", type="Boolean",
             help="Perform quick VM detection."),

        dict(name="no_nested", type="Boolean",
             help="Don't do nested VM detection."),

        dict(name="offset", type="IntParser", default=0,
             help="Offset in the physical image to start the scan."),

        dict(name="show_all", default=False, type="Boolean",
             help="Also show VMs that failed validation."),

        dict(name="image_is_guest", default=False, type="Boolean",
             help="The image is for a guest VM, not the host."),

        dict(name="no_validation", default=False, type="Boolean",
             help="[DEBUG SETTING] Disable validation of VMs.")
    ]

    def __init__(self, *args, **kwargs):
        super(VmScan, self).__init__(*args, **kwargs)
        if self.plugin_args.no_validate:
            self.plugin_args.show_all = True

    def get_vms(self):
        """Finds virtual machines in physical memory and returns a list of them.
        """

        all_vmcs = VMCSScanner(
            address_space=self.physical_address_space,
            session=self.session,
            profile=obj.NoneObject).scan(
                offset=self.plugin_args.offset,
                end=self.physical_address_space.end())

        host_vms = []
        nested_vms = []

        # == HOST VM validation
        # Group the host VMCSs by (HOST_RIP, EPTP) and validate if requested.
        # You could use (HOST_RIP, HOST_CR3), but VMWare 10.X uses a different
        # HOST_CR3 per core. The EPTP, however, is the same and hardly any
        # virtualization product would ever want to have different EPTP's per
        # core because more page tables would have to be maintained for the
        # same VM.
        for host_rip, rip_vmcs_list in groupby(
                sorted(all_vmcs, key=lambda x: long(x.HOST_RIP)),
                lambda x: long(x.HOST_RIP)):

            sorted_rip_vmcs_list = sorted(
                rip_vmcs_list, key=lambda x: long(x.m("EPT_POINTER_FULL")))

            for ept, rip_ept_vmcs_list in groupby(
                    sorted_rip_vmcs_list,
                    lambda x: long(x.m("EPT_POINTER_FULL"))):

                vm = VirtualMachine(host_rip=host_rip, ept=ept,
                                    session=self.session)
                for vmcs in rip_ept_vmcs_list:
                    try:
                        # If a VMCS is nested we cannot do validation at this
                        # step unless the memory image is for a guest VM or the
                        # physical address_space is a VTxPagedMemory. The
                        # physical AS is a VTxPagedMemory when you specify the
                        # --ept parameter on the command line.
                        if vmcs.IS_NESTED:
                            if (self.plugin_args.image_is_guest or
                                    self.physical_address_space.metadata(
                                        "ept")):
                                vm.add_vmcs(
                                    vmcs,
                                    validate=not self.plugin_args.no_validate)
                            else:
                                vm.add_vmcs(vmcs, validate=False)
                        else:
                            vm.add_vmcs(
                                vmcs,
                                validate=not self.plugin_args.no_validate)

                        if vm.is_valid_vmcs(vmcs):
                            if self.plugin_args.quick:
                                break
                    except UnrelatedVmcsError:
                        # This may happen when we analyze live memory. When
                        # the HOST_RIP/EPT that we grouped with has changed
                        # between finding it and adding it to a vm, add_vmcs
                        # may raise an UnrelatedVmcsError.
                        # Not much we can do other than skipping this VMCS.
                        continue

                # Discard empty VMs, which can happen if we skipped vmcss.
                if not vm.vmcss:
                    continue

                # We need to split nested and host VMs here. However, we
                # cannot use the is_nested method of VirtualMachine, because the
                # potentially nested VMs aren't technically nested yet
                # (i.e: don't have a parent). So we resort to checking if
                # all the VMCSs are of nested-type.
                may_be_nested = all([v.IS_NESTED for v in vm.vmcss])
                if may_be_nested and not vm.is_valid:
                    # Only add as nested VMs ones that haven't been validated
                    # yet. This covers the case there image_is_guest is True
                    # and they were validated as hosts.
                    nested_vms.append(vm)
                else:
                    host_vms.append(vm)

        if self.plugin_args.no_nested:
            return host_vms

        # == NESTED VM validation
        # Only 1 level of nesting supported at the moment.
        #
        # TODO: Detect turtles-type VMCSs and relate them to the proper VM.
        # https://www.usenix.org/event/osdi10/tech/full_papers/Ben-Yehuda.pdf
        #
        # These should show up as another valid VM.
        if not self.plugin_args.no_validate:
            candidate_hosts = [vm for vm in host_vms if vm.is_valid]
        else:
            candidate_hosts = []

        # This step validates nested VMs. We try all candidate nested vms
        # against all candidate hosts.
        for candidate_host_vm in candidate_hosts:
            candidate_host_vm.add_nested_vms(
                nested_vms, validate_all=not self.plugin_args.quick)

        # Add all remaining VMs that we weren't able to guess the hierarchy of
        # to the output vm list.
        host_vms.extend(nested_vms)
        return host_vms


    def render(self, renderer=None):
        renderer.table_header([
            dict(name="Description", type="TreeNode", max_depth=5, child=dict(
                type="VirtualizationNode", style="light",
                quick=self.plugin_args.quick)),
            ("Type", "type", ">20s"),
            ("Valid", "valid", ">8s"),
            ("EPT", "ept", "s")
            ])

        virtual_machines = self.get_vms()

        # At this point the hierarchy has been discovered.
        for vm in virtual_machines:
            # Skip invalid VMs.
            if not self.plugin_args.show_all and not vm.is_valid:
                continue
            self.render_vm(renderer, vm, indent_level=0)

        if self.plugin_args.verbosity > 2:
            for vm in virtual_machines:
                for vmcs in vm.vmcss:
                    if (not self.plugin_args.show_all and
                        not vm.is_valid_vmcs(vmcs)):
                        continue
                    renderer.section("VMCS @ %#x" % vmcs.obj_offset)
                    renderer.table_header([("Details", "details", "s")])
                    self.session.plugins.p(vmcs).render(renderer)

                for nested_vm in vm.virtual_machines:
                    for vmcs in nested_vm.vmcss:
                        if (not self.plugin_args.show_all and
                            not vm.is_valid_vmcs(vmcs)):
                            continue
                        renderer.section("VMCS @ %#x" % vmcs.obj_offset)
                        renderer.table_header([("Details", "details", "s")])
                        self.session.plugins.p(vmcs).render(renderer)

    def render_vm(self, renderer, vm, indent_level=0):
        vm_ept = ','.join(["0x%X" % e for e in vm.ept_list])
        renderer.table_row(vm, 'VM', vm.is_valid, vm_ept, depth=indent_level)

        if vm.is_valid and isinstance(
                self.session, session_module.InteractiveSession):
            self.session.session_list.append(vm.GetSession())

        if self.plugin_args.verbosity > 1:
            for vmcs in sorted(vm.vmcss,
                               key=lambda x: x.m("VPID")):
                if not self.plugin_args.show_all and not vm.is_valid_vmcs(vmcs):
                    continue

                valid = vm.is_valid_vmcs(vmcs)
                renderer.table_row(
                    vmcs,
                    vmcs.obj_name, valid, '', depth=indent_level+1)

        for nested_vm in vm.virtual_machines:
            if not self.plugin_args.show_all and not nested_vm.is_valid:
                continue
            self.render_vm(renderer, nested_vm, indent_level=indent_level+1)
