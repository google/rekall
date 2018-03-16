libvmi = None
try:
    import libvmi
    from libvmi import Libvmi, VMIMode
except ImportError:
    pass
import re
from rekall import addrspace

URL_PREFIX = 'vmi://'

# URL must be like the following:
#   vmi://<domain>
# examples:
#   vmi://windows_7_x64
#   vmi://debian_stretch
# if you wish to specify the hypervisor:
#   vmi://(xen|kvm)/<domain>
# exmaples:
#   vmi://xen/windows_10
#   vmi://kvm/winxp
class VMIAddressSpace(addrspace.BaseAddressSpace):
    """An address space which operates on top of Libvmi's interface."""

    __abstract = False
    __name = "vmi"
    order = 90
    volatile = True
    __image = True

    def __init__(self, base=None, filename=None, session=None, **kwargs):
        self.as_assert(libvmi, "The LibVMI python bindings must be installed")
        self.as_assert(base is None, "must be first Address Space")
        self.session = session

        url = filename or (session and session.GetParameter("filename"))
        self.as_assert(url, "Filename must be specified in session (e.g. "
                       "session.SetParameter('filename', 'vmi://domain').")
        pattern = '{}((?P<hypervisor>xen|kvm)/)?(?P<domain>.*)'.format(URL_PREFIX)
        m = re.match(pattern, url)
        self.as_assert(m,
                "VMI URL format: {}(xen|kvm)?<domain>".format(URL_PREFIX))
        domain = m.group('domain')
        hypervisor = m.group('hypervisor')
        self.as_assert(domain, "no domain name specified")
        self.mode = None
        if hypervisor:
            self.mode = VMIMode[hypervisor.upper()]

        super(VMIAddressSpace, self).__init__(base=base, session=session, **kwargs)
        self.vmi = Libvmi(domain, mode=self.mode, partial=True)
        self.min_addr = 0
        self.max_addr = self.vmi.get_memsize() - 1

    def close(self):
        self.vmi.destroy()

    def read(self, addr, size):
        buffer, bytes_read = self.vmi.read_pa(addr, size)
        if bytes_read != size:
            raise RuntimeError('Error while reading physical memory at {}'.format(hex(addr)))
        return buffer

    def write(self, addr, data):
        bytes_written = self.vmi.write_pa(addr, data)
        if bytes_written != len(data):
            return False
        return True

    def is_valid_address(self, addr):
        if addr is None:
            return False
        return self.min_addr < addr < self.max_addr

    def get_available_addresses(self):
        yield (self.min_addr, self.max_addr)

    def get_mappings(self, start=0, end=2 ** 64):
        yield addrspace.Run(start=self.min_addr, end=self.max_addr, file_offset=0, address_space=self)
