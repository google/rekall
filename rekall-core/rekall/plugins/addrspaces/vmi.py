from urllib.parse import urlparse, parse_qs
from distutils.util import strtobool
from rekall import addrspace

libvmi = None
try:
    import libvmi
    from libvmi import Libvmi, VMIMode
except ImportError:
    pass

SCHEME = 'vmi'


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
                       "session.SetParameter('filename', 'vmi:///domain').")
        vmi_url = urlparse(url)
        self.as_assert(vmi_url.scheme == SCHEME, "URL scheme must be vmi://")
        self.as_assert(vmi_url.path, "No domain name specified")
        domain = vmi_url.path[1:]
        # hypervisor specified ?
        self.mode = None
        hypervisor = vmi_url.netloc
        if hypervisor:
            self.mode = VMIMode[hypervisor.upper()]
        # query parameters ?
        self.volatile = True
        if vmi_url.query:
            params = parse_qs(vmi_url.query, strict_parsing=True)
            try:
                self.volatile = strtobool((params['volatile'][0]))
            except KeyError:
                raise RuntimeError('Invalid query parameters in vmi:// URI')
        # build Libvmi instance
        super(VMIAddressSpace, self).__init__(base=base, session=session,
                                              **kwargs)
        self.vmi = Libvmi(domain, mode=self.mode, partial=True)
        self.min_addr = 0
        self.max_addr = self.vmi.get_memsize() - 1
        # pause in case volatile has been disabled
        if not self.volatile:
            self.vmi.pause_vm()
        # register flush hook to destroy vmi instance when session.Flush() is called
        session.register_flush_hook(self, self.close)

    def close(self):
        if not self.volatile:
            self.vmi.resume_vm()
        self.vmi.destroy()

    def read(self, addr, size):
        buffer, _ = self.vmi.read_pa(addr, size, padding=True)
        return buffer

    def write(self, addr, data):
        bytes_written = self.vmi.write_pa(addr, data)
        if bytes_written != len(data):
            return False
        return True

    def is_valid_address(self, addr):
        if addr is None:
            return False
        return self.min_addr <= addr <= self.max_addr

    def get_available_addresses(self):
        yield (self.min_addr, self.max_addr)

    def get_mappings(self, start=0, end=2 ** 64):
        yield addrspace.Run(start=self.min_addr, end=self.max_addr,
                            file_offset=0, address_space=self)
