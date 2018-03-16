libvmi = None
try:
    import libvmi
    from libvmi import Libvmi
except ImportError:
    pass
from rekall import addrspace

URL_PREFIX = 'vmi://'

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
        self.as_assert(url.startswith(URL_PREFIX),
                       "The domain must be passed with the URL prefix {}".format(URL_PREFIX))
        domain = url[len(URL_PREFIX):]
        self.as_assert(domain, "domain name missing after {}".format(URL_PREFIX))

        super(VMIAddressSpace, self).__init__(base=base, session=session, **kwargs)
        self.vmi = Libvmi(domain, partial=True)
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
