""" This Address Space allows us to open ewf files """

#pylint: disable-msg=C0111

import ctypes

from ctypes import util
from volatility.plugins.addrspaces import standard


possible_names = ['libewf-1', 'ewf', ]
for name in possible_names:
    resolved = util.find_library(name)
    if resolved:
        break

if resolved:
    libewf = ctypes.CDLL(resolved)

if not resolved or not libewf._name:
    raise ImportError("EWFlib not available.")

class ewffile(object):
    """ A file like object to provide access to the ewf file """
    def __init__(self, volumes):
        if isinstance(volumes, str):
            volumes = [volumes, ]

        volume_array = ctypes.c_char_p * len(volumes)
        self.handle = libewf.libewf_open(volume_array(*volumes),
                                         ctypes.c_int(len(volumes)),
                                         ctypes.c_int(1))
        if self.handle == 0:
            raise RuntimeError("Unable to open ewf file")

        self.readptr = 0
        size_p = ctypes.pointer(ctypes.c_ulonglong(0))
        libewf.libewf_get_media_size(self.handle, size_p)
        self.size = size_p.contents.value

    def seek(self, offset, whence = 0):
        if whence == 0:
            self.readptr = offset
        elif whence == 1:
            self.readptr += offset
        elif whence == 2:
            self.readptr = self.size + offset

        self.readptr = min(self.readptr, self.size)

    def tell(self):
        return self.readptr

    def read(self, length):
        buf = ctypes.create_string_buffer(length)
        length = libewf.libewf_read_random(self.handle, buf,
                                           ctypes.c_ulong(length),
                                           ctypes.c_ulonglong(self.readptr))

        return buf.raw[:length]

    def close(self):
        libewf.libewf_close(self.handle)

    def get_headers(self):
        properties = ["case_number", "description", "examinier_name",
                      "evidence_number", "notes", "acquiry_date",
                      "system_date", "acquiry_operating_system",
                      "acquiry_software_version", "password",
                      "compression_type", "model", "serial_number", ]

        ## Make sure we parsed all headers
        libewf.libewf_parse_header_values(self.handle, ctypes.c_int(4))
        result = {'size': self.size}
        buf = ctypes.create_string_buffer(1024)
        for p in properties:
            libewf.libewf_get_header_value(self.handle, p, buf, 1024)
            result[p] = buf.value

        ## Get the hash
        if libewf.libewf_get_md5_hash(self.handle, buf, 16) == 1:
            result['md5'] = buf.raw[:16]

        return result


def ewf_open(volumes):
    return ewffile(volumes)


class EWFAddressSpace(standard.FDAddressSpace):
    """ An EWF capable address space.

    In order for us to work we need:
    1) There must be a base AS.
    2) The first 6 bytes must be 45 56 46 09 0D 0A (EVF header)
    """
    order = 20
    _md_image = True

    def __init__(self, base=None, filename=None, session=None, **kwargs):
        self.as_assert(base!=None, "No base address space provided")

        self.as_assert(base.read(0, 6)=="\x45\x56\x46\x09\x0D\x0A",
                       "EWF signature not present")

        path = session.filename or filename
        fhandle = ewf_open([path])

        super(EWFAddressSpace, self).__init__(
            fhandle=fhandle, session=session, base=base, **kwargs)
