# Fix bugs in dependent libraries.

# Fix bug in pyelftools.
from elftools.elf import elffile

# pyelftools does not officially support ARM but this seems to work anyway.
class ELFFile(elffile.ELFFile):
    def get_machine_arch(self):
        result = super(ELFFile, self).get_machine_arch()
        if result == "ARM":
            result = "MIPS"

        return result

elffile.ELFFile = ELFFile

# Switch off parso's annoying logging messages.
try:
    from parso.python import diff
    diff.logging.debug = lambda *args: None
except: pass


## The following are needed to get Pyinstaller to include these files.

if 0:
    from  parsedatetime.pdt_locales import (
        de_DE, en_AU, en_US,
        es, nl_NL, pt_BR,
        ru_RU, fr_FR)

    from Crypto.Cipher import (
        _raw_ecb,
        _raw_cbc,
        _raw_cfb,
        _raw_ofb,
        _raw_ctr,
        _Salsa20,
        _raw_ocb,
        _raw_des,
        _raw_arc2,
        _raw_des3,
        _raw_aes,
        _ARC4)

    from Crypto.Hash import (
        _SHA256, _BLAKE2s)
    from Crypto.Util import (
        _strxor, _galois, _cpuid)


    from Crypto.Protocol import _scrypt
