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
