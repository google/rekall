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
