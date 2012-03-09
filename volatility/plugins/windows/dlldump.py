# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
#
# Additional Authors:
# Michael Cohen <scudette@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

import os
import re
from volatility.plugins.windows import procdump
from volatility import utils


class DLLDump(procdump.ProcExeDump):
    """Dump DLLs from a process address space"""

    __name = "dlldump"

    def __init__(self, regex=None, base=None, **kwargs):
        """Dump a dll linked into a process.

        Args:
          regex: A regular expression to match the dlls to dump.
          base: Dump DLLS at the specified BASE offset in the process address
             space.
        """
        super(DLLDump, self).__init__(**kwargs)
        self.regex = regex
        self.base = base

    def get_module(self, regex=None):
        """Search the modules of the filtered processes.

        Args:
          regex: A regular expression to match the dlls to dump.
        """
        # If not specified match all dlls.
        mod_re = re.compile(self.regex or regex or ".*")
        for proc in self.filter_processes():
            ps_ad = proc.get_process_address_space()
            if ps_ad == None:
                continue

            mods = dict((mod.DllBase.v(), mod) for mod in proc.get_load_modules())
            if self.base:
                if mods.has_key(self.base):
                    mod_name = mods[self.base].BaseDllName
                else:
                    mod_name = "Unknown"
                yield proc, ps_ad, int(self.base), mod_name
            else:
                for mod in mods.values():
                    if mod_re.search(utils.SmartStr(mod.FullDllName)) or mod_re.search(
                        utils.SmartStr(mod.BaseDllName)):
                        yield proc, ps_ad, mod.DllBase.v(), mod.BaseDllName

    def render(self, outfd):
        self._check_dump_dir()

        for proc, ps_ad, mod_base, mod_name in self.get_module():
            if ps_ad.is_valid_address(mod_base):
                process_offset = ps_ad.vtop(proc.obj_offset)
                dump_file = "module.{0}.{1:x}.{2:x}.dll".format(
                    proc.UniqueProcessId, process_offset, mod_base)

                outfd.write("Dumping {0}, Process: {1}, Base: {2:8x} output: {3}\n".format(
                        mod_name, proc.ImageFileName, mod_base, dump_file))

                of = open(os.path.join(self.dump_dir, dump_file), 'wb')
                try:
                    for chunk in self.get_image(ps_ad, mod_base):
                        offset, code = chunk
                        of.seek(offset)
                        of.write(code)
                except ValueError, ve:
                    outfd.write("Unable to dump executable; sanity check failed:\n")
                    outfd.write("  " + str(ve) + "\n")
                    outfd.write("You can use -u to disable this check.\n")
                of.close()
            else:
                outfd.write("Cannot dump {0}@{1} at {2:8x}\n".format(
                        proc.ImageFileName, mod_name, mod_base))
