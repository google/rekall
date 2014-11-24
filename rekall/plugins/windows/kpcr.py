# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
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

"""This plugin is used for displaying information about the Kernel Processor
Control Blocks.
"""

# pylint: disable=protected-access
from rekall import obj
from rekall.plugins.windows import common


class KPCR(common.WindowsCommandPlugin):
    """A plugin to print all KPCR blocks."""
    __name = "kpcr"

    def kpcr(self):
        """A generator of KPCR objects (one for each CPU)."""
        # On windows 7 the KPCR is just stored in a symbol.
        initial_pcr = self.profile.get_constant_object(
            "KiInitialPCR",
            "_KPCR")

        # Validate the PCR through the self member.
        self_Pcr = initial_pcr.m("SelfPcr") or initial_pcr.m("Self")
        if self_Pcr.v() == initial_pcr.obj_offset:
            return initial_pcr

        # On windows XP the KPCR is hardcoded to 0xFFDFF000
        pcr = self.profile._KPCR(0xFFDFF000)
        if pcr.SelfPcr.v() == pcr.obj_offset:
            return pcr

        return obj.NoneObject("Unknown KPCR")

    def render(self, renderer):
        kpcr = self.kpcr()

        renderer.section()

        renderer.table_header([("Property", "property", "<30"),
                               ("Value", "value", "<")])

        renderer.table_row("Offset (V)", "%#x" % kpcr.obj_offset)
        renderer.table_row("KdVersionBlock", kpcr.KdVersionBlock, style="full")

        renderer.table_row("IDT", "%#x" % kpcr.IDT)
        renderer.table_row("GDT", "%#x" % kpcr.GDT)

        current_thread = kpcr.ProcessorBlock.CurrentThread
        idle_thread = kpcr.ProcessorBlock.IdleThread
        next_thread = kpcr.ProcessorBlock.NextThread

        if current_thread:
            renderer.format("{0:<30}: {1:#x} TID {2} ({3}:{4})\n",
                            "CurrentThread",
                            current_thread, current_thread.Cid.UniqueThread,
                            current_thread.owning_process().ImageFileName,
                            current_thread.Cid.UniqueProcess,
                           )

        if idle_thread:
            renderer.format("{0:<30}: {1:#x} TID {2} ({3}:{4})\n",
                            "IdleThread",
                            idle_thread, idle_thread.Cid.UniqueThread,
                            idle_thread.owning_process().ImageFileName,
                            idle_thread.Cid.UniqueProcess,
                           )

        if next_thread:
            renderer.format("{0:<30}: {1:#x} TID {2} ({3}:{4})\n",
                            "NextThread",
                            next_thread,
                            next_thread.Cid.UniqueThread,
                            next_thread.owning_process().ImageFileName,
                            next_thread.Cid.UniqueProcess,
                           )

        renderer.format("{0:<30}: CPU {1} ({2} @ {3} MHz)\n",
                        "Details",
                        kpcr.ProcessorBlock.Number,
                        kpcr.ProcessorBlock.VendorString,
                        kpcr.ProcessorBlock.MHz)

        renderer.format(
            "{0:<30}: {1:#x}\n", "CR3/DTB",
            kpcr.ProcessorBlock.ProcessorState.SpecialRegisters.Cr3)
