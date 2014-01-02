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

import logging

from rekall.plugins.windows import common


class KPCR(common.AbstractWindowsCommandPlugin):
    """A plugin to print all KPCR blocks."""
    __name = "kpcr"

    @classmethod
    def is_active(cls, session):
        # Only active for windows 7 right now.
        return (super(KPCR, cls).is_active(session) and
                session.profile.metadata("major") >= 6)

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(KPCR, cls).args(parser)
        parser.add_argument("--eprocess",
                            help="An _EPROCESS virtual address to start "
                            "scanning with.")

    def __init__(self, eprocess=None, **kwargs):
        """Print all KPCR Objects.

        Args:
          eprocess: an _EPROCESS virtual address to use to enumerate threads.
        """
        super(KPCR, self).__init__(**kwargs)
        self.eprocess = eprocess

    def find_kpcr(self, task):
        """Given an _EPROCESS object, find KPCR."""
        # This is the offset of the WaitListHead from the start of the _KPCR
        # struct.
        offset = self.profile._KPCR(vm=None).Prcb.WaitListHead.obj_offset

        seen_threads = set()
        seen = {}

        # Iterate over all the threads of this process.
        for kthread in task.Pcb.ThreadListHead.list_of_type(
            "_KTHREAD", "ThreadListEntry"):

            # Skip threads we already examined.
            if kthread.obj_offset in seen_threads:
                break

            seen_threads.add(kthread.obj_offset)

            # Look for threads in the Wait state. If this thread is in the Wait
            # state, the WaitListEntry will belong to the list of all waiting
            # threads. By following this list we should get to the list head
            # which lives inside the _KPCR object.
            for kwaiter in kthread.WaitListEntry.list_of_type(
                "_KTHREAD", "WaitListEntry"):

                self.session.report_progress()

                if kwaiter.obj_offset in seen_threads:
                    break

                seen_threads.add(kwaiter.obj_offset)

                # Assume the kwaiter is actually the KPRCB.WaitListHead.
                possible_kpcr = self.profile._KPCR(
                    kwaiter.WaitListEntry.obj_offset - offset)

                # Check for validity using the usual condition.
                if possible_kpcr.Self == possible_kpcr.obj_offset:
                    if possible_kpcr.obj_offset not in seen:
                        seen[possible_kpcr.obj_offset] = possible_kpcr


        # Return all the _KPCR structs we know about.
        return seen.values()

    def render(self, renderer):
        eprocess = self.eprocess

        if self.session.system_eprocess:
            # Convert the eprocess to the virtual address space by reflecting
            # through the ActiveProcessLinks.
            eprocess = self.session.system_eprocess.ActiveProcessLinks.reflect(
                vm=self.session.kernel_address_space).dereference_as(
                "_EPROCESS", "ActiveProcessLinks")

        if not eprocess:
            for task in self.session.plugins.pslist().list_eprocess():
                eprocess = task
                break

        if not eprocess:
            logging.error("Require at least one _EPROCESS to use.")
            return

        for kpcr in self.find_kpcr(eprocess):
            renderer.section()

            renderer.table_header([("Property", "property", "<30"),
                                   ("Value", "value", "<")])

            renderer.table_row("Offset (V)", hex(kpcr.obj_offset))
            renderer.table_row(
                "Offset (P)", hex(self.session.kernel_address_space.vtop(
                        kpcr.obj_offset)))

            renderer.table_row("KdVersionBlock", kpcr.KdVersionBlock)

            renderer.table_row("IDT", hex(kpcr._IDT))
            renderer.table_row("GDT", hex(kpcr._GDT))

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
