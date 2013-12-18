# Rekall Memory Forensics
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright 2013 Google Inc. All Rights Reserved.
#
# This file is part of Rekall Memory Forensics.
#
# Rekall Memory Forensics is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# Rekall Memory Forensics is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Rekall Memory Forensics.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization:
"""

from rekall.plugins.linux import common


class CheckSyscall(common.LinuxPlugin):
    """Checks if the system call table has been altered."""

    __name = "check_syscall"

    def Find_sys_call_table_size(self):
        """Calculates the size of the syscall table.

        Here we need the symbol __NR_syscall_max. We derive it from
        disassembling the following system calls:

        - system_call_fastpath function:

        http://lxr.linux.no/linux+v3.12/arch/x86/kernel/entry_64.S#L620
        system_call_fastpath:
        #if __SYSCALL_MASK == ~0
                cmpq $__NR_syscall_max,%rax
        #else
                andl $__SYSCALL_MASK,%eax
                cmpl $__NR_syscall_max,%eax
        #endif

        - ret_from_sys_call function (with a small reiwnd):
        http://lxr.linux.no/linux+v2.6.26/arch/x86/kernel/entry_64.S#L249

        249        cmpq $__NR_syscall_max,%rax
        250        ja badsys
        251        movq %r10,%rcx
        252        call *sys_call_table(,%rax,8)  # XXX:    rip relative
        253        movq %rax,RAX-ARGOFFSET(%rsp)
        254 /*
        255  * Syscall return path ending with SYSRET (fast path)
        256  * Has incomplete stack frame and undefined top of stack.
        257  */
        258 ret_from_sys_call:
        259        movl $_TIF_ALLWORK_MASK,%edi
        260        /* edi: flagmask */
        """
        for func_name, rewind in [("system_call_fastpath", 0),
                                   ("ret_from_sys_call", 40)]:
            func = self.profile.get_constant_object(
                func_name, target="Function").Rewind(rewind)

            # Only look in the first 2 instructions for something like
            # CMP EAX, $123.
            for instruction in func.Decompose(10):
                if instruction.mnemonic == "CMP":
                    return 1 + (instruction.operands[1].value & 0xffffffff)

        # Fallback. Note this underestimates the size quite a bit.
        return len(filter(lambda x: x.startswith("__syscall_meta__"),
                          self.profile.constants)) or 0x300

    def Find_ia32_sys_call_table_size(self):
        """Calculates the size of the ia32 syscall table.

        Here we are after the symbol IA32_NR_syscalls. We use the exported
        sysenter_do_call and rewind back a few instruction to locate the
        comparison.

        http://lxr.linux.no/linux+v2.6.24/arch/x86/ia32/ia32entry.S#L131
        jnz  sysenter_tracesys
                cmpq    $(IA32_NR_syscalls-1),%rax
                ja      ia32_badsys
        sysenter_do_call:
                cmpl    $(IA32_NR_syscalls-1),%eax
                ja      ia32_badsys
        """
        # Rewind approximately 20 bytes (a few instructions back).
        func = self.profile.get_constant_object(
            "sysenter_do_call", target="Function").Rewind(20)

        for instruction in func.Decompose(10):
            if instruction.mnemonic == "CMP":
                return (instruction.operands[1].value & 0xffffffff) + 1

        import pdb; pdb.set_trace()

        # Fallback. Note this underestimates the size quite a bit.
        return len(filter(lambda x: x.startswith("__syscall_meta__"),
                          self.profile.constants)) or 0x300

    def CheckSyscallTables(self):
        """
        This works by walking the system call table
        and verifies that each is a symbol in the kernel
        """
        lsmod = self.session.plugins.lsmod(session=self.session)

        for table_name, size_finder in [
                ("ia32_sys_call_table", self.Find_ia32_sys_call_table_size),
                ("sys_call_table", self.Find_sys_call_table_size)]:

            # The syscall table is simply an array of pointers to functions.
            table = self.profile.get_constant_object(
                table_name,
                target="Array",
                target_args=dict(
                    count=size_finder(),
                    target="Pointer",
                    target_args=dict(
                        target="Function"
                        )
                    )
                )

            for i, entry in enumerate(table):
                yield table_name, i, entry, lsmod.ResolveSymbolName(entry.deref())

    def render(self, renderer):
        renderer.table_header([
                ("Table Name", "table", "6"),
                ("Index", "index", "[addr]"),
                ("Address", "address", "[addrpad]"),
                ("Symbol", "symbol", "<30")])

        for table_name, i, call_addr, sym_name in self.CheckSyscallTables():
            renderer.table_row(table_name, i, call_addr, sym_name or "Unknown",
                               highlight=None if sym_name else "important")
