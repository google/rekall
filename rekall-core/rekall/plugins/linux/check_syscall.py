# Rekall Memory Forensics
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright 2013 Google Inc. All Rights Reserved.
#
# This file is part of Rekall Memory Forensics.
#
# Rekall Memory Forensics is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General Public
# License.
#
# Rekall Memory Forensics is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# Rekall Memory Forensics.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization:
"""

from rekall.plugins.linux import common
from rekall.plugins.tools import dynamic_profiles


class CheckSyscall(common.LinuxPlugin):
    """Checks if the system call table has been altered."""

    __name = "check_syscall"

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="table", hidden=True),
        dict(name="index", style="address"),
        dict(name="address", style="address"),
        dict(name="symbol", width=80)
    ]


    def Find_sys_call_tables(self):
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

        - ret_from_sys_call function (with a small rewind):
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


        - sysenter_do_call
           Linux> dis "linux!sysenter_do_call"
           Address    Rel           Op Codes           Instruction    Comment
           ------- ---------- -------------------- ------------------ -------
           ------ linux!sysenter_do_call ------: 0xc12c834d
           0xc12c834d        0x0 3d5d010000           CMP EAX, 0x15d
           0xc12c8352        0x5 0f8397baffff         JAE 0xc12c3def  linux!syscall_badsys

        """
        rules = [
            # Look for a comparison of the register (EAX) with a fixed value.
            {'mnemonic': 'CMP', 'operands': [
                {'type': 'REG'}, {'type': 'IMM', 'target': "$value"}]},

            # Immediately followed by a branch to linux!badsys,
            # linux!ia32_badsys etc.
            {'comment': '~.+badsys'}
        ]
        func = None
        tables = set()
        for func_name, table_name in [
                # http://lxr.free-electrons.com/source/arch/x86_64/kernel/entry.S?v=2.4.37
                ("system_call", "sys_call_table"),
                # http://lxr.free-electrons.com/source/arch/x86/kernel/entry_64.S?v=3.16
                ("system_call_fastpath", "sys_call_table"),


                # http://lxr.free-electrons.com/source/arch/x86/ia32/ia32entry.S?v=3.14
                ("ia32_sysenter_target", "ia32_sys_call_table"),
                ("sysenter_auditsys", "ia32_sys_call_table"),

                # http://lxr.free-electrons.com/source/arch/x86/kernel/entry_32.S?v=3.3
                ("sysenter_do_call", "sys_call_table")]:

            if table_name in tables:
                continue

            # This table does not exist in this profile dont bother looking for
            # its size.
            if self.profile.get_constant(table_name) == None:
                continue

            func = self.profile.get_constant_object(
                func_name, target="Function")
            if func == None:
                continue

            matcher = dynamic_profiles.DisassembleMatcher(
                name="sys_call_table_size",
                mode=func.mode, rules=rules, session=self.session)

            result = matcher.MatchFunction(func)
            if result:
                tables.add(table_name)
                yield table_name, result["$value"] + 1

        # Fallback. Note this underestimates the size quite a bit.
        if func == None:
            table_size = len([x for x in self.profile.constants
                              if x.startswith("__syscall_meta__")]) or 0x300
            yield "ia32_sys_call_table", table_size
            yield "sys_call_table", table_size

    def collect(self):
        """
        This works by walking the system call table
        and verifies that each is a symbol in the kernel
        """
        for table_name, table_size in  self.Find_sys_call_tables():
            # The syscall table is simply an array of pointers to functions.
            table = self.profile.get_constant_object(
                table_name,
                target="Array",
                target_args=dict(
                    count=table_size,
                    target="Pointer",
                    target_args=dict(
                        target="Function"
                        )
                    )
                )

            yield dict(divider="Table %s" % table_name)

            resolver = self.session.address_resolver
            for i, entry in enumerate(table):
                sym_name = resolver.format_address(entry.deref())[:2]
                yield dict(
                    table=table_name, index=i,
                    address=entry,
                    symbol=sym_name or "Unknown",
                    highlight=None if sym_name else "important")
