# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
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
"""Plugins for checking internal consistancy of pointers."""

__author__ = "Michael Cohen <scudette@google.com>"


from rekall import obj
from rekall.plugins.darwin import common


class DarwinCheckSysCalls(common.DarwinPlugin):
    """Checks the syscall table."""

    __name = "check_syscalls"

    def CheckSyscallTables(self):
        sysenter = self.profile.get_constant_object(
            "_sysent",
            target="Array",
            target_args=dict(
                count=self.profile.get_constant_object(
                    "_nsysent", "unsigned int"),
                target="sysent"
                )
            )

        # Resolve which kernel module or symbol the entry point is to.
        lsmod = self.session.plugins.lsmod(session=self.session)
        for entry in sysenter:
            call = entry.sy_call.deref()
            yield entry, call, lsmod.ResolveSymbolName(call)

    def render(self, renderer):
        renderer.table_header(
            [("Index", "index", "6"),
             ("Address", "address", "[addrpad]"),
             ("Target", "target", "[addrpad]"),
             ("Symbol", "symbol", "<30")])

        for i, (entry, call, symbol) in enumerate(self.CheckSyscallTables()):
            renderer.table_row(i, entry, call, symbol)


class OIDInfo(object):
    def __init__(self, oidp, names=[], numbers=[]):
        self.oidp = oidp
        self._names = names
        self._numbers = numbers
        self.handler = None

    def __iter__(self):
        oidp = self.oidp
        while oidp:
            if oidp.oid_name:
                yield OIDInfo(oidp, self._names, self._numbers)

            oidp = oidp.oid_link.sle_next

    @property
    def perms(self):
        return (("R" if self.oidp.oid_perms.CTLFLAG_RD else "-") +
                ("W" if self.oidp.oid_perms.CTLFLAG_WR else "-") +
                ("L" if self.oidp.oid_perms.CTLFLAG_LOCKED else "-"))

    @property
    def arg(self):
        """Decode the arg according to its type."""
        if self.oidp.oid_kind_type == "CTLTYPE_NODE":
            if self.oidp.oid_handler:
                return "Node"
            else:
                names = self._names[:]
                names.append(self.oidp.oid_name.deref())
                numbers = self._numbers[:]
                numbers.append(self.oidp.oid_number)

                oid = self.oidp.oid_arg1.dereference_as("sysctl_oid_list")
                return OIDInfo(oid.slh_first, names, numbers)

        elif self.oidp.oid_kind_type == "CTLTYPE_INT":
            return self.oidp.oid_arg1.dereference_as("int")

        elif self.oidp.oid_kind_type == "CTLTYPE_STRING":
            return self.oidp.oid_arg1.dereference_as("String")

        elif self.oidp.oid_kind_type == "CTLTYPE_QUAD":
            return self.oidp.oid_arg1.dereference_as("long long int")

        elif self.oidp.oid_kind_type == "CTLTYPE_OPAQUE":
            return self.oidp.oid_arg1.dereference_as("Void")

        return obj.NoneObject("Unknown arg type")

    @property
    def name(self):
        names = self._names[:]
        names.append(self.oidp.oid_name.deref())
        return ".".join(["%s" % x for x in names])

    @property
    def number(self):
        numbers = self._numbers[:]
        numbers.append(self.oidp.oid_number)
        return ".".join(["%s" % x for x in numbers])


class DarwinSysctl(common.DarwinPlugin):
    """Dumps the sysctl database.

    On OSX the kernel is configured through the sysctl mechanism. This is
    analogous to /proc or /sysfs on Linux. The configuration space is broken
    into MIBs - or hierarchical namespace.

    https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man8/sysctl.8.html

    For example:

    net.inet.ip.subnets_are_local
    net.inet.ip.ttl
    net.inet.ip.use_route_genid

    This is implemented via a singly linked list of sysctl_oid structs. The
    structs can be on the following types:

    - CTLTYPE_INT     means this MIB will handle an int.
    - CTLTYPE_STRING  means this MIB will handle a string.
    - CTLTYPE_QUAD    means this MIB will handle a long long int.
    - CTLTYPE_NODE means this is a node which handles a sublevel of MIBs. It is
      actually a pointer to a new sysctl_oid_list which handles the sublevel.

    """

    __name = "sysctl"

    def CheckSysctl(self):
        sysctrl_list = self.profile.get_constant_object(
            "_sysctl__children", "sysctl_oid_list")

        oidinfo = OIDInfo(sysctrl_list.slh_first)
        for oid in self._process(oidinfo):
            yield oid

    def _process(self, oidinfo):
        # Output in sorted order since its eaiser to read.
        for oid in sorted(oidinfo, key=lambda x: x.name):
            if isinstance(oid.arg, OIDInfo):
                for x in self._process(oid.arg):
                    yield x
            else:
                yield oid

    def render(self, renderer):
        renderer.table_header(
            [("Name", "name", "45"),
             ("MIB", "mib", "16"),
             ("Perms", "perms", "6"),
             ("Handler", "handler", "[addrpad]"),
             ("Module", "symbol", "30"),
             ("Value", "value", "")])

        lsmod = self.session.plugins.lsmod(session=self.session)

        for oid in self.CheckSysctl():
            handler = lsmod.ResolveSymbolName(oid.oidp.oid_handler)

            # Format the value nicely.
            value = oid.arg
            if isinstance(value, obj.Pointer):
                value = "@ 0x%X" % int(value)

            elif not value == None:
                try:
                    value = int(value)
                    value = "0x%X (%d)" % (value, value)
                except (ValueError, AttributeError):
                    pass

            renderer.table_row(oid.name,
                               oid.number,
                               oid.perms,
                               oid.oidp.oid_handler,
                               handler,
                               value)


class CheckTrapTable(common.DarwinPlugin):
    """Checks the traps table for hooks."""

    __name = "check_trap_table"


    def __init__(self, **kwargs):
        super(CheckTrapTable, self).__init__(**kwargs)

        # The mach_trap_t struct is not exported in debug symbols, but can be
        # found here xnu-2422.1.72/bsd/dev/dtrace/systrace.c:
        #    typedef struct {
        #        int mach_trap_arg_count;
        #        kern_return_t    (*mach_trap_function)(void *);
        #    #if defined(__x86_64__)
        #        mach_munge_t *mach_trap_arg_munge32;
        #    #endif
        #        int  mach_trap_u32_words;
        #        #if  MACH_ASSERT
        #        const char  *mach_trap_name;
        #    #endif /* MACH_ASSERT */
        #    } mach_trap_t;

        # We only really care about the mach_trap_function here.
        if self.profile.metadata("arch") == "I386":
            offset = 4
        else:
            offset = 8

        self.profile.add_types({
                "mach_trap": [16, {
                        "mach_trap_function": [offset, ["Pointer", dict(
                                    target="Function"
                                    )]]
                        }],
                })

    def CheckTrapTables(self):
        lsmod = self.session.plugins.lsmod(session=self.session)

        # The trap table is simply an array of pointers to functions.
        table = self.profile.get_constant_object(
            "_mach_trap_table",
            target="Array",
            target_args=dict(
                count=self.profile.get_constant_object(
                    "_mach_trap_count", "unsigned int"),
                target="mach_trap",
                )
            )

        for i, entry in enumerate(table):
            call = entry.mach_trap_function.deref()
            yield i, entry, call, lsmod.ResolveSymbolName(call)

    def render(self, renderer):
        renderer.table_header([
                ("Index", "index", "[addr]"),
                ("Address", "address", "[addrpad]"),
                ("Target", "target", "[addrpad]"),
                ("Symbol", "symbol", "<30")])

        for i, entry, call, sym_name in self.CheckTrapTables():
            renderer.table_row(i, entry, call, sym_name or "Unknown",
                               highlight=None if sym_name else "important")
