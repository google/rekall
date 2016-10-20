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
from rekall import scan
from rekall import utils
from rekall.plugins.darwin import common


class DarwinFindSysent(common.AbstractDarwinParameterHook):
    """Find sysent by scanning around nsysent.

    The production kernel no longer ships with the 'sysent' symbol,
    which is the address of the syscall switch table. However, because
    sysent and nsysent are initialized around the same time it works out that
    they are always near each other.

    This is an old technique, documented around the internet, for example here:
    https://reverse.put.as/2010/11/27/a-semi-automated-way-to-find-sysent/
    """

    name = "sysent_scan"

    # Start looking 2560 pages below nsysent.
    SYSENT_REL_OFFSET = -0x1000 * 0x1000

    # Scan at most 2560 pages below and above.
    LIMIT = 0x2000 * 0x1000

    def scan(self, start, limit):
        scanner = scan.FastStructScanner(
            session=self.session,
            profile=self.session.profile,
            type_name="sysent",
            expected_values=[
                {"sy_arg_bytes": 0, "sy_narg": 0},
                {"sy_arg_bytes": 4, "sy_narg": 1},
                {"sy_arg_bytes": 0, "sy_narg": 0},
                {"sy_arg_bytes": 12, "sy_narg": 3}],
            address_space=self.session.default_address_space)

        for hit in scanner.scan(offset=start, maxlen=limit):
            return hit

    def calculate(self):
        nsysent_off = self.session.profile.get_constant(
            "_nsysent", is_address=True)

        if not nsysent_off:
            return

        return self.scan(start=nsysent_off + self.SYSENT_REL_OFFSET,
                         limit=self.LIMIT)


class DarwinCheckSysCalls(common.AbstractDarwinCommand):
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
        resolver = self.session.address_resolver
        for entry in sysenter:
            call = entry.sy_call.deref()
            yield entry, call, resolver.format_address(call)

    def render(self, renderer):
        renderer.table_header(
            [("Index", "index", "6"),
             ("Address", "address", "[addrpad]"),
             ("Target", "target", "[addrpad]"),
             ("Symbol", "symbol", "")])

        for i, (entry, call, symbol) in enumerate(self.CheckSyscallTables()):
            renderer.table_row(i, entry, call, symbol)


class OIDInfo(object):
    def __init__(self, oidp, names=None, numbers=None):
        self.oidp = oidp
        self._names = names or []
        self._numbers = numbers or []
        self.handler = None

    def __iter__(self):
        oidp = self.oidp
        while oidp:
            if oidp.oid_name:
                yield OIDInfo(oidp, self._names, self._numbers)

            oidp = oidp.oid_link.sle_next

    @utils.safe_property
    def perms(self):
        return (("R" if self.oidp.oid_perms.CTLFLAG_RD else "-") +
                ("W" if self.oidp.oid_perms.CTLFLAG_WR else "-") +
                ("L" if self.oidp.oid_perms.CTLFLAG_LOCKED else "-"))

    @utils.safe_property
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

    @utils.safe_property
    def name(self):
        names = self._names[:]
        names.append(self.oidp.oid_name.deref())
        return ".".join(["%s" % x for x in names])

    @utils.safe_property
    def number(self):
        numbers = self._numbers[:]
        numbers.append(self.oidp.oid_number)
        return ".".join(["%s" % x for x in numbers])


class DarwinSysctl(common.AbstractDarwinCommand):
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

    table_header = [
        dict(name="name", width=45),
        dict(name="mib", width=16),
        dict(name="perms", width=6),
        dict(name="handler", style="address"),
        dict(name="symbol", width=40),
        dict(name="value")
    ]

    def column_types(self):
        return dict(name="",
                    mib="101.101.104",
                    perms="RWL",
                    handler=self.session.profile.Pointer(),
                    symbol=utils.FormattedAddress(
                        self.session.address_resolver, 0),
                    value="")

    def collect(self):
        for oid in self.CheckSysctl():
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

            yield (oid.name,
                   oid.number,
                   oid.perms,
                   oid.oidp.oid_handler,
                   utils.FormattedAddress(
                       self.session.address_resolver,
                       oid.oidp.oid_handler),
                   value)


class CheckTrapTable(common.AbstractDarwinCommand):
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

        resolver = self.session.address_resolver
        for i, entry in enumerate(table):
            call = entry.mach_trap_function.deref()
            yield i, entry, call, resolver.format_address(call)

    def render(self, renderer):
        renderer.table_header([
            ("Index", "index", "[addr]"),
            ("Address", "address", "[addrpad]"),
            ("Target", "target", "[addrpad]"),
            ("Symbol", "symbol", "")])

        for i, entry, call, sym_name in self.CheckTrapTables():
            if call == None:
                continue

            renderer.table_row(i, entry, call, sym_name or "Unknown",
                               highlight=None if sym_name else "important")
