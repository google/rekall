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

__author__ = (
    "Michael Cohen <scudette@google.com>",
    "Adam Sindelar <adam.sindelar@gmail.com>")

from rekall import obj
from rekall import plugin
from rekall import registry

from rekall.plugins.darwin import common


class DarwinUnpListCollector(common.AbstractDarwinProducer):
    """Walks the global list of sockets in uipc_usrreq."""

    name = "unp_sockets"
    type_name = "socket"

    def collect(self):
        for head_const in ["_unp_dhead", "_unp_shead"]:
            lhead = self.session.profile.get_constant_object(
                head_const,
                target="unp_head")

            for unp in lhead.lh_first.walk_list("unp_link.le_next"):
                yield [unp.unp_socket]


class DarwinSocketsFromHandles(common.AbstractDarwinProducer):
    """Looks up handles that point to a socket and collects the socket."""

    name = "open_sockets"
    type_name = "socket"

    def collect(self):
        for fileproc in self.session.plugins.collect("fileproc"):
            if fileproc.fg_type == "DTYPE_SOCKET":
                yield [fileproc.autocast_fg_data()]


class DarwinNetstat(common.AbstractDarwinCommand):
    """Prints all open sockets we know about, from any source.

    Netstat will display even connections that lsof doesn't know about, because
    they were either recovered from an allocation zone, or found through a
    secondary mechanism (like system call handler cache).

    On the other hand, netstat doesn't know the file descriptor or, really, the
    process that owns the connection (although it does know the PID of the last
    process to access the socket.)

    Netstat will also tell you, in the style of psxview, if a socket was only
    found using some of the methods available.
    """

    name = "netstat"

    @classmethod
    def methods(cls):
        """Return the names of available socket enumeration methods."""
        # Find all the producers that collect procs and inherit from
        # AbstractDarwinCachedProducer.
        methods = []
        for subclass in common.AbstractDarwinProducer.classes.itervalues():
            # We look for a plugin which is a producer and a darwin command.
            if (issubclass(subclass, common.AbstractDarwinCommand) and
                    issubclass(subclass, plugin.Producer) and
                    subclass.type_name == "socket"):
                methods.append(subclass.name)
        methods.sort()

        return methods

    @registry.classproperty
    @registry.memoize
    def table_header(cls):  # pylint: disable=no-self-argument
        header = [dict(name="socket", type="socket", width=60)]
        for method in cls.methods():
            header.append(dict(name=method, width=12))

        return plugin.PluginHeader(*header)

    def collect(self):
        methods = self.methods()

        for socket in sorted(self.session.plugins.collect("socket"),
                             key=lambda socket: socket.last_pid):
            row = [socket]
            for method in methods:
                row.append(method in socket.obj_producers)

            yield row


class DarwinGetArpListHead(common.AbstractDarwinParameterHook):
    """

    One version of arp_init looks like this:

    void
    arp_init(void)
    {
        VERIFY(!arpinit_done);

        LIST_INIT(&llinfo_arp); // <-- This is the global we want.

        llinfo_arp_zone = zinit(sizeof (struct llinfo_arp),
            LLINFO_ARP_ZONE_MAX * sizeof (struct llinfo_arp), 0,
            LLINFO_ARP_ZONE_NAME);
        if (llinfo_arp_zone == NULL)
            panic("%s: failed allocating llinfo_arp_zone", __func__);

        zone_change(llinfo_arp_zone, Z_EXPAND, TRUE);
        zone_change(llinfo_arp_zone, Z_CALLERACCT, FALSE);

        arpinit_done = 1;
    }

    Disassembled, the first few instructions look like this:
     0x0 55                   PUSH RBP
     0x1 4889e5               MOV RBP, RSP
     0x4 803d65e9400001       CMP BYTE [RIP+0x40e965], 0x1
     0xb 7518                 JNZ 0xff80090a7f95
     0xd 488d3dee802900       LEA RDI, [RIP+0x2980ee]
    0x14 488d35f5802900       LEA RSI, [RIP+0x2980f5]
    0x1b baf3000000           MOV EDX, 0xf3

    # This is a call to kernel!panic (later kernel!assfail):
    0x20 e80b6c1400           CALL 0xff80091eeba0

    # This is where it starts initializing the linked list:
    0x25 48c70548e94000000000 MOV QWORD [RIP+0x40e948], 0x0
         00
    0x30 488d0d0e812900       LEA RCX, [RIP+0x29810e]
    """
    name = "disassembled_llinfo_arp"

    PANIC_FUNCTIONS = (u"__kernel__!_panic", u"__kernel__!_assfail")

    def calculate(self):
        resolver = self.session.address_resolver
        arp_init = resolver.get_constant_object("__kernel__!_arp_init",
                                                target="Function")
        instructions = iter(arp_init.Decompose(20))

        # Walk down to the CALL mnemonic and use the address resolver to
        # see if it calls one of the panic functions.
        for instruction in instructions:
            # Keep spinning until we get to the first CALL.
            if instruction.mnemonic != "CALL":
                continue

            # This is absolute:
            target = instruction.operands[0].value
            _, names = resolver.get_nearest_constant_by_address(target)
            if not names:
                return obj.NoneObject("Could not find CALL in arp_init.")

            if names[0] not in self.PANIC_FUNCTIONS:
                return obj.NoneObject(
                    "CALL was to %r, which is not on the PANIC list."
                    % names)

            # We verified it's the right CALL. MOV should be right after it,
            # so let's just grab it.
            mov_instruction = next(instructions)
            if mov_instruction.mnemonic != "MOV":
                return obj.NoneObject("arp_init code changed.")

            offset = (mov_instruction.operands[0].disp
                      + mov_instruction.address
                      + mov_instruction.size)
            address = self.session.profile.Object(type_name="address",
                                                  offset=offset)

            llinfo_arp = self.session.profile.Object(
                type_name="llinfo_arp",
                offset=address.v())

            if llinfo_arp.isvalid:
                return llinfo_arp.obj_offset

            return obj.NoneObject("llinfo_arp didn't validate.")


class DarwinArp(common.AbstractDarwinProducer):
    """Show information about arp tables."""

    name = "arp"
    type_name = "rtentry"

    def collect(self):
        llinfo_arp = self.session.address_resolver.get_constant_object(
            "__kernel__!_llinfo_arp",
            target="Pointer",
            target_args=dict(target="llinfo_arp"))

        if not llinfo_arp:
            # Must not have it in the profile. Try asking the session hook
            # for the address.
            offset = self.session.GetParameter("disassembled_llinfo_arp")
            if not offset:
                self.session.logging.error(
                    "Could not find the address of llinfo_arp.")
                return

            llinfo_arp = self.session.profile.Object(
                type_name="llinfo_arp", offset=offset)

        for arp_hit in llinfo_arp.walk_list("la_le.le_next"):
            yield [arp_hit.la_rt]


class DarwinRoute(common.AbstractDarwinCommand):
    """Show routing table."""

    __name = "route"

    RNF_ROOT = 2

    def rn_walk_tree(self, h):
        """Walks the radix tree starting from the header h.

        This function is taken from
        xnu-2422.1.72/bsd/net/radix.c: rn_walk_tree()

        Which is why it does not conform to the style guide.

        Note too that the darwin source code abuses C macros:

        #define rn_dupedkey     rn_u.rn_leaf.rn_Dupedkey
        #define rn_key          rn_u.rn_leaf.rn_Key
        #define rn_mask         rn_u.rn_leaf.rn_Mask
        #define rn_offset       rn_u.rn_node.rn_Off
        #define rn_left         rn_u.rn_node.rn_L
        #define rn_right        rn_u.rn_node.rn_R

        And then the original code does:
        rn = rn.rn_left

        So we replace these below.
        """
        rn = h.rnh_treetop

        seen = set()

        # First time through node, go left */
        while rn.rn_bit >= 0:
            rn = rn.rn_u.rn_node.rn_L

        while rn and rn not in seen:
            base = rn

            seen.add(rn)

            # If at right child go back up, otherwise, go right
            while (rn.rn_parent.rn_u.rn_node.rn_R == rn and
                   not rn.rn_flags & self.RNF_ROOT):
                rn = rn.rn_parent

            # Find the next *leaf* to start from
            rn = rn.rn_parent.rn_u.rn_node.rn_R
            while rn.rn_bit >= 0:
                rn = rn.rn_u.rn_node.rn_L

            next = rn

            # Process leaves
            while True:
                rn = base
                if not rn:
                    break

                base = rn.rn_u.rn_leaf.rn_Dupedkey
                if not rn.rn_flags & self.RNF_ROOT:
                    yield rn

            rn = next
            if rn.rn_flags & self.RNF_ROOT:
                return

    def render(self, renderer):
        renderer.table_header(
            [("Source IP", "source", "20"),
             ("Dest IP", "dest", "20"),
             ("Interface", "interface", "9"),
             ("Sent", "sent", "8"),
             ("Recv", "recv", "8"),
             ("Time", "timestamp", "24"),
             ("Expires", "expires", "8"),
             ("Delta", "delta", "8")])

        route_tables = self.profile.get_constant_object(
            "_rt_tables",
            target="Array",
            target_args=dict(
                count=32,
                target="Pointer",
                target_args=dict(
                    target="radix_node_head")))

        for node in self.rn_walk_tree(route_tables[2]):
            rentry = node.dereference_as("rtentry")

            renderer.table_row(
                rentry.source_ip,
                rentry.dest_ip,
                rentry.name,
                rentry.sent, rentry.rx,
                rentry.base_calendartime,
                rentry.rt_expire,
                rentry.delta)


class DarwinIfnetHook(common.AbstractDarwinParameterHook):
    """Walks the global list of interfaces.

    The head of the list of network interfaces is a kernel global [1].
    The struct we use [2] is just the public part of the data [3]. Addresses
    are related to an interface in a N:1 relationship [4]. AF-specific data
    is a normal sockaddr struct.

    References:
      1:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/net/dlil.c#L254
      2:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/net/if_var.h#L528
      3:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/net/dlil.c#L188
      4:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/net/if_var.h#L816
    """

    name = "ifconfig"

    # ifnet_head is the actual extern holding ifnets and seems to be an
    # improvement over dlil_ifnet_head, which is a static and used only in the
    # dlil (stands for data link interface, I think?) module.
    IFNET_HEAD_NAME = ("_ifnet_head", "_dlil_ifnet_head")

    def calculate(self):
        ifnet_head = obj.NoneObject("No ifnet global names given.")
        for name in self.IFNET_HEAD_NAME:
            ifnet_head = self.session.profile.get_constant_object(
                name,
                target="Pointer",
                target_args=dict(
                    target="ifnet"))

            if ifnet_head:
                break

        return [x.obj_offset for x in ifnet_head.walk_list("if_link.tqe_next")]


class DarwinIfnetCollector(common.AbstractDarwinCachedProducer):
    name = "ifconfig"
    type_name = "ifnet"


class DarwinIPFilters(common.AbstractDarwinCommand):
    """Check IP Filters for hooks."""

    __name = "ip_filters"

    def render(self, renderer):
        renderer.table_header([
            ("Context", "context", "10"),
            ("Filter", "filter", "16"),
            ("Handler", "handler", "[addrpad]"),
            ("Symbol", "symbol", "20")])

        resolver = self.session.address_resolver
        for list_name in ["_ipv4_filters", "_ipv6_filters"]:
            filter_list = self.profile.get_constant_object(
                list_name, target="ipfilter_list")

            for item in filter_list.tqh_first.walk_list("ipf_link.tqe_next"):
                filter = item.ipf_filter
                name = filter.name.deref()
                handler = filter.ipf_input.deref()
                renderer.table_row("INPUT", name, handler,
                                   resolver.format_address(handler))

                handler = filter.ipf_output.deref()
                renderer.table_row("OUTPUT", name, handler,
                                   resolver.format_address(handler))

                handler = filter.ipf_detach.deref()
                renderer.table_row("DETACH", name, handler,
                                   resolver.format_address(handler))
