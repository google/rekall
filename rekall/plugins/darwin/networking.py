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

__author__ = "Michael Cohen <scudette@google.com>"

from rekall.plugins.darwin import common


class DarwinArp(common.DarwinPlugin):
    """Show information about arp tables."""

    __name = "arp"

    def render(self, renderer):
        renderer.table_header(
            [("IP Addr", "ip_addr", "20"),
             ("MAC Addr", "mac", "18"),
             ("Interface", "interface", "9"),
             ("Sent", "sent", "8"),
             ("Recv", "recv", "8"),
             ("Time", "timestamp", "24"),
             ("Expires", "expires", "8"),
             ("Delta", "delta", "8"),
             ])

        arp_cache = self.profile.get_constant_object(
            "_llinfo_arp",
            target="Pointer",
            target_args=dict(
                target="llinfo_arp"
                )
            )

        while arp_cache:
            entry = arp_cache.la_rt

            renderer.table_row(
                entry.source_ip,
                entry.dest_ip,
                entry.name,
                entry.sent,
                entry.rx,
                entry.base_calendartime,
                entry.rt_expire,
                entry.delta
                )

            arp_cache = arp_cache.la_le.le_next


class DarwinRoute(common.DarwinPlugin):
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
             ("Delta", "delta", "8"),
             ])

        route_tables = self.profile.get_constant_object(
            "_rt_tables",
            target="Array",
            target_args=dict(
                count=32,
                target="Pointer",
                target_args=dict(
                    target="radix_node_head"
                    )
                )
            )

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


class DarwinIFConfig(common.DarwinPlugin):
    """List network interface information."""

    __name = "ifconfig"

    def render(self, renderer):
        renderer.table_header([("Interface", "interface", "10"),
                               ("Address", "address", "20")])

        ifnet_head = self.profile.get_constant_object(
            "_dlil_ifnet_head",
            target="Pointer",
            target_args=dict(
                target="ifnet"
                )
            )

        for interface in ifnet_head.walk_list("if_link.tqe_next"):
            for address in interface.if_addrhead.tqh_first.walk_list(
                "ifa_link.tqe_next"):
                name = "%s%d" % (interface.if_name.deref(),
                                      interface.if_unit)

                renderer.table_row(
                    name, address.ifa_addr.deref())


class DarwinIPFilters(common.DarwinPlugin):
    """Check IP Filters for hooks."""

    __name = "ip_filters"

    def render(self, renderer):
        renderer.table_header([
                ("Context", "context", "10"),
                ("Filter", "filter", "16"),
                ("Handler", "handler", "[addrpad]"),
                ("Symbol", "symbol", "20")])

        lsmod = self.session.plugins.lsmod(session=self.session)

        for list_name in ["_ipv4_filters", "_ipv6_filters"]:
            filter_list = self.profile.get_constant_object(
                list_name, target="ipfilter_list")

            for item in filter_list.tqh_first.walk_list("ipf_link.tqe_next"):
                filter = item.ipf_filter
                name = filter.name.deref()
                handler = filter.ipf_input.deref()
                renderer.table_row("INPUT", name, handler,
                                   lsmod.ResolveSymbolName(handler))

                handler = filter.ipf_output.deref()
                renderer.table_row("OUTPUT", name, handler,
                                   lsmod.ResolveSymbolName(handler))

                handler = filter.ipf_detach.deref()
                renderer.table_row("DETACH", name, handler,
                                   lsmod.ResolveSymbolName(handler))


class DarwinNetstat(common.DarwinProcessFilter):
    """List per process network connections."""

    __name = "netstat"

    def render(self, renderer):
        """Display all sockets for requested processes.

        We show two separate lists, one for the TCP sockets and one for Unix
        domain sockets.
        """
        unix_sockets = []
        tcp_sockets = []

        for proc in self.filter_processes():
            for fd, fileproc in enumerate(proc.p_fd.fd_ofiles):
                # When the fileproc is a socket, the fg_data is of type
                # "socket".
                if fileproc.f_fglob.fg_type == "DTYPE_SOCKET":
                    socket = fileproc.f_fglob.fg_data.dereference_as("socket")
                    family = socket.so_proto.pr_domain.dom_family

                    if family == "AF_UNIX":
                        unpcb = socket.so_pcb.dereference_as("unpcb")
                        name = unpcb.unp_addr.sun_path
                        unix_sockets.append((proc, fd, socket, name))

                    elif family in ("AF_INET", "AF_INET6"):
                        tcp_sockets.append((proc, fd, socket))

        # First do the tcp sockets.
        renderer.table_header([("Proto", "proto", "14"),
                               ("SAddr", "saddr", "15"),
                               ("SPort", "sport", "8"),
                               ("DAddr", "daddr", "15"),
                               ("DPort", "dport", "5"),
                               ("State", "state", "15"),
                               ("Pid", "pid", "8"),
                               ("Comm", "comm", "20")])

        for proc, fd, sock  in tcp_sockets:
            info = sock.fill_socketinfo()

            renderer.table_row(
                sock.so_proto.pr_protocol,
                info.local_ip,
                info.local_port,
                info.remote_ip,
                info.remote_port,
                info.state,
                proc.p_pid,
                proc.p_comm,
                )

        # Now do the udp sockets.
        renderer.table_header([("Family", "proto", "14"),
                               ("Pid", "pid", "8"),
                               ("Comm", "comm", "20"),
                               ("Path", "path", "20")])

        for proc, _, socket, name in unix_sockets:
            renderer.table_row(
                socket.so_proto.pr_domain.dom_family,
                proc.p_pid,
                proc.p_comm,
                name
                )
