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


from rekall import testlib
from rekall.plugins.linux import common
from rekall.plugins.overlays import basic


class Netstat(common.LinuxPlugin):
    """Print the active network connections."""

    __name = "netstat"

    def sockets(self):
        """Enumerate all socket objects."""

        lsof = self.session.plugins.lsof(session=self.session)
        for task, file_struct, fd in lsof.lsof():
            if (file_struct.f_op == self.profile.get_constant(
                "socket_file_ops") or
                file_struct.m("d_entry").d_op == self.profile.get_constant(
                    "sockfs_dentry_operations")):

                iaddr = file_struct.dentry.d_inode

                # See http://lxr.free-electrons.com/source/include/net/sock.h?v=3.8#L1319
                skt = basic.container_of(iaddr, "socket_alloc",
                                         "vfs_inode").socket

                yield task, fd, skt.sk, iaddr

    def render(self, renderer):
        unix_sockets = []
        inet_sockets = []

        for task, fd, sock, iaddr in self.sockets():
            inet_sock = sock.dereference_as("inet_sock")

            if sock.sk_protocol not in ("IPPROTO_TCP", "IPPROTO_UDP",
                                        "IPPROTO_IPV4", "IPPROTO_IPV6",
                                        "IPPROTO_HOPOPT"):
                continue

            sk_common = sock.m("__sk_common")

            if sk_common.skc_family in ("AF_UNIX", "AF_LOCAL"):
                unix_sock = sock.dereference_as("unix_sock")
                name = unix_sock.addr.name[0].sun_path
                unix_sockets.append((task, fd, sock, iaddr, sk_common))

            elif sk_common.skc_family in ("AF_INET", "AF_INET6"):
                inet_sockets.append((task, fd, sock, iaddr, sk_common))

        # First do the AF_INET and AF_INET6 sockets.
        renderer.table_header([("Proto", "proto", "12"),
                               ("SAddr", "saddr", "15"),
                               ("SPort", "sport", "8"),
                               ("DAddr", "daddr", "15"),
                               ("DPort", "dport", "5"),
                               ("State", "state", "15"),
                               ("Pid", "pid", "8"),
                               ("Comm", "comm", "20")])

        for task, fd, sock, iaddr, sk_common in inet_sockets:
            inet_sock = sock.dereference_as("inet_sock")

            renderer.table_row(
                inet_sock.sk.sk_protocol,
                inet_sock.src_addr,
                inet_sock.src_port,
                inet_sock.dst_addr,
                inet_sock.dst_port,
                sk_common.skc_state,
                task.pid,
                task.comm,
                )

        renderer.section()

        # Now do the UNIX sockets.
        renderer.table_header([("Proto", "proto", "12"),
                               ("RefCount", "ref", "^8"),
                               ("Type", "type", "15"),
                               ("State", "state", "18"),
                               ("Inode", "inode", "8"),
                               ("Path", "path", "20")])

        for task, fd, sock, iaddr, sk_common in unix_sockets:
            unix_sock = sock.dereference_as("unix_sock")
            name = unix_sock.addr.name[0].sun_path

            renderer.table_row(
                "UNIX",
                unix_sock.addr.refcnt.counter,
                sock.sk_type,
                sk_common.skc_state,
                iaddr.i_ino,
                name
                )


class PacketQueues(common.LinuxPlugin):
    """Dumps the current packet queues for all known open sockets."""

    __name = "pkt_queues"

    @classmethod
    def args(cls, parser):
        super(PacketQueues, cls).args(parser)
        parser.add_argument(
            "--dump_dir", default=None, help="Output directory",
            required=True)

    def __init__(self, dump_dir=None, **kwargs):
        super(PacketQueues, self).__init__(**kwargs)
        self.output_dir = dump_dir

    def process_socket(self, renderer, task, fd_num, socket):
        queues = ["receive", "write"]
        for queue_name in queues:
            sk_buff_head_name = "sk_{0:s}_queue".format(queue_name)
            queue = getattr(socket, sk_buff_head_name)
            filename = "{0:d}.{1:s}.{2:s}.{3:d}".format(
                task.pid, task.name, queue_name, fd_num)
            data = []
            for sk_buff in queue.walk_list("next", False):
                pkt_len = sk_buff.len
                if pkt_len > 0:
                    if not sk_buff.data:
                        continue
                    data.append(self.kernel_address_space.read(
                        sk_buff.data.obj_offset, pkt_len))
            if data:
                with renderer.open(directory=self.output_dir,
                                   filename=filename,
                                   mode="wb") as fd:
                    fd.write(''.join(data))
                    self.session.logging.debug("Wrote %d bytes to %s",
                                               fd.tell(), filename)
                return True

            else:
                self.session.logging.debug("Skipped empty queue %s", filename)
                return False

    def render(self, renderer):
        netstat_plugin = self.session.plugins.netstat(session=self.session)
        sockets = netstat_plugin.sockets()

        all_sockets = list(sockets)
        skipped_sockets_count = 0
        for task, fd, socket, _ in all_sockets:
            if not self.process_socket(renderer, task, fd, socket):
                skipped_sockets_count += 1

        renderer.format("Skipped {0:d}/{1:d} sockets.", skipped_sockets_count,
                        len(all_sockets))


class TestPacketQueues(testlib.HashChecker):
    PARAMETERS = dict(
        commandline="pkt_queues --dump_dir %(tempdir)s"
        )
