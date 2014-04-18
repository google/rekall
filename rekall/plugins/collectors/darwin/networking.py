# Rekall Memory Forensics
#
# Copyright 2014 Google Inc. All Rights Reserved.
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

"""
Collectors for sockets and other network-related things.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall import components
from rekall import identity as id


def ParseSocket(socket):
    if socket.addressing_family in ("AF_INET", "AF_INET6"):
        connection = components.Connection(
            addressing_family=socket.addressing_family,
            state=socket.tcp_state,
            protocols=(
                "IPv4" if socket.addressing_family == "AF_INET" else "IPv6",
                socket.l4_protocol,
            ),
            src_addr=socket.src_addr,
            src_bind=socket.src_port,
            dst_addr=socket.dst_addr,
            dst_bind=socket.dst_port,
        )

        named = components.Named(
            name="%s/%d -> %s/%d" % (
                connection.src_addr, connection.src_bind,
                connection.dst_addr, connection.dst_bind),
            kind="%s socket" % connection.protocols[0],
        )
    elif socket.addressing_family == "AF_UNIX":
        connection = components.Connection(
            addressing_family="AF_UNIX",
            state=None,
            src_addr="0x%x" % int(socket.so_pcb),
            dst_addr="0x%x" % int(socket.unp_conn),
            protocols=("Unix", socket.unix_type),
            src_bind=socket.get_socketinfo_attr("unsi_addr"),
            dst_bind=None,
        )

        named = components.Named(
            name="%s->%s" % (connection.src_addr, connection.dst_addr),
            kind="%s socket" % connection.protocols[0],
        )
    else:
        connection = components.Connection(
            addressing_family=socket.addressing_family,
            state=None,
            src_addr=None,
            src_bind=None,
            dst_addr=None,
            dst_bind=None,
            protocols=[socket.addressing_family],
        )

        named = components.Named(
            name=None,
            kind="%s socket" % connection.addressing_family,
        )

    return connection, named


def ParseVnode(vnode):
    file = components.File(
        full_path=vnode.full_path,
    )

    named = components.Named(
        name=vnode.full_path,
        kind="Reg. File",
    )

    return file, named


def UnixSocketCollector(profile):
    """Walks the global unpcb lists and returns just the sockets.

    Yields:
      DarwinUnixSocket entities.

    See here:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/kern/uipc_usrreq.c#L121
    """
    for head_const in ["_unp_dhead", "_unp_shead"]:
        lhead = profile.get_constant_object(
            head_const,
            target="unp_head")

        for unp in lhead.lh_first.walk_list("unp_link.le_next"):
            connection, named = ParseSocket(unp.unp_socket)
            yield id.BaseObjectIdentity(unp.unp_socket), (connection, named)


def FileprocHandleCollector(profile):
    for process in profile.session.entities.find_by_component("Process"):
        base_obj = process.components.MemoryObject.base_object

        for fd, fileproc, flags in base_obj.get_open_files():
            data = fileproc.autocast_fg_data()
            assert data
            resource_id = id.BaseObjectIdentity(data)
            handle_id = id.BaseObjectIdentity(fileproc)

            handle = components.Handle(
                process_identity=process.identity,
                fd=fd,
                flags=flags,
                resource_identity=resource_id,
            )

            handle_mem_obj = components.MemoryObject(
                base_object=fileproc,
                type="fileproc",
            )

            yield handle_id, (handle, handle_mem_obj)

            resource_mem_obj = components.MemoryObject(
                base_object=data,
                type=type(data).__name__,
            )

            resource = components.Resource(
                handle_identity=handle_id,
            )

            yield resource_id, (resource_mem_obj, resource)


def HandleSocketCollector(profile):
    # Indexing commented out because, right now, it actually makes things
    # slower by about 300 ms on the first run (subsequent runs are obviously
    # much faster). TODO: Try and optimize indexing, maybe by doing it in
    # batches, or deferring it.
    # profile.session.entities.add_attribute_lookup("MemoryObject", "type")

    # Make sure all the handles are collected.
    profile.session.entities.run_collector(FileprocHandleCollector)

    # We just need the base objects for sockets.
    for entity in profile.session.entities.find_by_attribute(
        "MemoryObject", "type", "socket"):
        connection, named = ParseSocket(entity["MemoryObject.base_object"])

        # The original entity /is/ the socket, so we just reuse the identity.
        yield entity.identity, (connection, named)


def HandleVnodeCollector(profile):
    # Collect all the handles.
    profile.session.entities.run_collector(FileprocHandleCollector)

    # All we need are vnodes.
    for entity in profile.session.entities.find_by_attribute(
        "MemoryObject", "type", "vnode"):
        file, named = ParseVnode(entity["MemoryObject.base_object"])

        yield entity.identity, (file, named)


def ParseNetworkInterface(interface):
    yield components.Named(
        name="%s%d" % (
            interface.if_name.deref(),
            interface.if_unit,
        ),
        kind="Network Interface",
    )

    yield components.NetworkInterface(
        addresses=[
            (x.ifa_addr.sa_family, x.ifa_addr.deref())
            for x
            in interface.if_addrhead.tqh_first.walk_list("ifa_link.tqe_next")
        ],
    )


def NetworkInterfaces(profile):
    """Walks the global list of interfaces.

    The head of the list of network interfaces is a kernel global [1].
    The struct we use [2] is just the public part of the data [3]. Addresses
    are related to an interface in a N:1 relationship [4]. AF-specific data
    is a normal sockaddr struct.

    Yields:
      Network interfaces.

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
    ifnet_head = profile.get_constant_object(
        "_dlil_ifnet_head",
        target="Pointer",
        target_args=dict(
            target="ifnet"
        )
    )

    for interface in ifnet_head.walk_list("if_link.tqe_next"):
        yield interface, ParseNetworkInterface(interface)

