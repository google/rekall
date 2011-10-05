# Volatility
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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""

import volatility.obj as obj

import linux_common, linux_flags
import linux_list_open_files as lof

import socket

class linux_netstat(lof.linux_list_open_files):
    ''' lists open files '''
    __name = "netstat"

    def calculate(self):
    
        if not self.profile.has_type("inet_sock"):
            # ancient (2.6.9) centos kernels do not have inet_sock in debug info
            raise AttributeError, "Given profile does not have inet_sock, please file a bug if the kernel version is > 2.6.11"

        openfiles = lof.linux_list_open_files.calculate(self)
    
        for (task, filp, _i, _addr_space) in openfiles:

            # its a socket!
            if filp.f_op == self.smap["socket_file_ops"] or filp.get_dentry().d_op == self.smap["sockfs_dentry_operations"]:
            
                iaddr = filp.get_dentry().d_inode
                skt = self.SOCKET_I(iaddr)
                inet_sock = obj.Object("inet_sock", offset = skt.sk, vm = self.addr_space)

                yield task, inet_sock

    def render_text(self, outfd, data):

        for task, inet_sock in data:

            proto = self.get_proto_str(inet_sock)
            
            if proto in ("TCP", "UDP", "IP"):

                state = self.get_state_str(inet_sock) if proto == "TCP" else ""
                family = inet_sock.sk.__sk_common.skc_family

                if family == 1: #AF_UNIX
                    
                    unix_sock = obj.Object("unix_sock", offset=inet_sock.sk.v(), vm=self.addr_space)
                    
                    if unix_sock.addr:
    
                        name = obj.Object("sockaddr_un", offset=unix_sock.addr.name.obj_offset, vm=self.addr_space)
                        
                        # only print out sockets with paths
                        if name.sun_path != "":
                            outfd.write("UNIX {0:s}\n".format(name.sun_path))
                             
                elif family in (2, 10):

                    if family == 2: #AF_INET
                        (daddr, saddr) = self.format_ipv4(inet_sock)
                        (dport, sport) = self.format_port(inet_sock)

                    elif family == 10: #AF_INET 6
                        (daddr, saddr) = self.format_ipv6(inet_sock)
                        (dport, sport) = self.format_port(inet_sock)

                    outfd.write("{0:8s} {1}:{2:<5} {3}:{4:<5} {5:s} {6:>17s}/{7:<5d}\n".format(proto, saddr, sport, daddr, dport, state, task.comm, task.pid))


    def format_ipv6(self, inet_sock):
        daddr = linux_common.ip62str(inet_sock.pinet6.daddr)
        saddr = linux_common.ip62str(inet_sock.pinet6.saddr)

        return (daddr, saddr)        

    # formats an ipv4 address
    def format_ipv4(self, inet_sock):
        try:
            daddr = linux_common.ip2str(inet_sock.daddr.v())
            saddr = linux_common.ip2str(inet_sock.rcv_saddr.v())
        except AttributeError:
            daddr = linux_common.ip2str(inet_sock.inet_daddr.v())
            saddr = linux_common.ip2str(inet_sock.inet_rcv_saddr.v())

        return (daddr, saddr)

    def format_port(self, inet_sock):
        try:
            dport = socket.htons(inet_sock.dport)
            sport = socket.htons(inet_sock.sport)
        except AttributeError:
            dport = socket.htons(inet_sock.inet_dport)
            sport = socket.htons(inet_sock.inet_sport)

        return (dport, sport)

    def get_state_str(self, inet_sock):

        state = inet_sock.sk.__sk_common.skc_state

        return linux_flags.tcp_states[state]

    def get_proto_str(self, inet_sock):

        proto = inet_sock.sk.sk_protocol.v()

        if proto in linux_flags.protocol_strings:
            ret = linux_flags.protocol_strings[proto]
        else:
            ret = "UNKNOWN"

        return ret

    # has to get the struct socket given an inode (see SOCKET_I in sock.h)
    def SOCKET_I(self, inode):
        # if too many of these, write a container_of
        backsize = linux_common.sizeofstruct("socket", self.profile)
        addr = inode - backsize

        return obj.Object('socket', offset = addr, vm = self.addr_space)
