# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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

#pylint: disable-msg=C0111

from volatility.plugins.windows import common
from volatility import obj

protos = {
          0:"HOPOPT",
          1:"ICMP",
          2:"IGMP",
          3:"GGP",
          4:"IPv4",
          5:"ST",
          6:"TCP",
          7:"CBT",
          8:"EGP",
          9:"IGP",
          10:"BBN-RCC-MON",
          11:"NVP-II",
          12:"PUP",
          13:"ARGUS",
          14:"EMCON",
          15:"XNET",
          16:"CHAOS",
          17:"UDP",
          18:"MUX",
          19:"DCN-MEAS",
          20:"HMP",
          21:"PRM",
          22:"XNS-IDP",
          23:"TRUNK-1",
          24:"TRUNK-2",
          25:"LEAF-1",
          26:"LEAF-2",
          27:"RDP",
          28:"IRTP",
          29:"ISO-TP4",
          30:"NETBLT",
          31:"MFE-NSP",
          32:"MERIT-INP",
          33:"DCCP",
          34:"3PC",
          35:"IDPR",
          36:"XTP",
          37:"DDP",
          38:"IDPR-CMTP",
          39:"TP++",
          40:"IL",
          41:"IPv6",
          42:"SDRP",
          43:"IPv6-Route",
          44:"IPv6-Frag",
          45:"IDRP",
          46:"RSVP",
          47:"GRE",
          48:"DSR",
          49:"BNA",
          50:"ESP",
          51:"AH",
          52:"I-NLSP",
          53:"SWIPE",
          54:"NARP",
          55:"MOBILE",
          56:"TLSP",
          57:"SKIP",
          58:"IPv6-ICMP",
          59:"IPv6-NoNxt",
          60:"IPv6-Opts",
          61:"Host-interal",
          62:"CFTP",
          63:"Local Network",
          64:"SAT-EXPAK",
          65:"KRYPTOLAN",
          66:"RVD",
          67:"IPPC",
          68:"Dist-FS",
          69:"SAT-MON",
          70:"VISA",
          71:"IPCV",
          72:"CPNX",
          73:"CPHB",
          74:"WSN",
          75:"PVP",
          76:"BR-SAT-MON",
          77:"SUN-ND",
          78:"WB-MON",
          79:"WB-EXPAK",
          80:"ISO-IP",
          81:"VMTP",
          82:"SECURE-VMTP",
          83:"VINES",
          84:"TTP",
          84:"IPTM",
          85:"NSFNET-IGP",
          86:"DGP",
          87:"TCF",
          88:"EIGRP",
          89:"OSPFIGP",
          90:"Sprite-RPC",
          91:"LARP",
          92:"MTP",
          93:"AX.25",
          94:"IPIP",
          95:"MICP",
          96:"SCC-SP",
          97:"ETHERIP",
          98:"ENCAP",
          99:"Encryption",
          100:"GMTP",
          101:"IFMP",
          102:"PNNI",
          103:"PIM",
          104:"ARIS",
          105:"SCPS",
          106:"QNX",
          107:"A/N",
          108:"IPComp",
          109:"SNP",
          110:"Compaq-Peer",
          111:"IPX-in-IP",
          112:"VRRP",
          113:"PGM",
          114:"0-hop",
          115:"L2TP",
          116:"DDX",
          117:"IATP",
          118:"STP",
          119:"SRP",
          120:"UTI",
          121:"SMP",
          122:"SM",
          123:"PTP",
          124:"ISIS over IPv4",
          125:"FIRE",
          126:"CRTP",
          127:"CRUDP",
          128:"SSCOPMCE",
          129:"IPLT",
          130:"SPS",
          131:"PIPE",
          132:"SCTP",
          133:"FC",
          134:"RSVP-E2E-IGNORE",
          135:"Mobility Header",
          136:"UDPLite",
          137:"MPLS-in-IP",
          138:"manet",
          139:"HIP",
          140:"Shim6",
          141:"WESP",
          142:"ROHC",
          253:"Experimental",
          254:"Experimental",
          255:"Reserved",
}


# The following are found empirically by reverse engineering. We try to find the
# TCB table which matches the image. This plugin is likely to fail for other
# operating systems and versions.
module_versions_xp = {
    'MP' : {
        'TCBTableOff' : 0x497e8,
        'SizeOff' : 0x3f7c8,
        'AddrObjTableOffset' : 0x48760,
        'AddrObjTableSizeOffset' : 0x48764,
        },
    'UP' : {
        'TCBTableOff' : 0x495e8,
        'SizeOff' : 0x3f5bc,
        'AddrObjTableOffset' : 0x48560,
        'AddrObjTableSizeOffset' : 0x48564,
        },
    '2180' : {
        'TCBTableOff' : 0x493e8,
        'SizeOff' : 0x3f3b0,
        'AddrObjTableOffset'  : 0x48360,
        'AddrObjTableSizeOffset' : 0x48364,
        },
    '3244' : {
        'TCBTableOff' : 0x496E8,
        'SizeOff' : 0x3F6BC,
        'AddrObjTableOffset'  : 0x48660,
        'AddrObjTableSizeOffset' : 0x48664,
        },
    '3394': {
        'TCBTableOff': 0x49768,
        'SizeOff': 0x3F73C,
        'AddrObjTableOffset': 0x486E0,
        'AddrObjTableSizeOffset': 0x486E4,
        },
    '5625' : {
        'TCBTableOff' : 0x49ae8,
        'SizeOff' : 0x3fac8,
        'AddrObjTableOffset'  : 0x48a60,
        'AddrObjTableSizeOffset' : 0x48a64,
        },
    '2111' : {
        'TCBTableOff' : 0x49A68,
        'SizeOff' : 0x3FA48,
        'AddrObjTableOffset'  : 0x489E0,
        'AddrObjTableSizeOffset' : 0x489E4,
        },
    }

module_versions_2k3 = {
    # w2k3 sp0
    '3790' : {
        'TCBTableOff' : 0x4c6c8,
        'SizeOff' : 0x4312c,
        'AddrObjTableOffset'  : 0x4bba0,
        'AddrObjTableSizeOffset' : 0x4bba4,
        },
    # w2k3 sp1
    '1830' : {
        'TCBTableOff' : 0x4e428,
        'SizeOff' : 0x44140,
        'AddrObjTableOffset'  : 0x4d4e4,
        'AddrObjTableSizeOffset' : 0x4d4e8,
        },
    # w2k3 sp2
    '3959' : {
        'TCBTableOff' : 0x7c548,
        'SizeOff' : 0x50308,
        'AddrObjTableOffset'  : 0x5ada4,
        'AddrObjTableSizeOffset' : 0x5ada8,
        },
    # w2k3 sp2
    '4573' : {
        'TCBTableOff' : 0x7f0ac,
        'SizeOff' : 0x52328,
        'AddrObjTableOffset'  : 0x5cf04,
        'AddrObjTableSizeOffset' : 0x5cf08,
        },
    }


class Connections(common.AbstractWindowsCommandPlugin):
    """
    Print list of open connections [Windows XP Only]
    ---------------------------------------------

    This module enumerates the active connections from tcpip.sys.

    Note that if you are using a hibernated image this might not work
    because Windows closes all sockets before hibernating. You might
    find it more effective to do conscan instead.
    """

    __name = "connections"

    def __init__(self, **kwargs):
        """Enumerates the active connections in tcpip.sys's data structures."""
        super(Connections, self).__init__(**kwargs)

    def determine_connections(self):
        """Determines active connections in tcpip.sys"""
        version = (self.profile.metadata('major', 0),
                   self.profile.metadata('minor', 0))

        if version <= (5, 1):
            module_versions = module_versions_xp
        else:
            module_versions = module_versions_2k3

        # List all the modules using the modules plugin
        modules = self.session.plugins.modules(session=self.session)
        for m in modules.lsmod():
            # Try to find the tcpip.sys module.
            if str(m.BaseDllName).lower() == 'tcpip.sys':

                # Try every possibility in the lookup table.
                for attempt in module_versions:
                    SizeOff = module_versions[attempt]['SizeOff']
                    TCBTableOff = module_versions[attempt]['TCBTableOff']
                    BaseAddress = int(m.DllBase)

                    table_size = m.obj_profile.Object(
                        theType="long", offset=BaseAddress + SizeOff, vm=m.obj_vm)

                    table_addr = m.obj_profile.Object(
                        theType="unsigned long", offset=BaseAddress + TCBTableOff,
                        vm = m.obj_vm)

                    if table_size > 0:
                        table = m.obj_profile.Object(
                            theType="Array", offset=table_addr, vm=m.obj_vm,
                            count = table_size,
                            target = "Pointer", target_args = dict(target='_TCPT_OBJECT'))

                        if table:
                            for entry in table:
                                conn = entry.dereference()
                                seen = set()
                                while conn.is_valid() and conn.obj_offset not in seen:
                                    yield conn
                                    seen.add(conn.obj_offset)
                                    conn = conn.Next.dereference()


    def render(self, renderer):
        renderer.table_header([("Offset (V)", "offset_v", "[addrpad]"),
                               ("Local Address", "local_net_address", "25"),
                               ("Remote Address", "remote_net_address", "25"),
                               ("Pid", "pid", ">6")
                               ])

        for conn in self.determine_connections():
            offset = conn.obj_offset
            local = "{0}:{1}".format(conn.LocalIpAddress, conn.LocalPort)
            remote = "{0}:{1}".format(conn.RemoteIpAddress, conn.RemotePort)
            renderer.table_row(offset, local, remote, conn.Pid)


class Sockets(common.AbstractWindowsCommandPlugin):
    """
    Print list of open sockets. [Windows xp only]
    ---------------------------------------------

    This module enumerates the active sockets from tcpip.sys

    Note that if you are using a hibernated image this might not work
    because Windows closes all sockets before hibernating.
    """

    __name = "sockets"

    def __init__(self, **kwargs):
        """Enumerates the active sockets in tcpip.sys's data structures."""
        super(Sockets, self).__init__(**kwargs)

    def determine_sockets(self):
        """Determines all active sockets in tcpip.sys"""
        version = (self.profile.metadata('major', 0),
                   self.profile.metadata('minor', 0))

        if version <= (5, 1):
            module_versions = module_versions_xp
        else:
            module_versions = module_versions_2k3

        # List all the modules using the modules plugin
        modules = self.session.plugins.modules(session=self.session)
        for m in modules.lsmod():
            # Try to find the tcpip.sys module.
            if str(m.BaseDllName).lower() == 'tcpip.sys':

                # Try every possibility in the lookup table.
                for attempt in module_versions:
                    AddrObjTableSizeOffset = module_versions[attempt]['AddrObjTableSizeOffset']
                    AddrObjTableOffset = module_versions[attempt]['AddrObjTableOffset']
                    BaseAddress = int(m.DllBase)

                    table_size = m.obj_profile.Object(
                        theType="long", offset=BaseAddress + AddrObjTableSizeOffset,
                        vm=m.obj_vm)

                    table_addr = m.obj_profile.Object(
                        theType="unsigned long", offset=BaseAddress + AddrObjTableOffset,
                        vm = m.obj_vm)

                    if table_size > 0:
                        table = m.obj_profile.Object(
                            theType="Array", offset=table_addr, vm=m.obj_vm,
                            count = table_size,
                            target = "Pointer", target_args=dict(target='_ADDRESS_OBJECT'))

                        if table:
                            for entry in table:
                                sock = entry.dereference()
                                seen = set()
                                while sock.is_valid() and sock.obj_offset not in seen:
                                    yield sock
                                    seen.add(sock.obj_offset)
                                    sock = sock.Next.dereference()

    def render(self, renderer):
        renderer.table_header([("Offset (V)", "offset_v", "[addrpad]"),
                               ("PID", "pid", ">6"),
                               ("Port", "port", ">6"),
                               ("Proto", "protocol_number", ">6"),
                               ("Protocol", "protocol", "15"),
                               ("Address", "address", "15"),
                               ("Create Time", "socket_create_time", "")
                               ])

        for sock in self.determine_sockets():
            offset = sock.obj_offset
            protocol = sock.Protocol.v()
            if protocol > 255:
                protocol = "-"
            else:
                protocol = protos.get(protocol, "Unassigned")

            renderer.table_row(offset, sock.Pid, sock.LocalPort, sock.Protocol, protocol,
                               sock.LocalIpAddress, sock.CreateTime)
