# Copyright (c) 2008, Bruce M. Simpson
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# Neither the name of the authors nor the names of contributors may be
# used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# File: $Id$
#
# Author: Bruce M. Simpson
#
# Description: This module performs a self test on a DHCPv4 packet.

import unittest
import sys

from hexdumper import hexdumper

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.

    from pcs import inet_atol
    from pcs import PcapConnector

    from pcs.packets.ethernet import ether_atob
    from pcs.packets.ethernet import ether_btoa
    from pcs.packets.ipv4 import *
    from pcs.packets.udp import *

    from pcs.packets import dhcpv4
    from pcs.packets.dhcpv4 import *

    from pcs.packets import dhcpv4_options
    from pcs.packets.dhcpv4_options import *

class bootpTestCase(unittest.TestCase):
    def test_dhcpv4_encode(self):
        p = dhcpv4()
        assert (p != None)

        p.op = pcs.packets.dhcpv4.BOOTREQUEST
        p.htype = pcs.packets.dhcpv4.HTYPE_ETHER
        p.hlen = 6      # sizeof(struct ether_addr)
        p.hops = 99
        p.xid = 0xABADCAFE
        p.secs = 123
        p.flags = pcs.packets.dhcpv4.BOOTP_BROADCAST

        p.ciaddr = inet_atol("1.2.3.4")
        p.yiaddr = inet_atol("5.6.7.8")
        p.siaddr = inet_atol("9.10.11.12")
        p.giaddr = inet_atol("13.14.15.16")

        p.chaddr = ether_atob("00:01:02:03:04:05")
        p.sname = "fubar"
        p.file  = "barfu"

        # Append DHCP options, which MUST include the cookie.

        p.options.append(dhcpv4_options.cookie().field())

        # Maximum DHCP message size.
        msz = dhcpv4_options.dhcp_max_message_size()
        msz.value = 1460
        p.options.append(msz.field())

        # DHCP message type.
        dhcp = dhcpv4_options.dhcp_message_type()
        dhcp.value = DHCPDISCOVER
        p.options.append(dhcp.field())

        # DHCP vendor class.
        vc = dhcpv4_options.dhcp_class_identifier()
        vc.value = "FreeBSD:amd64:7-CURRENT"
        p.options.append(vc.field())

        # BOOTP options end marker.
        end = dhcpv4_options.end()
        p.options.append(end.field())

        # Pad BOOTP payload to 32-bit width.
        padlen = 4 - (len(p.bytes) % 4)
        pad = dhcpv4_options.pad(padlen)
        p.options.append(pad.field())

        p.encode()
        #hd = hexdumper()
        #print p
        #print hd.dump2(p.bytes)
        gotttted = p.bytes
        expected = \
                "\x01\x01\x06\x63\xAB\xAD\xCA\xFE" \
                "\x00\x7B\x80\x00\x01\x02\x03\x04" \
                "\x05\x06\x07\x08\x09\x0A\x0B\x0C" \
                "\x0D\x0E\x0F\x10\x00\x01\x02\x03" \
                "\x04\x05\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x66\x75\x62\x61" \
                "\x72\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x62\x61\x72\x66" \
                "\x75\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x63\x82\x53\x63" \
                "\x39\x02\x05\xB4\x35\x01\x01\x3C" \
                "\x17\x46\x72\x65\x65\x42\x53\x44" \
                "\x3A\x61\x6D\x64\x36\x34\x3A\x37" \
                "\x2D\x43\x55\x52\x52\x45\x4E\x54" \
                "\xFF\x00\x00\x00"

        self.assertEqual(expected, gotttted, "test encoding")

    def test_dhcpv4_decode(self):
        """This test reads from a pre-stored pcap file."""
        file = PcapConnector("dhcp_minimal.pcap")
        packet = file.readpkt()

        chain = packet.chain()
        #print chain

        ether = chain.packets[0]
        assert (ether != None)

        ip = chain.packets[1]
        assert (ip != None)

        udp = chain.packets[2]
        assert (udp != None)

        dhcp = chain.packets[3]
        assert (dhcp != None)

        self.assertEqual(dhcp.op, 1, "op not equal")
        self.assertEqual(dhcp.xid, 0xffff0001, "xid not equal")
        self.assertEqual(dhcp.secs, 42848, "secs not equal")
        self.assertEqual(dhcp.flags, 0x8000, "flags not equal")
        mac = ether_atob("52:54:00:12:34:56")
        #print ether_btoa(dhcp.chaddr)
        self.assertEqual(dhcp.chaddr[:dhcp.hlen], mac, "mac not equal")

        self.assertEqual(len(dhcp.options), 6, "wrong option field count %d should be %d"  % (len(dhcp.options), 6))
        # Not a tlv field
        self.assertEqual(dhcp.options[0], pcs.packets.dhcpv4_options.DHCP_OPTIONS_COOKIE, "invalid cookie value")

        # TLV fields
        self.assertEqual(dhcp.options[1].value, 1460, "invalid maximum message size value")
        self.assertEqual(dhcp.options[2].value, "FreeBSD:i386:6.3-RELEASE", \
                                                "invalid vendor class")
        self.assertEqual(dhcp.options[3].value, pcs.packets.dhcpv4_options.DHCPDISCOVER, "invalud dhcp message type")

        # Not a tlv field
        self.assertEqual(dhcp.options[4], pcs.packets.dhcpv4_options.DHO_END, "invalid end value")

if __name__ == '__main__':
    unittest.main()
