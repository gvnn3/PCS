#!/usr/bin/env python
# Copyright (c) 2006, Neville-Neil Consulting
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
# Neither the name of Neville-Neil Consulting nor the names of its 
# contributors may be used to endorse or promote products derived from 
# this software without specific prior written permission.
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
# File: $Id: icmpv4test.py,v 1.8 2006/09/05 07:30:56 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: This module performs a self test on the IPv4 packet.
# That is to say it first encodes a packet, then decodes it and makes
# sure that the data matches.

import unittest

import sys
sys.path.insert(0, "..") # Look locally first
   
from pcs.packets.localhost import *
from pcs.packets.ipv4 import *
from pcs.packets.icmpv4 import *
from pcs import *

class icmpTestCase(unittest.TestCase):
    def test_icmpv4(self):
        # create one packet, copy its bytes, then compare their fields
        icmp = icmpv4()
        assert (icmp != None)
        icmp.type = 8
        icmp.code = 0
        # Create a packet to compare against
        icmpnew = icmpv4()
        icmpnew.decode(icmp.bytes)

        self.assertEqual(icmp.bytes, icmpnew.bytes, "bytes not equal")
        self.assertEqual(icmpnew.type, 8, "type not equal %d" % icmp.type)
        self.assertEqual(icmpnew.code, 0, "code not equal %d" % icmp.code)

    def test_icmpv4_read(self):
        """This test reads from a pre-stored pcap file generated with tcpdump and ping on the loopback interface."""
        file = PcapConnector("loopping.out")
        packet = file.read()
        ip = ipv4(packet[file.dloff:len(packet)])
        assert (ip != None)

        icmp = ip.data

        self.assertEqual(icmp.type, 8, "type not equal to 8")
        self.assertEqual(icmp.code, 0, "code not equal to 0")

    def test_icmpv4_compare(self):
        """Test the underlying __compare__ functionality of the
        packet.  Two packets constructed from the same bytes should be
        equal and two that are not should not be equal."""
        file = PcapConnector("loopping.out")
        packet = file.read()
        ip1 = ipv4(packet[file.dloff:len(packet)])
        ip2 = ipv4(packet[file.dloff:len(packet)])
        assert (ip1 != None)
        assert (ip2 != None)
        icmp1 = ip1.data
        icmp2 = ip2.data
        self.assertEqual(icmp1, icmp2, "packets should be equal but are not")

        icmp1.code = 32
        self.assertNotEqual(icmp1, icmp2,
                            "packets compare equal but should not")
        
    def test_icmpv4_print(self):
        """This test reads from a pre-stored pcap file generated with
        tcpdump and ping on the loopback interface and tests the
        __str__ method to make sure the correct values are printed."""
        file = PcapConnector("loopping.out")
        packet = file.read()
        ip = ipv4(packet[file.dloff:len(packet)])
        assert (ip != None)

        icmp = ip.data
        
        test_string = "ICMPv4\ntype 8\ncode 0\nchecksum 60550\n"

        string = icmp.__str__()

        self.assertEqual(string, test_string,
                         "strings are not equal \nexpected %s \ngot %s " %
                         (test_string, string))

    def test_icmpv4_ping(self):
        ip = ipv4()
        ip.version = 4
        ip.hlen = 5
        ip.tos = 0
        ip.length = 84
        ip.id = 1234
        ip.flags = 0
        ip.offset = 0
        ip.ttl = 64
        ip.protocol = IPPROTO_ICMP
        ip.src = inet_atol("127.0.0.1")
        ip.dst = inet_atol("127.0.0.1")

        icmp = icmpv4()
        icmp.type = 8
        icmp.code = 0
        icmp.cksum = 0
        
        echo = icmpv4echo()
        echo.id = 37123
        echo.sequence = 0

        lo = localhost()
        lo.type = 2
        packet = Chain([lo, ip, icmp, echo])
        
        ip.checksum = 0

        icmp_packet = Chain([icmp, echo])
        icmp.checksum = icmp_packet.calc_checksum()

        packet.encode()

        input = PcapConnector("lo0")
        input.setfilter("icmp")

        output = PcapConnector("lo0")
        assert (ip != None)

        out = output.write(packet.bytes, 88)
        assert (out == 88)

if __name__ == '__main__':
    unittest.main()

