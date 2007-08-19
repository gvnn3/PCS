# Copyright (c) 2005, Neville-Neil Consulting
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
# File: $Id: ipv6test.py,v 1.4 2006/08/01 13:35:58 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: This module performs a self test on the IPv6 packet.
# That is to say it first encodes a packet, then decodes it and makes
# sure that the data matches.

import unittest

import sys

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.
    from pcs import PcapConnector
    from pcs.packets.ipv6 import *
    from socket import AF_INET6, inet_pton

class ip6TestCase(unittest.TestCase):
    def test_ipv6(self):
        # create one packet, copy its bytes, then compare their fields
        ip = ipv6()
        assert (ip != None)
        ip.traffic_class = 1
        ip.flow = 0
        ip.length = 64
        ip.next_header = 6
        ip.hop = 64
        ip.src = inet_pton(AF_INET6, "::1")
        ip.dst = inet_pton(AF_INET6, "::1")

        # Create a packet to compare against
        ipnew = ipv6()
        ipnew.decode(ip.bytes)

        self.assertEqual(ip.bytes, ipnew.bytes, "bytes not equal")
        for field in ip._fieldnames:
            self.assertEqual(getattr(ip, field), getattr(ipnew, field), ("%s not equal" % field))

    def test_ipv6_read(self):
        """This test reads from a pre-stored pcap file generated with tcpdump and ping on the loopback interface."""
        file = PcapConnector("loopping6.out")
        packet = file.read()
        ip = ipv6(packet[file.dloff:len(packet)])
        assert (ip != None)

        self.assertEqual(ip.version, 6,
                         "version not equal %d" % ip.version)
        self.assertEqual(ip.traffic_class, 0,
                         "traffic_class not equal %d" % ip.traffic_class)
        self.assertEqual(ip.flow, 0, "flow not equal %d" % ip.flow)
        self.assertEqual(ip.length, 16, "length not equal %d" % ip.length)
        self.assertEqual(ip.next_header, 58,
                         "next_header not equal %d" % ip.next_header)
        self.assertEqual(ip.hop, 64, "hop not equal %d" % ip.hop)
        self.assertEqual(ip.src, inet_pton(AF_INET6, "::1"),
                         "src not equal %s" % ip.src)
        self.assertEqual(ip.dst, inet_pton(AF_INET6, "::1"),
                         "dst not equal %s" % ip.dst)

    def test_ipv6_compare(self):
        """Test the underlying __compare__ functionality of the
        packet.  Two packets constructed from the same bytes should be
        equal and two that are not should not be equal."""
        file = PcapConnector("loopping6.out")
        packet = file.read()
        ip1 = ipv6(packet[file.dloff:len(packet)])
        ip2 = ipv6(packet[file.dloff:len(packet)])
        assert (ip1 != None)
        assert (ip2 != None)
        self.assertEqual(ip1, ip2, "packets should be equal but are not")

        ip1.dst = inet_pton(AF_INET6, "2001:ffff::1");


        self.assertNotEqual(ip1, ip2, "packets compare equal but should not")
        
    def test_ipv6_print(self):
        """This test reads from a pre-stored pcap file generated with
        tcpdump and ping on the loopback interface and tests the
        __str__ method to make sure the correct values are printed."""
        file = PcapConnector("loopping6.out")
        packet = file.read()
        ip = ipv6(packet[file.dloff:len(packet)])
        assert (ip != None)

        test_string = "version 6\ntraffic_class 0\nflow 0\nlength 16\nnext_header 58\nhop 64\nsrc ::1\ndst ::1\n"

        string = ip.__str__()

        self.assertEqual(string, test_string,
                         "strings are not equal \nexpected %s \ngot %s " %
                         (test_string, string))

    def test_ipv6_println(self):
        """This test reads from a pre-stored pcap file generated with
        tcpdump and ping on the loopback interface and tests the
        __str__ method to make sure the correct values are printed."""
        file = PcapConnector("loopping6.out")
        packet = file.read()
        ip = ipv6(packet[file.dloff:len(packet)])
        assert (ip != None)

        test_string = "<IPv6: version: 6, traffic_class: 0, flow: 0, length: 16, next_header: 58, hop: 64, src: \'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\', dst: \'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\'>"

        string = ip.println()

        self.assertEqual(string, test_string,
                         "strings are not equal \nexpected %s \ngot %s " %
                         (test_string, string))


if __name__ == '__main__':
    unittest.main()

