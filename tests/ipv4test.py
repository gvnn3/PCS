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
# File: $Id: ipv4test.py,v 1.6 2006/08/01 13:35:58 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: This module performs a self test on the IPv4 packet.
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
    from pcs.packets.ipv4 import *
    from pcs import inet_atol

class ipTestCase(unittest.TestCase):
    def test_ipv4(self):
        # create one packet, copy its bytes, then compare their fields
        ip = ipv4()
        assert (ip != None)
        ip.version = 4
        ip.hlen = 5
        ip.tos = 0
        ip.length = 64
        ip.id = 1
        ip.flags = 1
        ip.offset = 2
        ip.ttl = 33
        ip.protocol = 6
        ip.src = 2130706433
        ip.dst = 2130706433

        # Create a packet to compare against
        ipnew = ipv4()
        ipnew.decode(ip.bytes)

        self.assertEqual(ip.bytes, ipnew.bytes, "bytes not equal")
        self.assertEqual(ipnew.version, 4,
                         "version not equal %d" % ipnew.version)
        self.assertEqual(ipnew.hlen, 5, "hlen not equal %d" % ipnew.hlen)
        self.assertEqual(ipnew.tos, 0, "tos not equal %d" % ipnew.tos)
        self.assertEqual(ipnew.length, 64, "length not equal %d" % ipnew.length)
        self.assertEqual(ipnew.id, 1, "id not equal %d" % ipnew.id)
        self.assertEqual(ipnew.flags, 1, "flags not equal %d" % ipnew.flags)
        self.assertEqual(ipnew.offset, 2, "offset not equal %d" % ipnew.offset)
        self.assertEqual(ipnew.ttl, 33, "ttl not equal %d" % ipnew.ttl)
        self.assertEqual(ipnew.protocol, 6,
                         "protocol not equal %d" % ipnew.protocol)
        self.assertEqual(ipnew.src, 2130706433, "src not equal %d" % ipnew.src)
        self.assertEqual(ipnew.dst, 2130706433, "dst not equal %d" % ipnew.dst)

    def test_ipv4_read(self):
        """This test reads from a pre-stored pcap file generated with tcpdump and ping on the loopback interface."""
        file = PcapConnector("loopping.out")
        packet = file.read()
        ip = ipv4(packet[file.dloff:len(packet)])
        assert (ip != None)

        self.assertEqual(ip.version, 4,
                         "version not equal %d" % ip.version)
        self.assertEqual(ip.hlen, 5, "hlen not equal %d" % ip.hlen)
        self.assertEqual(ip.tos, 0, "tos not equal %d" % ip.tos)
        self.assertEqual(ip.length, 84, "length not equal %d" % ip.length)
        self.assertEqual(ip.id, 59067, "id not equal %d" % ip.id)
        self.assertEqual(ip.flags, 0, "flags not equal %d" % ip.flags)
        self.assertEqual(ip.offset, 0, "offset not equal %d" % ip.offset)
        self.assertEqual(ip.ttl, 64, "ttl not equal %d" % ip.ttl)
        self.assertEqual(ip.protocol, 1,
                         "protocol not equal %d" % ip.protocol)
        self.assertEqual(ip.src, inet_atol("127.0.0.1"),
                         "src not equal %d" % ip.src)
        self.assertEqual(ip.dst, inet_atol("127.0.0.1"),
                         "dst not equal %d" % ip.dst)

    def test_ipv4_compare(self):
        """Test the underlying __compare__ functionality of the
        packet.  Two packets constructed from the same bytes should be
        equal and two that are not should not be equal."""
        file = PcapConnector("loopping.out")
        packet = file.read()
        ip1 = ipv4(packet[file.dloff:len(packet)])
        ip2 = ipv4(packet[file.dloff:len(packet)])
        assert (ip1 != None)
        assert (ip2 != None)
        self.assertEqual(ip1, ip2, "packets should be equal but are not")

        ip1.dst = 0xffffffff
        self.assertNotEqual(ip1, ip2, "packets compare equal but should not")
        
    def test_ipv4_print(self):
        """This test reads from a pre-stored pcap file generated with
        tcpdump and ping on the loopback interface and tests the
        __str__ method to make sure the correct values are printed."""
        file = PcapConnector("loopping.out")
        packet = file.read()
        ip = ipv4(packet[file.dloff:len(packet)])
        assert (ip != None)

        test_string = "IPv4\nversion 4\nhlen 5\ntos 0\nlength 84\nid 59067\nflags 0\noffset 0\nttl 64\nprotocol 1\nchecksum 0\nsrc 127.0.0.1\ndst 127.0.0.1\n"

        string = ip.__str__()

        self.assertEqual(string, test_string,
                         "strings are not equal \nexpected %s \ngot %s " %
                         (test_string, string))

    def test_ipv4_println(self):
        """This test reads from a pre-stored pcap file generated with
        tcpdump and ping on the loopback interface and tests the
        __str__ method to make sure the correct values are printed."""
        file = PcapConnector("loopping.out")
        packet = file.read()
        ip = ipv4(packet[file.dloff:len(packet)])
        assert (ip != None)

        test_string = "<IPv4: version: 4, hlen: 5, tos: 0, length: 84, id: 59067, flags: 0, offset: 0, ttl: 64, protocol: 1, checksum: 0, src: 2130706433, dst: 2130706433>"

        string = ip.println()

        self.assertEqual(string, test_string,
                         "strings are not equal \nexpected %s \ngot %s " %
                         (test_string, string))



if __name__ == '__main__':
    unittest.main()

