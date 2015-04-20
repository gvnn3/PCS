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
# File: $Id: udpv4test.py,v 1.2 2005/11/11 00:22:07 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: This module performs a self test on an UDPv4 packet.  That
# is to say it first encodes a packet, then decodes is and makes sure
# that the data matches.

import unittest

import sys

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.

    from pcs.packets.ethernet import *
    from pcs.packets.ipv4 import *
    from pcs.packets.udp import *
    #from pcs.packets.udpv4 import *

class udpTestCase(unittest.TestCase):
    def test_udpv4(self):
        # create one packet, copy its pdata, then compare their fields
        packet = udp()
        assert (packet != None)
        packet.sport = 67
        packet.dport = 68
        packet.length = 64
        packet.checksum = 0
        
        # Create a packet to compare against
        new_packet = udp()
        new_packet.decode(packet.pdata)

        self.assertEqual(packet.pdata, new_packet.pdata, "pdata not equal")
        for field in packet._fieldnames:
            self.assertEqual(getattr(packet, field), getattr(new_packet, field), ("%s not equal" % field))

    def test_udpv4_read(self):
        """This test reads from a pre-stored pcap file generated with tcpdump and ping on the loopback interface."""
        file = pcs.PcapConnector("dns.out")
        packet = file.readpkt()

        packet = packet.data.data
        assert (packet != None)

        self.assertEqual(packet.sport, 50942, 
                         "sport not equal exptected: %d got: %d " %
                         (50942, packet.sport))
        self.assertEqual(packet.dport, 53, 
                         "dport not equal exptected: %d got: %d " %
                         (53, packet.dport))
        self.assertEqual(packet.length, 62, 
                         "length not equal exptected: %d got: %d " %
                         (62, packet.length))
        self.assertEqual(packet.checksum, 46791,
                         "checksum not equal exptected: %d got: %d " %
                         (46791, packet.checksum))

    def test_udpv4_compare(self):
        """Test the underlying __compare__ functionality of the
        packet.  Two packets constructed from the same pdata should be
        equal and two that are not should not be equal."""
        file = pcs.PcapConnector("dns.out")
        packet = file.readpkt()
        ip = packet.data
        assert (ip != None)
        packet1 = udp(ip.data.pdata)
        packet2 = udp(ip.data.pdata)
        assert (packet1 != None)
        assert (packet2 != None)
        self.assertEqual(packet1, packet2, "packets should be equal but are not")

        packet1.dport = 0xffff
        self.assertNotEqual(packet1, packet2, "packets compare equal but should not\ngot %sexpect %s" % (packet1, packet2))
        
    def test_udpv4_print(self):
        """This test reads from a pre-stored pcap file generated with
        tcpdump and ping on the loopback interface and tests the
        __str__ method to make sure the correct values are printed."""
        file = pcs.PcapConnector("dns.out")
        packet = file.readpkt()
        ip = packet.data
        assert (ip != None)

        test_string = "UDP\nsport 50942\ndport 53\nlength 62\nchecksum 46791\n"

        packet = ip.data
        string = packet.__str__()

        self.assertEqual(string, test_string,
                         "strings are not equal \nexpected %s \ngot %s " %
                         (test_string, string))

    def test_udpv4_raw(self):
        # Create a packet for raw injection and verify it meets criteria.
        from pcs import inet_atol
        from pcs.packets.payload import payload

        c = ethernet(src=b"\x01\x02\x03\x04\x05\x06",		\
                     dst=b"\xff\xff\xff\xff\xff\xff") /		\
            ipv4(src=inet_atol("192.168.123.17"),		\
                 dst=inet_atol("192.0.2.2"), id=5235) /		\
            udp(sport=67, dport=68) /				\
            payload(b"foobar\n")

        c.calc_lengths()
        c.calc_checksums()
        c.encode()

        expected = \
        b"\xFF\xFF\xFF\xFF\xFF\xFF\x01\x02" \
        b"\x03\x04\x05\x06\x08\x00\x45\x00" \
        b"\x00\x23\x14\x73\x00\x00\x40\x11" \
        b"\x68\x9B\xC0\xA8\x7B\x11\xC0\x00" \
        b"\x02\x02\x00\x43\x00\x44\x00\x0F" \
        b"\xC0\x48\x66\x6F\x6F\x62\x61\x72" \
        b"\x0A"

        gotttted = c.pdata
        self.assertEqual(expected, gotttted, "test raw encoding")

if __name__ == '__main__':
    unittest.main()

