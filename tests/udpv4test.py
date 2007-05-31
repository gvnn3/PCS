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
#sys.path.insert(0, "..") # Look locally first.

from pcs.packets.ipv4 import *
from pcs.packets.udpv4 import *

class udpTestCase(unittest.TestCase):
    def test_udpv4(self):
        # create one packet, copy its bytes, then compare their fields
        udp = udpv4()
        assert (udp != None)
        udp.sport = 67
        udp.dport = 68
        udp.length = 64
        udp.checksum = 0
        
        # Create a packet to compare against
        udpnew = udpv4()
        udpnew.decode(udp.bytes)

        self.assertEqual(udp.bytes, udpnew.bytes, "bytes not equal")
        self.assertEqual(udpnew.sport, 67,
                         "sport not equal %d" % udpnew.sport)
        self.assertEqual(udpnew.dport, 68, "dport not equal %d" % udpnew.dport)
        self.assertEqual(udpnew.length, 64, "length not equal %d" % udpnew.length)
        self.assertEqual(udpnew.checksum, 0, "checksum not equal %d" %
                         udpnew.checksum)

    def test_udpv4_read(self):
        """This test reads from a pre-stored pcap file generated with tcpdump and ping on the loopback interface."""
        import pcs.pcap as pcap
        file = pcap.pcap("dns.out")
        packet = file.next()[1]
        ip = ipv4(packet[file.dloff:len(packet)])
        udp = udpv4(ip.data.bytes)
        assert (udp != None)

        self.assertEqual(udp.sport, 50942, 
                         "sport not equal exptected: %d got: %d " %
                         (50942, udp.sport))
        self.assertEqual(udp.dport, 53, 
                         "dport not equal exptected: %d got: %d " %
                         (53, udp.dport))
        self.assertEqual(udp.length, 62, 
                         "length not equal exptected: %d got: %d " %
                         (62, udp.length))
        self.assertEqual(udp.checksum, 46791,
                         "checksum not equal exptected: %d got: %d " %
                         (46791, udp.checksum))

    def test_udpv4_compare(self):
        """Test the underlying __compare__ functionality of the
        packet.  Two packets constructed from the same bytes should be
        equal and two that are not should not be equal."""
        import pcs.pcap as pcap
        file = pcap.pcap("loopping.out")
        packet = file.next()[1]
        ip = ipv4(packet[file.dloff:len(packet)])
        assert (ip != None)
        udp1 = udpv4(ip.data.bytes)
        udp2 = udpv4(ip.data.bytes)
        assert (udp1 != None)
        assert (udp2 != None)
        self.assertEqual(udp1, udp2, "packets should be equal but are not")

        udp1.dport = 0xffff
        self.assertNotEqual(udp1, udp2, "packets compare equal but should not\ngot %sexpect %s" % (udp1, udp2))
        
    def test_udpv4_print(self):
        """This test reads from a pre-stored pcap file generated with
        tcpdump and ping on the loopback interface and tests the
        __str__ method to make sure the correct values are printed."""
        import pcs.pcap as pcap
        file = pcap.pcap("dns.out")
        packet = file.next()[1]
        ip = ipv4(packet[file.dloff:len(packet)])
        assert (ip != None)

        test_string = "UDP\nsport 50942\ndport 53\nlength 62\nchecksum 46791\n"

        udpv4 = ip.data
        string = udpv4.__str__()

        self.assertEqual(string, test_string,
                         "strings are not equal \nexpected %s \ngot %s " %
                         (test_string, string))

if __name__ == '__main__':
    unittest.main()

