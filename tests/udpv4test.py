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

#     def test_udpv4_read(self):
#         """This test reads from a pre-stored pcap file generated with tcpdump and ping on the loopback interface."""
#         import pcs.pcap as pcap
#         file = pcap.pcap("loopping.out")
#         packet = file.next()[1]
#         udp = udpv4(packet[file.dloff:len(packet)])
#         assert (udp != None)

#         self.assertEqual(udp.version, 4,
#                          "version not equal %d" % udp.version)
#         self.assertEqual(udp.hlen, 5, "hlen not equal %d" % udp.hlen)
#         self.assertEqual(udp.tos, 0, "tos not equal %d" % udp.tos)
#         self.assertEqual(udp.length, 84, "length not equal %d" % udp.length)
#         self.assertEqual(udp.id, 59067, "id not equal %d" % udp.id)
#         self.assertEqual(udp.flags, 0, "flags not equal %d" % udp.flags)
#         self.assertEqual(udp.offset, 0, "offset not equal %d" % udp.offset)
#         self.assertEqual(udp.ttl, 64, "ttl not equal %d" % udp.ttl)
#         self.assertEqual(udp.protocol, 1,
#                          "protocol not equal %d" % udp.protocol)
#         self.assertEqual(udp.src, 2130706433, "src not equal %d" % udp.src)
#         self.assertEqual(udp.dst, 2130706433, "dst not equal %d" % udp.dst)

#     def test_udpv4_compare(self):
#         """Test the underlying __compare__ functionality of the
#         packet.  Two packets constructed from the same bytes should be
#         equal and two that are not should not be equal."""
#         import pcs.pcap as pcap
#         file = pcap.pcap("loopping.out")
#         packet = file.next()[1]
#         udp1 = udpv4(packet[file.dloff:len(packet)])
#         udp2 = udpv4(packet[file.dloff:len(packet)])
#         assert (udp1 != None)
#         assert (udp2 != None)
#         self.assertEqual(udp1, udp2, "packets should be equal but are not")

#         udp1.dst = 0xffffffff
#         self.assertNotEqual(udp1, udp2, "packets compare equal but should not")
        
#     def test_udpv4_print(self):
#         """This test reads from a pre-stored pcap file generated with
#         tcpdump and ping on the loopback interface and tests the
#         __str__ method to make sure the correct values are printed."""
#         import pcs.pcap as pcap
#         file = pcap.pcap("loopping.out")
#         packet = file.next()[1]
#         udp = udpv4(packet[file.dloff:len(packet)])
#         assert (udp != None)

#         test_string = "version 4\nhlen 5\ntos 0\nlength 84\nid 59067\nflags 0\noffset 0\nttl 64\nprotocol 1\nchecksum 0\nsrc 2130706433\ndst 2130706433\n"

#         string = udp.__str__()

#         self.assertEqual(string, test_string,
#                          "strings are not equal \nexpected %s \ngot %s " %
#                          (test_string, string))


if __name__ == '__main__':
    unittest.main()

