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
# File: $Id: ethertest.py,v 1.7 2006/07/13 10:05:40 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: This module performs a self test on an IP packet.  That
# is to say it first encodes a packet, then decodes is and makes sure
# that the data matches.

import unittest

import sys

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.

    from pcs import PcapConnector
    from pcs import PcapDumpConnector
    from pcs.packets.ethernet import *

class etherTestCase(unittest.TestCase):
    def test_ethernet(self):
        # create one packet, copy its bytes, then compare their fields
        ether = ethernet()
        assert (ethernet != None)
        ether.src = b"\x00\x00\x00\x00\x00\x00"
        ether.dst = b"\xff\xff\xff\xff\xff\xff"
        ether.type = 2048

        # Create a packet to compare against
        ethernew = ethernet()
        ethernew.decode(ether.bytes)

        self.assertEqual(ether.bytes, ethernew.bytes, "bytes not equal")
        self.assertEqual(ether.src, ethernew.src,
                         "sources not equal ether %s ethernew %s" %
                         (ether.src, ethernew.src))
        self.assertEqual(ether.dst, ethernew.dst,
                         "destinations not equal ether %s ethernew %s" %
                         (ether.dst, ethernew.dst))
        self.assertEqual(ether.type, ethernew.type,
                         "types not equal ether %s ethernew %s" %
                         (ether.type, ethernew.type))

    def test_ethernet_eq(self):
        "Test whether the eq function works for ethernet"
        ether = ethernet()
        assert (ether != None)
        ether.src = b"\x00\x00\x00\x00\x00\x00"
        ether.dst = b"\xff\xff\xff\xff\xff\xff"
        ether.type = 2048

        # Create a packet to compare against
        ethernew = ethernet()
        ethernew.decode(ether.bytes)

        self.assertEqual(ether.bytes, ethernew.bytes, "bytes not equal")
        self.assertEqual(ether.src, ethernew.src,
                         "sources not equal ether %s ethernew %s" %
                         (ether.src, ethernew.src))
        self.assertEqual(ether.dst, ethernew.dst,
                         "destinations not equal ether %s ethernew %s" %
                         (ether.dst, ethernew.dst))
        self.assertEqual(ether.type, ethernew.type,
                         "types not equal ether %s ethernew %s" %
                         (ether.type, ethernew.type))
        
        self.assertEqual(ether, ethernew, "ether != to ethernew but should be")

    def test_ethernet_read(self):
        """This test reads from a pre-stored pcap file generated with tcpdump and ping on the loopback interface."""
        file = PcapConnector(b"etherping.out")
#        packet = file.read()
#        ether = ethernet(packet)
        ether = file.readpkt()
        assert (ether != None)
        self.assertEqual(ether.dst, "\x00\x10\xdb\x3a\x3a\x77",
                         "dst not equal %s" % ether.src)
        self.assertEqual(ether.src, "\x00\x0d\x93\x44\xfa\x62",
                         "src not equal %s" % ether.dst)
        self.assertEqual(ether.type, 0x800, "type not equal %d" % ether.type)


    def test_ethernet_write(self):
        """This test writes a fake ethernet packet to a dump file."""
        from pcs.pcap import DLT_EN10MB
        file = PcapDumpConnector(b"etherdump.out", DLT_EN10MB)
        # create one packet, copy its bytes, then compare their fields
        ether = ethernet()
        assert (ethernet != None)
        ether.src = b"\x00\x00\x00\x00\x00\x00"
        ether.dst = b"\xff\xff\xff\xff\xff\xff"
        ether.type = 2048
        file.write(ether.bytes)

    def test_ethernet_compare(self):
        """Test the underlying __compare__ functionality of the
        packet.  Two packets constructed from the same bytes should be
        equal and two that are not should not be equal."""
        file = PcapConnector(b"etherping.out")
        packet = file.read()
        ether1 = ethernet(packet[0:file.dloff])
        ether2 = ethernet(packet[0:file.dloff])
        assert (ether1 != None)
        assert (ether2 != None)
        self.assertEqual(ether1, ether2, "packets should be equal but are not")

        ether1.dst = b"\xff\xff\xff\xff\xff\xff"
        self.assertNotEqual(ether1, ether2, "packets compare equal but should not")
        
    def test_ethernet_print(self):
        """This test reads from a pre-stored pcap file generated with
        tcpdump and ping on an ethernet interface and tests the
        __str__ method to make sure the correct values are printed."""
        file = PcapConnector(b"etherping.out")
        packet = file.read()
        ether = ethernet(packet[0:file.dloff])
        assert (ether != None)

        test_string = "Ethernet\ndst: 0:10:db:3a:3a:77\nsrc: 0:d:93:44:fa:62\ntype: 0x800"

        string = ether.__str__()

        self.assertEqual(string, test_string,
                         "strings are not equal \nexpected %s \ngot %s " %
                         (test_string, string))

    def test_ethernet_println(self):
        """This test reads from a pre-stored pcap file generated with
        tcpdump and ping on an ethernet interface and tests the
        println method to make sure the correct values are printed."""
        file = PcapConnector(b"etherping.out")
        packet = file.read()
        ether = ethernet(packet[0:file.dloff])
        assert (ether != None)

        string = ether.println()

        test_string = "<Ethernet: dst: 0:10:db:3a:3a:77 src: 0:d:93:44:fa:62 type: 0x800>"

        self.assertEqual(string, test_string,
                         "strings are not equal \nexpected %s \ngot %s " %
                         (test_string, string))

if __name__ == '__main__':
    unittest.main()

