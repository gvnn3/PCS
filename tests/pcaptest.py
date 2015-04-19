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

import time
import sys

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.

    from pcs import PcapConnector
    from pcs import PcapDumpConnector
    from pcs.packets.ethernet import *

class pcapTestCase(unittest.TestCase):
    def test_pcap_read(self):
        """This test reads from a pre-stored pcap file generated with tcpdump and ping on the loopback interface."""
        file = PcapConnector("etherping.out")
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
        file = PcapDumpConnector("pcapdump.out", DLT_EN10MB)
        # create one packet, copy its pdata, then compare their fields
        ether = ethernet()
        assert (ethernet != None)
        ether.src = "\x00\x00\x00\x00\x00\x00"
        ether.dst = "\xff\xff\xff\xff\xff\xff"
        ether.type = 2048
        file.write(ether.pdata)

    def test_ethernet_dump(self):
        """This test dumps a fake ethernet packet, with timetamp, to a
        dump file."""
        from pcs.pcap import DLT_EN10MB
        file = PcapDumpConnector("pcapdump2.out", DLT_EN10MB)
        # create one packet, copy its pdata, then compare their fields
        ether = ethernet()
        assert (ethernet != None)
        ether.src = "\x00\x00\x00\x00\x00\x00"
        ether.dst = "\xff\xff\xff\xff\xff\xff"
        ether.type = 2048
        class header:
            sec = 0
            usec = 0
            caplen = 0
        
        header.sec = 69
        header.usec = 69
        header.caplen = len(ether.pdata)
        file.sendto(ether.pdata, header)
        file.close()
        # Re read what we just wrote.
        file = PcapConnector("pcapdump2.out", DLT_EN10MB)        
        ether = file.readpkt()
        assert(ether.timestamp == 69.000069) 

if __name__ == '__main__':
    unittest.main()

