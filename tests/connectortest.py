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
# File: $Id: connectortest.py,v 1.2 2006/08/01 13:35:58 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: This module performs a self test on the Connector classes
# provided with PCS.

import unittest

import sys
   
from socket import *

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.

    from pcs.packets.ethernet import ethernet
    from pcs.packets.localhost import localhost
    from pcs.packets.ipv4 import ipv4
    from pcs.packets.icmpv4 import icmpv4
    from pcs.packets.icmpv4 import icmpv4echo
    
    from pcs import *

class pcapTestCase(unittest.TestCase):
    def test_pcap_file(self):
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

    def test_pcap_live(self):
        """Test live injection and reception.

        This test requires threads and must be run as root to succeed."""
        import threading

        e = ethernet()
        assert (e != None)
        e.src = "\x00\xbd\x03\x07\xfa\x00"
        e.dst = "\x00\xbd\x03\x07\xfa\x00"
        e.type = 0x0800

        # Create a vanilla ping packet
        ip = ipv4()

        ip.version = 4
        ip.hlen = 5
        ip.tos = 0
        ip.length = 64
        ip.id = 1
        ip.flags = 0
        ip.offset = 0
        ip.ttl = 64
        ip.protocol = IPPROTO_ICMP
        ip.src = inet_atol("192.0.2.1")
        ip.dst = inet_atol("192.0.2.1")
        
        icmp = icmpv4()
        icmp.type = 8
        icmp.code = 0
        
        echo = icmpv4echo()
        echo.id = 54321
        echo.seq = 12345

        ip.length = len(ip.pdata) + len(icmp.pdata) + len(echo.pdata)

        packet = Chain([e, ip, icmp, echo])

        packet.calc_checksums()
        packet.encode()

        import os
        uname = os.uname()[0]
        if uname == "FreeBSD":
            devname = "edsc0"
        elif uname == "Linux":
            devname = "lo"
        elif uname == "Darwin":
            devname = "en0"
        else:
            print("unknown host os %s" % uname)
            return

        wfile = PcapConnector(devname)
        rfile = PcapConnector(devname)
        rfile.setfilter("icmp")

        count = wfile.write(packet.pdata, 42)
        assert (count == 42)

        got = ethernet(rfile.read())
        ip = got.data
        ping = ip.data

        self.assertEqual(ping, icmp)

    def test_pcap_write(self):
        """Test the underlying __compare__ functionality of the
        packet.  Two packets constructed from the same bytes should be
        equal and two that are not should not be equal."""
        from pcs.pcap import DLT_NULL
        # Create a vanilla ping packet
        ip = ipv4()

        ip.version = 4
        ip.hlen = 5
        ip.tos = 0
        ip.length = 64
        ip.id = 1
        ip.flags = 0
        ip.offset = 0
        ip.ttl = 64
        ip.protocol = IPPROTO_ICMP
        ip.src = inet_atol("127.0.0.1")
        ip.dst = inet_atol("127.0.0.1")
        
        icmp = icmpv4()
        icmp.type = 8
        icmp.code = 0
        
        echo = icmpv4echo()
        echo.id = 32767
        echo.seq = 1
        
        lo = localhost()
        lo.type = 2

        packet = Chain([lo, ip, icmp, echo])

        outfile = PcapDumpConnector("pcaptest.dump", DLT_NULL)
        outfile.write(packet.pdata)
        outfile.close()
        
        infile = PcapConnector("pcaptest.dump")
        packet = infile.read()
        ipnew = ipv4(packet[infile.dloff:len(packet)])
        assert (ip != None)
        assert (ipnew != None)
        self.assertEqual(ip, ipnew, "packets should be equal but are not")

if __name__ == '__main__':
    unittest.main()

