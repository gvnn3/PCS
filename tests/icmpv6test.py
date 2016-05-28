#!/usr/bin/env python
# Copyright (c) 2016, Neville-Neil Consulting
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
# Author: George V. Neville-Neil
#
# Description: This module performs a self test on the ICMPv6 packet.
# That is to say it first encodes a packet, then decodes it and makes
# sure that the data matches.

import unittest

import sys
   
if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues

    from pcs.packets.ethernet import ethernet
    from pcs.packets.ipv6 import *
    from pcs.packets.icmpv6 import *
    from pcs import *

class icmpTestCase(unittest.TestCase):
    def test_icmpv6(self):
        # create one packet, copy its bytes, then compare their fields
        icmp = icmpv6()
        assert (icmp != None)
        icmp.type = ICMP6_ECHO_REQUEST
        icmp.code = 0
        # Create a packet to compare against
        icmpnew = icmpv6()
        icmpnew.decode(icmp.bytes)

        self.assertEqual(icmp.bytes, icmpnew.bytes, "bytes not equal")
        self.assertEqual(icmpnew.type, ICMP6_ECHO_REQUEST,
                         "type not equal %d" % icmp.type)
        self.assertEqual(icmpnew.code, 0, "code not equal %d" % icmp.code)

    def test_icmpv6_read(self):
        """This test reads from a pre-stored pcap file generated with tcpdump and ping on the loopback interface."""
        file = PcapConnector("loopping6.out")
        packet = file.read()
        ip = ipv6(packet[file.dloff:len(packet)])
        assert (ip != None)

        icmp = ip.data

        self.assertEqual(icmp.type, ICMP6_ECHO_REQUEST,
                         "type not equal to %d" % icmp.type)
        self.assertEqual(icmp.code, 0, "code not equal to 0")

    def test_icmpv6_compare(self):
        """Test the underlying __compare__ functionality of the
        packet.  Two packets constructed from the same bytes should be
        equal and two that are not should not be equal."""
        file = PcapConnector("loopping6.out")
        packet = file.read()
        ip1 = ipv6(packet[file.dloff:len(packet)])
        ip2 = ipv6(packet[file.dloff:len(packet)])
        assert (ip1 != None)
        assert (ip2 != None)
        icmp1 = ip1.data
        icmp2 = ip2.data
        self.assertEqual(icmp1, icmp2, "packets should be equal but are not")

        icmp1.code = 32
        self.assertNotEqual(icmp1, icmp2,
                            "packets compare equal but should not")
        
    def test_icmpv6_print(self):
        """This test reads from a pre-stored pcap file generated with
        tcpdump and ping on the loopback interface and tests the
        __str__ method to make sure the correct values are printed."""
        file = PcapConnector("loopping6.out")
        packet = file.read()
        ip = ipv6(packet[file.dloff:len(packet)])
        assert (ip != None)

        icmp = ip.data
        
        #test_string = "ICMPv6\ntype 8\ncode 0\nchecksum 60550\n"
        test_string = "ICMPv6 Echo Request\ntype 128\ncode 0\nchecksum 60454\n"

        string = icmp.__str__()

        self.assertEqual(string, test_string,
                         "strings are not equal \nexpected %s \ngot %s " %
                         (test_string, string))

    def test_icmpv6_ping(self):
	import os
	uname = os.uname()[0]
	if uname == "FreeBSD":
	    devname = "edsc0"
	elif uname == "Linux":
	    devname = "lo"
        elif uname == "Darwin":
            devname = "en0"
	else:
	    print "unknown host os %s" % uname
	    return

	e = ethernet()
	e.type = 0x0800
        e.src = "\x00\x00\x00\x00\x00\x00"
        e.dst = "\xff\xff\xff\xff\xff\xff"
        e.type = 0x0800

        ip = ipv6()
        ip.traffic_class = 1
        ip.flow = 0
        ip.length = 64
        ip.next_header = IPV6_ICMP
        ip.hop = 64
        ip.src = inet_pton(AF_INET6, "::1")
        ip.dst = inet_pton(AF_INET6, "::1")

        icmp = icmpv6()
        icmp.type = 128
        icmp.code = 0
        icmp.cksum = 0
        
	ip.len = len(ip.bytes) + len(icmp.bytes)

        packet = Chain([e, ip, icmp])

        packet.calc_checksums()
        packet.encode()

        input = PcapConnector(devname)
        input.setfilter("icmp6")

        output = PcapConnector(devname)
        assert (ip != None)

	# XXX The use of IP triggers a bpf header format bug if used
	# with loopback device on FreeBSD, so we use edsc(4) there.

        n_out = output.write(packet.bytes, 42)
        assert (n_out == 42)

	packet_in = input.read()
	assert (n_out == len(packet_in))

if __name__ == '__main__':
    unittest.main()

