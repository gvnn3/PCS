# Copyright (c) 2005-2016, Neville-Neil Consulting
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
# File: $Id: tcpv4test.py,v 1.2 2006/08/01 13:35:58 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: This module performs a self test on the IPv4 packet.
# That is to say it first encodes a packet, then decodes it and makes
# sure that the data matches.

import unittest
import sys
from hexdumper import hexdumper

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.
 
    from pcs import PcapConnector
    from pcs.packets.ipv4 import *
    from pcs.packets.tcp import tcp
    from pcs import inet_atol

class tcpTestCase(unittest.TestCase):
    def test_tcpv4(self):
        """Create one packet, copy its bytes, then compare their fields"""
        tcppacket = tcp()
        assert (tcppacket != None)
        tcppacket.sport = 51
        tcppacket.dport = 50
        tcppacket.sequence = 42
        tcppacket.offset = 10
        tcppacket.urgent = 1
        tcppacket.ack = 1
        tcppacket.push = 1
        tcppacket.reset = 1
        tcppacket.syn = 1
        tcppacket.fin = 1
        tcppacket.window = 1024
        tcppacket.checksum = 0

        # Create a packet to compare against
        tcpnew = tcp()
        tcpnew.decode(tcppacket.bytes)

        self.assertEqual(tcppacket.bytes, tcpnew.bytes, "bytes not equal")
        for field in tcppacket._fieldnames:
            self.assertEqual(getattr(tcppacket, field), getattr(tcpnew, field), ("%s not equal" % field))

    def test_tcpv4_offset(self):
        """Test the computed data offset field of the packet, without options"""
        tcppacket = tcp()
        tcppacket.offset = 0
        tcppacket.calc_length()
        self.assertEqual(tcppacket.offset, 5)

    def test_tcpv4_offset_with_options(self):
        """Test the computed data offset field of the packet, with options"""
        tcppacket = tcp()
        tcppacket.offset = 0
        nop = pcs.Field("nop", 8)
        mss = pcs.TypeLengthValueField("mss",
                                       pcs.Field("t", 8, default = 0x02),
                                       pcs.Field("l", 8),
                                       pcs.Field("v", 16))
        end = pcs.Field("end", 8)

        nop.value = 1
        mss.value.value = 1460		# Most common Internet MSS value.

	# Build a TCP option list which will be 32-bits aligned.
        tcppacket.options.append(nop)
        tcppacket.options.append(nop)
        tcppacket.options.append(mss)
        tcppacket.options.append(nop)
        tcppacket.options.append(end)

        tcppacket.calc_length()
        self.assertEqual(tcppacket.offset, 7)

    def test_tcpv4_read(self):
        """This test reads from a pre-stored pcap file generated with tcpdump."""
        file = PcapConnector("wwwtcp.out")
        packet = file.read()
        ip = ipv4(packet[file.dloff:len(packet)])
        assert (ip != None)
        tcppacket = tcp(ip.data.bytes)

        self.assertEqual(tcppacket.sport, 53678, "source port not equal %d" % tcppacket.sport)
        self.assertEqual(tcppacket.dport, 80, "destination port not equal %d" %
                tcppacket.dport)
        self.assertEqual(tcppacket.sequence, 1351059655, "sequence number not equal %d" %
                tcppacket.sequence)
        self.assertEqual(tcppacket.ack_number, 0, "ack number not equal %d" %
                tcppacket.ack_number)
        self.assertEqual(tcppacket.offset, 11, "offset not equal %d" % tcppacket.offset)
        self.assertEqual(tcppacket.reserved, 0, "reserved not equal %d" % tcppacket.reserved)
        self.assertEqual(tcppacket.urgent, 0, "urgent not equal %d" % tcppacket.urgent)
        self.assertEqual(tcppacket.ack, 0, "ack not equal %d" % tcppacket.ack)
        self.assertEqual(tcppacket.push, 0, "push not equal %d" % tcppacket.push)
        self.assertEqual(tcppacket.reset, 0, "reset not equal %d" % tcppacket.reset)
        self.assertEqual(tcppacket.syn, 1, "syn not equal %d" % tcppacket.syn)
        self.assertEqual(tcppacket.fin, 0, "fin not equal %d" % tcppacket.fin)
        self.assertEqual(tcppacket.window, 65535, "window not equal %d" % tcppacket.window)
        self.assertEqual(tcppacket.checksum, 15295, "checksum not equal %d" %
                tcppacket.checksum)

    def test_tcpv4_compare(self):
        """Test the underlying __compare__ functionality of the
        packet.  Two packets constructed from the same bytes should be
        equal and two that are not should not be equal."""
        file = PcapConnector("wwwtcp.out")
        packet = file.read()
        ip = ipv4(packet[file.dloff:len(packet)])
        tcp1 = tcp(ip.data.bytes)
        tcp2 = tcp(ip.data.bytes)
        assert (tcp1 != None)
        assert (tcp2 != None)

	#hd = hexdumper()
	#print hd.dump(tcp1.bytes)
	#print hd.dump(tcp2.bytes)

	# tcp1 should not equal tcp2, they are different instances,
	# and will therefore have different timestamps -- unless
	# we end up racing the system clock.
        self.assertNotEqual(tcp1, tcp2,
			    "instances SHOULD be equal")

        self.assertEqual(tcp1.bytes, tcp2.bytes,
			 "packet data SHOULD be equal")
        tcp1.dport = 0
        self.assertNotEqual(tcp1.bytes, tcp2.bytes,
			    "packet data SHOULD NOT be equal")
        
    def test_tcpv4_str(self):
        """Test the ___str__ method to make sure the correct
        values are printed."""
        file = PcapConnector("wwwtcp.out")
        packet = file.read()
        ip = ipv4(packet[file.dloff:len(packet)])
        assert (ip != None)
        tcppacket = tcp(ip.data.bytes)
        assert (tcppacket)

	# pre tcp options:
        #expected = "TCP\nsport 53678\ndport 80\nsequence 1351059655\nack_number 0\noffset 11\nreserved 0\nns 0\ncwr 0\nece 0\nurgent 0\nack 0\npush 0\nreset 0\nsyn 1\nfin 0\nwindow 65535\nchecksum 15295\nurg_pointer 0\n"

	# post tcp options:
        expected = "TCP\nsport 53678\ndport 80\nsequence 1351059655\nack_number 0\noffset 11\nreserved 0\nns 0\ncwr 0\nece 0\nurgent 0\nack 0\npush 0\nreset 0\nsyn 1\nfin 0\nwindow 65535\nchecksum 15295\nurg_pointer 0\n" \
		   "options [" \
			"[Field: mss, Value: " \
				"<pcs.Field  name v, 16 bits, " \
				"default 1460, discriminator 0>], " \
			"[Field: nop, Value: 1], " \
			"[Field: wscale, Value: " \
				"<pcs.Field  name v, 8 bits, " \
				"default 0, discriminator 0>], " \
			"[Field: nop, Value: 1], " \
			"[Field: nop, Value: 1], " \
			"[Field: tstamp, Value: " \
				"<pcs.Field  name v, 64 bits, " \
				"default 0, discriminator 0>], " \
			"[Field: sackok, Value: " \
				"<pcs.Field  name v, 0 bits, " \
				"default 0, discriminator 0>], " \
			"[Field: end, Value: 0], " \
			"[Field: end, Value: 0]" \
		    "]\n"

        gotttted = tcppacket.__str__()

        self.assertEqual(expected, gotttted,
                         "strings are not equal \nexpected %s \ngotttted %s " %
                         (expected, gotttted))

    def test_tcpv4_println(self):
        """Test the println method."""
        file = PcapConnector("wwwtcp.out")
        packet = file.read()
        ip = ipv4(packet[file.dloff:len(packet)])
        assert (ip != None)
        tcppacket = tcp(ip.data.bytes)
        assert (tcppacket)

	# pre tcp options:
        #expected = "<TCP: sport: 53678, dport: 80, sequence: 1351059655, ack_number: 0, offset: 11, reserved: 0, urgent: 0, ack: 0, push: 0, reset: 0, syn: 1, fin: 0, window: 65535, checksum: 15295, urg_pointer: 0>"

	# post tcp options:
	# XXX println() uses __repr__(), not __str__(). the rules for the
	# game "python" say we have to preserve the structure of
	# objects returned by __repr__().
        expected = "<TCP: sport: 53678, dport: 80, sequence: 1351059655, " \
		   "ack_number: 0, offset: 11, reserved: 0, " \
                   "ns: 0, cwr: 0, ece: 0, urgent: 0, " \
		   "ack: 0, push: 0, reset: 0, syn: 1, fin: 0, " \
		   "window: 65535, checksum: 15295, urg_pointer: 0, " \
		   "options: [" \
			"[Field: mss, Value: " \
				"<pcs.Field  name v, 16 bits, " \
				"default 1460, discriminator 0>], " \
			"[Field: nop, Value: 1], " \
			"[Field: wscale, Value: " \
				"<pcs.Field  name v, 8 bits, " \
				"default 0, discriminator 0>], " \
			"[Field: nop, Value: 1], " \
			"[Field: nop, Value: 1], " \
			"[Field: tstamp, Value: " \
				"<pcs.Field  name v, 64 bits, " \
				"default 0, discriminator 0>], " \
			"[Field: sackok, Value: " \
				"<pcs.Field  name v, 0 bits, " \
				"default 0, discriminator 0>], " \
			"[Field: end, Value: 0], " \
			"[Field: end, Value: 0]" \
		    "]>"

	# unusual naming to make it easier to spot deltas in an
	# 80 column display.
        gotttted = tcppacket.println()

        self.assertEqual(expected, gotttted,
                         "strings are not equal \nexpected %s \ngotttted %s " %
                         (expected, gotttted))

if __name__ == '__main__':
    unittest.main()

