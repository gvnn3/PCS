# Copyright (c) 2007, Neville-Neil Consulting
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
# File: $Id: $
#
# Author: George V. Neville-Neil
#
# Description: A test for the SCTP protocol

import unittest

import sys
   
if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.
    from pcs import PcapConnector
    from pcs.packets.ipv4 import *
    from pcs.packets.sctp import *

class sctpTestCase(unittest.TestCase):
    def test_sctp(self):
        """Create one packet"""
        packet = common()
        assert(packet != None)
        packet.sport = 9999
        packet.dport = 123
        packet.tag = 10000
        packet.checksum = 0

        new_packet = common()
        new_packet.decode(packet.bytes)

        self.assertEqual(packet.bytes, new_packet.bytes, "bytes not equal")
        for field in packet._fieldnames:
            self.assertEqual(getattr(packet, field), getattr(new_packet, field), ("%s not equal" % field))

    def test_sctp_read(self):
        """Read a packet from a pcap file."""
        file = PcapConnector("sctp.pcap")
        packet = file.readpkt()
        sctp = packet.data.data
        assert (sctp != None)

if __name__ == '__main__':
    unittest.main()
