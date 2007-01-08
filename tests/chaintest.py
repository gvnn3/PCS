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
# File: $Id: chaintest.py,v 1.3 2006/06/27 14:45:43 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A test of the Chain class in PCS.

import unittest

import sys
sys.path.insert(0, '../')

from pcs.packets.ethernet import ethernet
from pcs.packets.ipv4 import ipv4
from pcs import Chain

class chainTestCase(unittest.TestCase):
    def test_chain_compare(self):
        """Test the underlying __eq__ functionality of the
        packet.  Two packets constructed from the same bytes should be
        equal and two that are not should not be equal."""
        import pcap
        file = pcap.pcap("loopping.out")
        packet = file.next()[1]
        ip1 = ipv4(packet[file.dloff:len(packet)])
        ip2 = ipv4(packet[file.dloff:len(packet)])
        assert (ip1 != None)
        assert (ip2 != None)

        ether1 = ethernet()
        ether1.src = "\x00\x00\x00\x00\x00\x01"
        ether1.dst = "\x00\x00\x00\x00\x00\x02"

        ether2 = ethernet()
        ether2.src = "\x00\x00\x00\x00\x00\x01"
        ether2.dst = "\x00\x00\x00\x00\x00\x02"

        chain1 = Chain([ether1, ip1])
        chain2 = Chain([ether2, ip2])
        
        self.assertEqual(chain1, chain2, "chains should be equal but are not")

        ip1.dst = 0
        self.assertNotEqual(chain1, chain2, "chains compare equal but should not")

if __name__ == '__main__':
    unittest.main()

