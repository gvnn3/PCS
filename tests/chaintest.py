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

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.

    import pcs
    from pcs.packets.ethernet import ethernet
    from pcs.packets.ipv4 import ipv4
    from pcs import *


class chainTestCase(unittest.TestCase):
    def test_chain_compare(self):
        """Test the underlying __eq__ functionality of the
        packet.  Two packets constructed from the same bytes should be
        equal and two that are not should not be equal."""
        file = PcapConnector("loopping.out")
        packet = file.readpkt()
        # Create new packets don't just point to them
        ip1 = ipv4(packet.data.bytes)
        ip2 = ipv4(packet.data.bytes)
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

    def test_chain_read(self):
        """Test whether or not the chain method of the base class works."""
        file = PcapConnector("loopping.out")
        packet = file.readpkt()
        chain = packet.chain()
        test_string = "Localhost\ntype 2\n IPv4\nversion 4\nhlen 5\ntos 0\nlength 84\nid 59067\nflags 0\noffset 0\nttl 64\nprotocol 1\nchecksum 0\nsrc 127.0.0.1\ndst 127.0.0.1\noptions []\n ICMPv4\ntype 8\ncode 0\nchecksum 60550\n Payload\n\'\\x18\\x19\\x1a\\x1b\' "

        string = chain.__str__()

        self.assertEqual(test_string, string,
                         "strings not equal \ngot\n%s\nexpected\n%s" %
                         (string, test_string))

if __name__ == '__main__':
    unittest.main()

