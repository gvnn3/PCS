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
# Description: 

import unittest

import sys

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.

    from pcs import PcapConnector
    from pcs.packets.ethernet import *
    from pcs.packets.ipv4 import *
    from pcs.packets.null import *
    import pcs.packets.ethernet_map

class mapTestCase(unittest.TestCase):
    def test_map(self):
        # We're going to replace the higher layer protocol with the NULL
        # protocol.  (Actually we're replacing it with Folger's Crystals.)
        """This test reads from a pre-stored pcap file generated with
        tcpdump and ping on an ethernet interface and tests the
        __str__ method to make sure the correct values are printed."""
        file = PcapConnector("etherping.out")
        packet = file.readpkt()

        self.assertEqual(type(packet.data), ipv4)
        
        file.close

        # Replace the mapping of IPv4
        ethernet_map.map[ethernet_map.ETHERTYPE_IP] = null

        file = PcapConnector("etherping.out")
        packet = file.readpkt()

        self.assertEqual(type(packet.data), null)
        
        file.close
        
if __name__ == "__main__":
    unittest.main()
