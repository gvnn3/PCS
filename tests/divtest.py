# Copyright (c) 2008, Bruce M. Simpson.
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
# Neither the name of the authors nor the names of contributors may be
# used to endorse or promote products derived from this software without
# specific prior written permission.
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
# File: $Id$
#
# Author: Bruce M. Simpson
#
# Description: Test the Scapy-style chain construction syntax.

import unittest

import sys

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.

    import pcs
    from pcs import *

    import pcs.packets.ethernet as ethernet
    import pcs.packets.ipv4 as ipv4
    import pcs.packets.udpv4 as udpv4
    import pcs.packets.dhcpv4 as dhcpv4

class divTestCase(unittest.TestCase):
    def test_div(self):
        """Test the Scapy-style chain construction syntax."""

        # Create a bunch of individual packets.
        a = ethernet.ethernet()
        b = ipv4.ipv4()
        c = udpv4.udpv4(sport=1234)
        d = dhcpv4.dhcpv4()

        # Pack them into chains, assert that their properties still hold.
        x = a / b
        self.assertEqual(len(x.packets), 2, "x does not have 2 packets")
        self.assertEqual(x.packets[0].type, 0x0800, \
                         "x[0].type is not ETHERTYPE_IP")

        y = b / c
        self.assertEqual(len(y.packets), 2, "y does not have 2 packets")
        self.assertEqual(y.packets[0].protocol, 17, \
                         "y.packets[0].protocol is not UDP")

        z = c / d
        self.assertEqual(len(z.packets), 2, "z does not have 2 packets")
        self.assertEqual(z.packets[0].sport, 1234, "z.packets[0].sport is not 1234")
        self.assertEqual(z.packets[0].dport, 67, "z.packets[0].dport is not 67")

        # All together now.
        alpha = ethernet.ethernet() / ipv4.ipv4() / udpv4.udpv4(sport=1234) / \
                dhcpv4.dhcpv4()
        self.assertEqual(len(alpha.packets), 4, "alpha does not have 4 packets")
        self.assertEqual(alpha.packets[0].type, 0x0800, \
                         "alpha.packets[0].type is not ETHERTYPE_IP")
        self.assertEqual(alpha.packets[1].protocol, 17, \
                         "alpha.packets[1].protocol is not UDP")
        self.assertEqual(alpha.packets[2].sport, 1234, \
                         "alpha.packets[2].sport is not 1234")
        self.assertEqual(alpha.packets[2].dport, 67, \
                         "alpha.packets[2].dport is not 67")

if __name__ == '__main__':
    unittest.main()
