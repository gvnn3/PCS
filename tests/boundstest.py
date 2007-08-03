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
# File: $Id:$
#
# Author: George V. Neville-Neil
#
# Description: A simple test of all the bound checking code in PCS


import unittest

import sys
#sys.path.insert(0, "..") # Look locally first
   
from pcs.packets.ipv4 import *
from pcs.packets.ethernet import *
from pcs.packets.dns import *

class boundaryPacket(pcs.Packet):
    """Define a packet full of bit fields for use in testing.
    """
    _layout = pcs.Layout()
    
    def __init__(self, bytes = None):
        f1 = pcs.Field("f1", 1)
        f2 = pcs.Field("f2", 2)
        f3 = pcs.Field("f3", 3)
        f4 = pcs.Field("f4", 4)
        f5 = pcs.Field("f5", 5)
        f6 = pcs.Field("f6", 6)
        f7 = pcs.Field("f7", 7)
        f8 = pcs.Field("f8", 8)
        f9 = pcs.Field("f9", 9)
        f10 = pcs.Field("f10", 10)
        f11 = pcs.Field("f11", 11)
        f12 = pcs.Field("f12", 12)
        f13 = pcs.Field("f13", 13)
        f14 = pcs.Field("f14", 14)
        f15 = pcs.Field("f15", 15)
        f16 = pcs.Field("f16", 16)
        f17 = pcs.Field("f17", 17)
        f18 = pcs.Field("f18", 18)
        f19 = pcs.Field("f19", 19)
        f20 = pcs.Field("f20", 20)
        f21 = pcs.Field("f21", 21)
        f22 = pcs.Field("f22", 22)
        f23 = pcs.Field("f23", 23)
        f24 = pcs.Field("f24", 24)
        f25 = pcs.Field("f25", 25)
        f26 = pcs.Field("f26", 26)
        f27 = pcs.Field("f27", 27)
        f28 = pcs.Field("f28", 28)
        f29 = pcs.Field("f29", 29)
        f30 = pcs.Field("f30", 30)
        f31 = pcs.Field("f31", 31)
        f32 = pcs.Field("f32", 32)
        pcs.Packet.__init__(self,
                            [f1, f2, f3, f4, f5, f6, f7, f8, f9,
                             f10, f11, f12, f13, f14, f15, f16,
                             f17, f18, f19, f20, f21, f22, f23,
                             f24, f25, f26, f27, f28, f29, f30,
                             f31, f32], bytes = None)

class boundsTestCase(unittest.TestCase):
    def test_field(self):
        ip = ipv4()
        assert (ip != None)
        self.assertRaises(pcs.FieldBoundsError, setattr, ip, 'version', 9999)
            
    def test_stringfield(self):
        ether = ethernet()
        self.assertRaises(pcs.FieldBoundsError, setattr, ether, 'src',
                         "\x00\x00\x00\x00\x00\x00\x00")

    def test_lengthvaluefield(self):
        dns = dnsrr()
        self.assertRaises(pcs.FieldBoundsError, setattr, dns, 'name', "The walrus and the carpenter were walking close at hand.  The wept like anything to see such quantities of sand.  The Walrus and the Carpenter Were walking close at hand; They wept like anything to see Such quantities of sand: If this were only cleared away, They said, it would be grand!  If seven maids with seven mops Swept it for half a year.  Do you suppose, the Walrus said, That they could get it clear?  I doubt it, said the Carpenter, And shed a bitter tear.The time has come the walrus said to speak of many things of shoes and ships and sealing wax and cabbages and Kings, and why the sea is boiling hot and whether pigs have whings.  Caloo Callay or frabjous day for cabbages and kings?")
            
    def test_allbits(self):
        packet = boundaryPacket()
        for field in packet._layout:
            self.assertRaises(pcs.FieldBoundsError, setattr,
                              packet, field.name, 2 ** field.width)
            self.assertRaises(pcs.FieldBoundsError, setattr,
                              packet, field.name, -1)

if __name__ == '__main__':
    unittest.main()

