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
# Author: Bruce M. Simpson
#
# Description: Type/Length/Value test

import unittest
import sys
from hexdumper import hexdumper

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.
    import pcs

class testPacket(pcs.Packet):
    """Define a packet containing a TLV field for use in testing."""
    _layout = pcs.Layout()

    def __init__(self, bytes = None):
        f1 = pcs.Field("f1", 32)
        f2 = pcs.TypeLengthValueField("f2", pcs.Field("t", 8),
				     pcs.Field("l", 8),
                                     pcs.StringField("v", 10 * 8))
        pcs.Packet.__init__(self, [f1, f2], bytes = None)

    def __str__(self):
        """Walk the entire packet and pretty print the values of the fields."""
        retval = "TEST\n"
        for field in self._layout:
                retval += "%s %s\n" % (field.name, self.__dict__[field.name])
        return retval

class tlvTestCase(unittest.TestCase):
    def test_tlv(self):
        """Create one packet containing a TLV field."""
	data = "\x12\x34\xAB\xCD\xAB\x0c\x66\x6F" \
	       "\x6F\x62\x61\x72\x00\x00\x00\x00"

	# XXX The length of the f2 field is filled out with
	# the maximum length of the value field, NOT its packed
	# length. LengthValueField also has this issue.
	# Also, the TLV fields are ambiguous as to whether the
	# length represents bits or bytes.
	# IP protocols are usually byte or 32-bit word aligned.
	packet = testPacket()
	packet.f1 = 0x1234abcd
	packet.f2.type.value = 0xab
	packet.f2.length.value = len("foobar")
	packet.f2.value.value = "foobar"
	packet.encode()

	#hd = hexdumper()
	#print hd.dump(packet.bytes)
	#print hd.dump(data)

	self.assertEqual(packet.bytes, data, \
			 "packets should be equal but are not")

if __name__ == '__main__':
    unittest.main()
