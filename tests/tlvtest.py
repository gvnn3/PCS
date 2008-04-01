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

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.
    import pcs

# This hack by: Raymond Hettinger
class hexdumper:
    """Given a byte array, turn it into a string. hex bytes to stdout."""
    def __init__(self):
	self.FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' \
						    for x in range(256)])

    def dump(self, src, length=8):
	result=[]
	for i in xrange(0, len(src), length):
	    s = src[i:i+length]
	    hexa = ' '.join(["%02X"%ord(x) for x in s])
	    printable = s.translate(self.FILTER)
	    result.append("%04X   %-*s   %s\n" % \
			  (i, length*3, hexa, printable))
	return ''.join(result)

class testPacket(pcs.Packet):
    """Define a packet containing a TLV field for use in testing."""
    _layout = pcs.Layout()

    def __init__(self, bytes = None):
        f1 = pcs.Field("f1", 32)
	f2 = pcs.TypeLengthValueField("f2", 0x7C)
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
	packet = testPacket()
	packet.f1 = 9
	# Note: TLV is gnarly at the moment, the first element of the
	# value list for a TLV is the type. It is totally ignored,
	# and overwritten with what you provided to the constructor,
	# which means the representation is inconsistent with what
	# you actually get when you encode.
	# Also, you MUST specify a type field in the constructor even
	# though it's declared as an optional argument.
	#  TODO: Throw an exception in that case.
	packet.f2 = (123, 4, "foo")	# must fill out all fields t,l,v.
					# Note: type 123 is ignored.
	# Now overwrite, observe that 124 (0x7C) actually appears.
	packet.f2 = (0, 6, "foobar")
	print packet
	packet.encode()
	print packet.bytes
	hd = hexdumper()
	print hd.dump(packet.bytes)
	return

if __name__ == '__main__':
    unittest.main()
