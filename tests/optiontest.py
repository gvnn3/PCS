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
# File: $Id:$
#
# Author: George V. Neville-Neil
#
# Description: A test of the option fields in PCS.

import unittest
import sys

from hexdumper import hexdumper

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.

    import pcs
    from pcs.packets.tcp import *


#
# TODO: Rototile interface so that consumers do not need to
# have knowledge of option structure, currently the option
# code needs to be explicitly specified.
#
# Also this doesn't forcibly pad to 32 bits, nor does it check
# that the length of all options wouldn't exceed 40.
#
class optionTestCase(unittest.TestCase):
    def test_tcp_with_options(self):
	"""Assert that a TCP with options is correctly encoded."""
        packet = tcp()

        nop = pcs.Field("nop", 8)
	mss = pcs.TypeLengthValueField("mss",
	                               pcs.Field("t", 8, default = 0x02),
				       pcs.Field("l", 8),
				       pcs.Field("v", 16))
        end = pcs.Field("end", 8)

        nop.value = 1
        mss.value.value = 1460		# Most common Internet MSS value.

	# Build a TCP option list which will be 32-bits aligned.
        packet.options.append(nop)
        packet.options.append(nop)
        packet.options.append(mss)
        packet.options.append(nop)
        packet.options.append(end)

	expected = "\x00\x00\x00\x00\x00\x00\x00\x00" \
		   "\x00\x00\x00\x00\x00\x00\x00\x00" \
		   "\x00\x00\x00\x00\x01\x01\x02\x04" \
		   "\x05\xb4\x01\x00"
	got = packet.bytes

	#packet.encode()
	#hd = hexdumper()
	#print hd.dump(expected)
	#print hd.dump(got)

        self.assertEqual(expected, got)

    def test_tcp_without_options(self):
	"""Assert that a TCP without options does not get any additional
	   fields appended to it on the wire."""
        packet = tcp()

	expected = "\x00\x00\x00\x00\x00\x00\x00\x00" \
		   "\x00\x00\x00\x00\x00\x00\x00\x00" \
		   "\x00\x00\x00\x00"
	got = packet.bytes

	#packet.encode()
	#hd = hexdumper()
	#print hd.dump(expected)
	#print hd.dump(got)

	self.assertEqual(len(packet.options), 0)
        self.assertEqual(expected, got)

if __name__ == '__main__':
    unittest.main()
