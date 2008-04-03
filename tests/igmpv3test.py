#!/usr/bin/env python

# TODO: Rationalize igmpv2/v3/dvmrp/mtrace and 

import unittest
import sys

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues

    from hexdumper import hexdumper
    from pcs.packets.ethernet import *
    from pcs.packets.ipv4 import *
    from pcs.packets.igmpv3 import *
    from pcs import *

class igmpv3TestCase(unittest.TestCase):

    def test_igmpv3_encode(self):
        # create one packet, copy its bytes, then compare their fields.
        igmp = igmpv3_report()
        assert (igmp != None)
        igmp.type = IGMP_v3_HOST_MEMBERSHIP_REPORT

        # An ASM/SSM leave.
        rec0 = GroupRecordField("rec0")
        rec0.type.value = IGMP_CHANGE_TO_INCLUDE
        rec0.group.value = inet_atol("239.0.1.2")
        igmp.records.append(rec0)

        # An SSM join.
        rec1 = GroupRecordField("rec1")
        rec1.type.value = IGMP_CHANGE_TO_INCLUDE
        rec1.group.value = inet_atol("239.3.2.1")
        rec1.sources.append(pcs.Field("", 32,
                                      default = inet_atol("192.0.2.1")))
        rec1.nsources.value = len(rec1.sources)
        igmp.records.append(rec1)

        # An ASM join.
        rec2 = GroupRecordField("rec2")
        rec2.type.value = IGMP_CHANGE_TO_EXCLUDE
        rec2.group.value = inet_atol("224.111.222.111")
        igmp.records.append(rec2)

        # An ASM filter change.
        # XXX I can't get auxiliary data embedding to work reliably,
        # this seems to be because the syntactic sugar for OptionListField
        # makes it difficult to retrieve the size of the embedded fields.
        rec3 = GroupRecordField("rec3")
        rec3.type.value = IGMP_BLOCK_OLD_SOURCES
        rec3.group.value = inet_atol("225.4.3.2")
        rec3.sources.append(pcs.Field("", 32,
                                      default = inet_atol("192.0.2.99")))
        rec3.nsources.value = len(rec3.sources)
        igmp.records.append(rec3)

        igmp.nrecords = len(igmp.records)
        igmp_packet = Chain([igmp])
        igmp.checksum = igmp_packet.calc_checksum()

	#hd = hexdumper()
	#print hd.dump2(igmp.bytes)
	expected = "\x22\x00\xC5\xA5\x00\x00\x00\x04" \
		   "\x03\x00\x00\x00\xEF\x00\x01\x02" \
		   "\x03\x00\x00\x01\xEF\x03\x02\x01" \
		   "\xC0\x00\x02\x01\x04\x00\x00\x00" \
		   "\xE0\x6F\xDE\x6F\x06\x00\x00\x01" \
		   "\xE1\x04\x03\x02\xC0\x00\x02\x63"
	gotttted = igmp.bytes
	self.assertEqual(expected, gotttted, "test encoding")

    def test_igmpv3_decode(self):
	# Try decoding the same packet as above, see what we get.
	input    = "\x22\x00\xC5\xA5\x00\x00\x00\x04" \
		   "\x03\x00\x00\x00\xEF\x00\x01\x02" \
		   "\x03\x00\x00\x01\xEF\x03\x02\x01" \
		   "\xC0\x00\x02\x01\x04\x00\x00\x00" \
		   "\xE0\x6F\xDE\x6F\x06\x00\x00\x01" \
		   "\xE1\x04\x03\x02\xC0\x00\x02\x63"

	igmp = igmpv3_report(input)
	self.assertEqual(input, igmp.bytes, "test decoding")

if __name__ == '__main__':
    unittest.main()
