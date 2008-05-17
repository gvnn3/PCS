#!/usr/bin/env python

import unittest
import sys

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues

    from hexdumper import hexdumper
    from pcs.packets.ethernet import *
    from pcs.packets.ipv4 import *
    from pcs.packets.igmp import *
    from pcs.packets.igmpv3 import *
    from pcs import *

class igmpv3TestCase(unittest.TestCase):

    def test_igmpv3_encode(self):
        # create one packet, copy its bytes, then compare their fields.
        c = igmp(type=IGMP_v3_HOST_MEMBERSHIP_REPORT) / igmpv3.report()
        rep = c.packets[1]

        # An ASM/SSM leave.
        rec0 = GroupRecordField("rec0")
        rec0.type.value = IGMP_CHANGE_TO_INCLUDE
        rec0.group.value = inet_atol("239.0.1.2")
        rep.records.append(rec0)

        # An SSM join.
        rec1 = GroupRecordField("rec1")
        rec1.type.value = IGMP_CHANGE_TO_INCLUDE
        rec1.group.value = inet_atol("239.3.2.1")
        rec1.sources.append(pcs.Field("", 32,
                                      default = inet_atol("192.0.2.1")))
        rec1.nsources.value = len(rec1.sources)
        rep.records.append(rec1)

        # An ASM join.
        rec2 = GroupRecordField("rec2")
        rec2.type.value = IGMP_CHANGE_TO_EXCLUDE
        rec2.group.value = inet_atol("224.111.222.111")
        rep.records.append(rec2)

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
        rep.records.append(rec3)

        rep.nrecords = len(rep.records)

        c.calc_checksums()
        c.encode()

	#hd = hexdumper()
	#print hd.dump2(c.bytes)
	expected = "\x22\x00\xC5\xA5\x00\x00\x00\x04" \
		   "\x03\x00\x00\x00\xEF\x00\x01\x02" \
		   "\x03\x00\x00\x01\xEF\x03\x02\x01" \
		   "\xC0\x00\x02\x01\x04\x00\x00\x00" \
		   "\xE0\x6F\xDE\x6F\x06\x00\x00\x01" \
		   "\xE1\x04\x03\x02\xC0\x00\x02\x63"
 
	#print hd.dump2(expected)
	gotttted = c.bytes
	self.assertEqual(expected, gotttted, "test encoding")

    def test_igmpv3_decode(self):
	# Try decoding the same packet as above, see what we get.
	input    = "\x22\x00\xC5\xA5\x00\x00\x00\x04" \
		   "\x03\x00\x00\x00\xEF\x00\x01\x02" \
		   "\x03\x00\x00\x01\xEF\x03\x02\x01" \
		   "\xC0\x00\x02\x01\x04\x00\x00\x00" \
		   "\xE0\x6F\xDE\x6F\x06\x00\x00\x01" \
		   "\xE1\x04\x03\x02\xC0\x00\x02\x63"

	igh = igmp(input)
	self.assertEqual(input, igh.chain().bytes, "test decoding")

    def test_igmpv3_encode_kv(self):
        # Create reports using the new syntax.
        #c = igmp(type=IGMP_v3_HOST_MEMBERSHIP_REPORT) /                    \
        c = igmp() / \
            igmpv3.report(records=[GroupRecordField("",                    \
                                    group=inet_atol("239.0.1.2"),          \
                                    type=IGMP_CHANGE_TO_INCLUDE),
                                   GroupRecordField("",                    \
                                    group=inet_atol("239.3.2.1"),          \
                                    type=IGMP_CHANGE_TO_INCLUDE,           \
                                    sources=[inet_atol("192.0.2.1")]),     \
                                   GroupRecordField("",                    \
                                    group=inet_atol("224.111.222.111"),    \
                                    type=IGMP_CHANGE_TO_EXCLUDE),          \
                                   GroupRecordField("",                    \
                                    group=inet_atol("225.4.3.2"),          \
                                    type=IGMP_BLOCK_OLD_SOURCES,           \
                                    sources=[inet_atol("192.0.2.99")])])

        c.calc_lengths()
        c.calc_checksums()
        c.encode()

	#hd = hexdumper()
	#print hd.dump2(c.bytes)
	expected = "\x22\x00\xC5\xA5\x00\x00\x00\x04" \
		   "\x03\x00\x00\x00\xEF\x00\x01\x02" \
		   "\x03\x00\x00\x01\xEF\x03\x02\x01" \
		   "\xC0\x00\x02\x01\x04\x00\x00\x00" \
		   "\xE0\x6F\xDE\x6F\x06\x00\x00\x01" \
		   "\xE1\x04\x03\x02\xC0\x00\x02\x63"
 
	#print hd.dump2(expected)
	gotttted = c.bytes
	self.assertEqual(expected, gotttted, "test encoding")

if __name__ == '__main__':
    unittest.main()
