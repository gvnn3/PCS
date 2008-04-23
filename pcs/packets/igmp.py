import pcs
from socket import AF_INET, inet_ntop

import struct
import inspect
import time

import igmpv2
import igmpv3
#import dvmrp
#import mtrace

IGMP_HOST_MEMBERSHIP_QUERY = 0x11
IGMP_v1_HOST_MEMBERSHIP_REPORT = 0x12
IGMP_DVMRP = 0x13
IGMP_v2_HOST_MEMBERSHIP_REPORT = 0x16
IGMP_HOST_LEAVE_MESSAGE = 0x17
IGMP_v3_HOST_MEMBERSHIP_REPORT = 0x22
IGMP_MTRACE_REPLY = 0x1e
IGMP_MTRACE_QUERY = 0x1f

map = {
	IGMP_HOST_MEMBERSHIP_QUERY:	igmpv2.igmpv2,
	IGMP_v1_HOST_MEMBERSHIP_REPORT:	igmpv2.igmpv2,
	#IGMP_DVMRP:			dvmrp.dvmrp,
	IGMP_v2_HOST_MEMBERSHIP_REPORT:	igmpv2.igmpv2,
	IGMP_HOST_LEAVE_MESSAGE:	igmpv2.igmpv2,
	#IGMP_MTRACE_REPLY:		mtrace.reply,
	#IGMP_MTRACE_QUERY:		mtrace.query,
	IGMP_v3_HOST_MEMBERSHIP_REPORT:	igmpv3.report
}

descr = {
	IGMP_HOST_MEMBERSHIP_QUERY:	"IGMPv2 Query",
	IGMP_v1_HOST_MEMBERSHIP_REPORT:	"IGMPv1 Report",
	IGMP_DVMRP:			"DVMRP",
	IGMP_v2_HOST_MEMBERSHIP_REPORT:	"IGMPv2 Report",
	IGMP_HOST_LEAVE_MESSAGE:	"IGMPv2 Leave",
	IGMP_MTRACE_REPLY:		"MTRACE Reply",
	IGMP_MTRACE_QUERY:		"MTRACE Query",
	IGMP_v3_HOST_MEMBERSHIP_REPORT:	"IGMPv3 Report"
}

class igmp(pcs.Packet):
    """IGMP"""

    _layout = pcs.Layout()
    _map = map
    _descr = descr

    def __init__(self, bytes = None, timestamp = None):
        """ Define the common IGMP encapsulation; see RFC 2236. """
        type = pcs.Field("type", 8, discriminator=True)
        code = pcs.Field("code", 8)
        checksum = pcs.Field("checksum", 16)
        pcs.Packet.__init__(self, [type, code, checksum], bytes = bytes)
        # Description MUST be set after the PCS layer init
        self.description = inspect.getdoc(self)

        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes != None:
            offset = self.sizeof()
            if self.type == IGMP_HOST_MEMBERSHIP_QUERY and \
               len(bytes) >= igmpv3.IGMP_V3_QUERY_MINLEN:
                    self.data = igmpv3.query(bytes[offset:len(bytes)],
                                             timestamp = timestamp)
            else:
                self.data = self.next(bytes[offset:len(bytes)],
                                      timestamp = timestamp)
        else:
            self.data = None

    def __str__(self):
        """Walk the entire packet and pretty print the values of the fields."""
        retval = self._descr[self.type] + "\n"
        for field in self._layout:
            retval += "%s %s\n" % (field.name, field.value)
        return retval
