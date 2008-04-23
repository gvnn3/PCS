#!/usr/bin/env python

from pcs.packets.localhost import *
from pcs.packets.ethernet import *
from pcs.packets.ipv4 import *
from pcs.packets.igmp import *
from pcs.packets.igmpv3 import *
from pcs.packets.payload import *
from pcs import *
from time import sleep

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

# Send a spoof IGMPv3 report which says we've left the given group.

def main():

    from optparse import OptionParser

    parser = OptionParser()

    parser.add_option("-I", "--ether_iface",
                      dest="ether_iface", default=None,
                      help="The name of the source interface.")

    parser.add_option("-e", "--ether_source",
                      dest="ether_source", default=None,
                      help="The host Ethernet source address.")

    parser.add_option("-s", "--ip_source",
                      dest="ip_source", default=None,
                      help="The IP source address.")

    parser.add_option("-G", "--igmp_group",
                      dest="igmp_group", default=None,
                      help="The IPv4 group to spoof an IGMPv3 leave for.")

    (options, args) = parser.parse_args()

    if options.ether_iface is None or \
       options.ether_source is None or \
       options.ip_source is None or \
       options.igmp_group is None:
	print "Non-optional argument missing."
	return

    # Set up the vanilla packet
    ether = ethernet()
    ether.type = 0x0800
    ether.src = ether_atob(options.ether_source)
    ether.dst = "\x01\x00\x5e\x00\x00\x16"

    # IGMPv3 Host Reports are always sent to IGMP.MCAST.NET (224.0.0.22),
    # and must always contain the Router Alert option.

    ip = ipv4()
    ip.version = 4
    ip.hlen = 5
    ip.tos = 0
    ip.id = 0
    ip.flags = 0x02		# DF (yes, it's byte swapped here).
    ip.offset = 0
    ip.ttl = 1
    ip.protocol = IPPROTO_IGMP
    ip.src = inet_atol(options.ip_source)
    ip.dst = INADDR_ALLRPTS_GROUP

    # Create an IGMPv3 change-to-include report for the given group
    # with no sources, which means we're leaving the group.
    ig = igmp()
    ig.type = IGMP_v3_HOST_MEMBERSHIP_REPORT

    rep = igmpv3.report()

    rec0 = GroupRecordField("rec0")
    rec0.type.value = IGMP_CHANGE_TO_INCLUDE
    rec0.group.value = inet_atol(options.igmp_group)

    rep.records.append(rec0)
    rep.nrecords = len(rep.records)

    igmp_packet = Chain([ig, rep])
    ig.checksum = igmp_packet.calc_checksum()

    # Prepend IP Router Alert option to IP header.
    ra = pcs.TypeLengthValueField("ra",
			          pcs.Field("", 8, default = IPOPT_RA),
			          pcs.Field("", 8),
			          pcs.Field("", 16))
    ip.options.append(ra)

    # Compute outer IP header length and checksum.
    ip.hlen = len(ip.bytes) >> 2
    ip.length = len(ip.bytes) + len(igmp_packet.bytes)
    ip.checksum = ip.cksum()

    # Send it.
    packet = Chain([ether, ip, ig, rep])
    packet.encode()
    output = PcapConnector(options.ether_iface)
    out = output.write(packet.bytes, len(packet.bytes))

main()
