#!/usr/bin/env python

from pcs.packets.localhost import *
from pcs.packets.ipv4 import *
from pcs.packets.igmpv2 import *
from pcs.packets.payload import *
from pcs import *
from time import sleep

# Send an IGMPv2 general or group-specific query.

def main():

    from optparse import OptionParser

    parser = OptionParser()

    parser.add_option("-s", "--ip_source",
                      dest="ip_source", default=None,
                      help="The IP source address.")

    parser.add_option("-G", "--igmp_group",
                      dest="igmp_group", default=None,
                      help="The IPv4 group to query.")

    parser.add_option("-M", "--maxresp",
                      dest="maxresp", default=None,
                      help="The maximum time for end-stations to respond (in seconds).")

    parser.add_option("-c", "--count",
                      dest="count", default=None,
                      help="Stop after receiving at least count responses.")

    (options, args) = parser.parse_args()
    
    # Set up the vanilla packet
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

    igmp = igmpv2()
    igmp.type = IGMP_MEMBERSHIP_QUERY
    igmp.code = int(options.maxresp) * 10	# in units of deciseconds

    if options.igmp_group is None:
        # General query.
	dst = "224.0.0.1"
        ip.dst = inet_atol(dst)
        igmp.group = 0
    else:
        # Group-specific query.
	dst = options.igmp_group
        ip.dst = inet_atol(dst)
        igmp.group = ip.dst
    
    igmp_packet = Chain([igmp])
    igmp.checksum = igmp_packet.calc_checksum()

    # Queries don't contain the Router Alert option as they are
    # destined for end stations, not routers.

    ip.length = len(ip.bytes) + len(igmp.bytes)
    ip.checksum = ip.calc_checksum()

    packet = Chain([ip, igmp])
    packet.encode()
    
    input = IP4Connector()

    output = IP4Connector()
    out = output.sendto(packet.bytes, (dst, 0), 0)

    # XXX this doesn't work, more work needed in IP4Connector area.

    #
    # Wait for up to 'count' responses to the query to arrive and print them.
    #
    count = int(options.count)
    while count > 0:
	array = input.read(1024)
	input.unpack(
        packet = input.read(1024)
        chain = packet.chain()
	if chain.packets[1].type == IGMP_V2_MEMBERSHIP_REPORT:
	    #print chain.packets[0].println()
	    print "%s is in %s" % \
	        (inet_ntop(AF_INET, struct.pack('!L', chain.packets[1].src)), \
	         inet_ntop(AF_INET, struct.pack('!L', chain.packets[2].group)))
	    count -= 1

main()
