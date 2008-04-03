#!/usr/bin/env python

from pcs.packets.localhost import *
from pcs.packets.ethernet import *
from pcs.packets.ipv4 import *
from pcs.packets.igmpv2 import *
from pcs.packets.payload import *
from pcs import *
from time import sleep

# Send an IGMPv2 general or group-specific query.

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
                      help="The IPv4 group for a group-specific query. "
			   "If omitted, send a general query.")

    parser.add_option("-M", "--maxresp",
                      dest="igmp_maxresp", default=None,
                      help="The maximum time for end-stations to respond "
			   "(in seconds).")

    parser.add_option("-c", "--count",
                      dest="count", default=None,
                      help="Stop after receiving at least count responses.")

    (options, args) = parser.parse_args()

    if options.ether_iface is None or \
       options.ether_source is None or \
       options.ip_source is None or \
       options.count is None:
        print "Non-optional argument missing."
        return

    maxresp = 3 * 10
    if options.igmp_maxresp is not None:
        maxresp = int(options.igmp_maxresp) * 10    # in units of deciseconds

    # Set up the vanilla packet
    ether = ethernet()
    ether.type = 0x0800
    ether.src = ether_atob(options.ether_source)
    ether.dst = "\x01\x00\x5e\x00\x00\x01"

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
    igmp.type = IGMP_HOST_MEMBERSHIP_QUERY
    igmp.code = maxresp

    if options.igmp_group is None:
	# General query.
    	ip.dst = INADDR_ALLHOSTS_GROUP
        igmp.group = INADDR_ANY
    else:
	# Group-specific query.
    	ip.dst = inet_atol(options.igmp_group)
        igmp.group = ip.dst
    
    igmp_packet = Chain([igmp])
    igmp.checksum = igmp_packet.calc_checksum()

    # Queries don't contain the Router Alert option as they are
    # destined for end stations, not routers.

    ip.length = len(ip.bytes) + len(igmp.bytes)
    ip.checksum = ip.cksum()

    packet = Chain([ether, ip, igmp])
    packet.encode()
    
    input = PcapConnector(options.ether_iface)
    input.setfilter("igmp")

    output = PcapConnector(options.ether_iface)
    out = output.write(packet.bytes, len(packet.bytes))

    #
    # Wait for up to 'count' responses to the query to arrive and print them.
    #
    count = int(options.count)
    while count > 0:
        packet = input.readpkt()
        chain = packet.chain()
	if chain.packets[2].type == IGMP_v2_HOST_MEMBERSHIP_REPORT:
	    #print chain.packets[2].println()
	    print "%s is in %s" % \
	        (inet_ntop(AF_INET, struct.pack('!L', chain.packets[1].src)), \
	         inet_ntop(AF_INET, struct.pack('!L', chain.packets[2].group)))
	    count -= 1

main()
