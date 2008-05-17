#!/usr/bin/env python

from pcs.packets.localhost import *
from pcs.packets.ethernet import *
from pcs.packets.ipv4 import *
from pcs.packets.igmp import *
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

    if options.igmp_group is None:
	# General query.
    	dst = INADDR_ALLHOSTS_GROUP
        group = INADDR_ANY
    else:
	# Group-specific query.
    	dst = inet_atol(options.igmp_group)
        group = dst

    # Queries don't contain the Router Alert option as they are
    # destined for end stations, not routers.

    c = ethernet(src=ether_atob(options.ether_source),		\
                 dst=ETHER_MAP_IP_MULTICAST(dst)) /		\
        ipv4(flags=0x02, ttl=1,				\
             src=inet_atol(options.ip_source),			\
             dst=dst) /						\
        igmp(type=IGMP_HOST_MEMBERSHIP_QUERY, code=maxresp) /	\
        igmpv2(group=group)

    # TODO: Push length logic into Chain and down into packets themselves.
    ip = c.packets[1]
    ip.length = len(ip.bytes) + len(c.packets[2].bytes) + \
                len(c.packets[3].bytes)
    ip.hlen = len(ip.bytes) >> 2

    c.calc_checksums()
    # XXX Always encode before you send.
    c.encode()

    input = PcapConnector(options.ether_iface)
    input.setfilter("igmp")

    output = PcapConnector(options.ether_iface)
    out = output.write(c.bytes, len(c.bytes))

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
	         inet_ntop(AF_INET, struct.pack('!L', chain.packets[3].group)))
	    count -= 1

main()
