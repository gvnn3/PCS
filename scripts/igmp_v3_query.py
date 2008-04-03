#!/usr/bin/env python

from pcs.packets.localhost import *
from pcs.packets.ethernet import *
from pcs.packets.ipv4 import *
from pcs.packets.igmpv3 import *
from pcs.packets.payload import *
from pcs import *
from time import sleep

# Send an IGMPv3 query. General, group-specific, or
# group-and-source-specific queries are supported.

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
                      help="The IPv4 group to query.")

    parser.add_option("-S", "--igmp_sources",
                      dest="igmp_sources", default=None,
                      help="Comma-delimited list of IPv4 sources for "
			   "a group-and-source specific query.")

    parser.add_option("-M", "--igmp_maxresp",
                      dest="igmp_maxresp", default=None,
                      help="The maximum time for end-stations to "
		           "respond (in seconds).")

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

    #
    # Parse source list for a GSR query.
    #
    igmp_sources = []
    if options.igmp_sources is not None:
	if options.igmp_group is None:
	    raise "A group must be specified for a GSR query."
	else:
	    for source in options.igmp_sources.split(','):
		igmp_sources.append(inet_atol(source))
	    if len(igmp_sources) == 0:
	 	raise "Error parsing source list."

    # Set up the vanilla packet
    ether = ethernet()
    ether.type = 0x0800
    ether.src = ether_atob(options.ether_source)
    ether.dst = "\x01\x00\x5e\x00\x00\x01"

    # IGMPv3 General Queries are always sent to ALL-SYSTEMS.MCAST.NET.
    # We expect replies however on 224.0.0.22.
    # Queries don't contain the Router Alert option as they are
    # destined for end stations, not routers.

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

    igmp = igmpv3_query()
    igmp.maxresp = maxresp
    igmp.qrv = 2		    # SHOULD NOT be 1, MUST NOT be 0
    igmp.qqic = 10		    # I query every 10 seconds

    if options.igmp_group is None:
        # General query.
        ip.dst = INADDR_ALLHOSTS_GROUP
        igmp.group = 0
    else:
        # Group-specific query, possibly with sources.
        ip.dst = inet_atol(options.igmp_group)
        igmp.group = ip.dst

    for src in igmp_sources:
        igmp.sources.append(pcs.Field("", 32, default = src))
    igmp.nsrc = len(igmp_sources)

    igmp_packet = Chain([igmp])
    igmp.checksum = igmp_packet.calc_checksum()

    ip.length = len(ip.bytes) + len(igmp.bytes)
    ip.checksum = ip.cksum()

    packet = Chain([ether, ip, igmp])
    packet.encode()
    
    input = PcapConnector(options.ether_iface)
    input.setfilter("igmp and ip dst 224.0.0.22")

    output = PcapConnector(options.ether_iface)
    out = output.write(packet.bytes, len(packet.bytes))

    #
    # Wait for up to 'count' responses to the query to arrive and print them.
    #
    count = int(options.count)
    while count > 0:
        packet = input.readpkt()
        chain = packet.chain()
	if chain.packets[2].type == IGMP_V3_MEMBERSHIP_REPORT:
	    print chain.packets[2].println()
	    #print "%s is in %s" % \
	    #    (inet_ntop(AF_INET, struct.pack('!L', chain.packets[1].src)), \
	    #     inet_ntop(AF_INET, struct.pack('!L', chain.packets[2].group)))
	    count -= 1

main()
