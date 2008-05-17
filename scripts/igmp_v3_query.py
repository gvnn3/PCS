#!/usr/bin/env python

from pcs.packets.localhost import *
from pcs.packets.ethernet import *
from pcs.packets.ipv4 import *
from pcs.packets.igmp import *
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

    parser.add_option("-g", "--ether_dest",
                      dest="ether_dest", default=None,
                      help="The host Ethernet destination address.")

    parser.add_option("-s", "--ip_source",
                      dest="ip_source", default=None,
                      help="The IP source address.")

    parser.add_option("-D", "--ip_dest",
                      dest="ip_dest", default=None,
                      help="The IP destination address.")

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

    parser.add_option("-2", "--igmp_v2_listen",
                      action="store_true", dest="igmp_v2_listen",
                      help="Listen for responses from IGMPv2 end-stations.")

    parser.add_option("-R", "--igmp_robustness",
                      dest="igmp_robustness", default=None,
                      help="Querier Robustness (default 2)")

    parser.add_option("-Q", "--igmp_qqic",
                      dest="igmp_qqic", default=None,
                      help="Querier's Query Interval (default 10s)")

    (options, args) = parser.parse_args()

    if options.ether_iface is None or \
       options.ether_source is None or \
       options.ip_source is None or \
       options.count is None:
	print "Non-optional argument missing."
	return

    #if options.ip_dest is not None and options.ether_dest is None:
    #	print "Non-optional argument missing."
    #	return

    maxresp = 10 * 10
    if options.igmp_maxresp is not None:
        maxresp = int(options.igmp_maxresp) * 10    # in units of deciseconds

    #
    # Parse source list for a GSR query.
    #
    sources = []
    if options.igmp_sources is not None:
	if options.igmp_group is None:
	    raise "A group must be specified for a GSR query."
	else:
	    for source in options.igmp_sources.split(','):
		sources.append(inet_atol(source))
	    if len(sources) == 0:
	 	raise "Error parsing source list."

    # Set up the vanilla packet

    if options.ether_dest is not None:
        edst = ether_atob(options.ether_dest)
    else:
        edst = ETHER_MAP_IP_MULTICAST(INADDR_ALLHOSTS_GROUP)

    c = ethernet(src=ether_atob(options.ether_source), dst=edst) / \
        ipv4(flags=0x02, ttl=1, src=inet_atol(options.ip_source)) / \
        igmp(type=IGMP_HOST_MEMBERSHIP_QUERY, code=maxresp) / \
        igmpv3.query()
    ip = c.packets[1]
    q = c.packets[3]

    # IGMPv3 General Queries are always sent to ALL-SYSTEMS.MCAST.NET.
    # However we allow this to be overidden for protocol testing -- Windows,
    # in particular, doesn't seem to respond.
    #
    # We expect reports on 224.0.0.22.
    # Queries don't contain the Router Alert option as they are
    # destined for end stations, not routers.

    if options.igmp_robustness is not None:
        q.qrv = int(options.igmp_robustness)
    else:
        q.qrv = 2		    # SHOULD NOT be 1, MUST NOT be 0

    if options.igmp_qqic is not None:
        q.qqic = int(options.igmp_qqic)
    else:
        q.qqic = 10		    # I query every 10 seconds

    if options.igmp_group is None:
        # General query.
        if options.ip_dest is not None:
            ip.dst = inet_atol(options.ip_dest)
        else:
            ip.dst = INADDR_ALLHOSTS_GROUP
        q.group = INADDR_ANY
    else:
        # Group-specific query, possibly with sources.
        if options.ip_dest is not None:
            ip.dst = inet_atol(options.ip_dest)
        else:
            ip.dst = inet_atol(options.igmp_group)
        q.group = ip.dst

    if IN_MULTICAST(ip.dst) is True and \
       options.ether_dest is None:
        c.packets[0].dst = ETHER_MAP_IP_MULTICAST(ip.dst)

    for src in sources:
        q.sources.append(pcs.Field("", 32, default = src))
    q.nsrc = len(sources)

    ip.length = len(ip.bytes) + len(c.packets[2].bytes) + \
                len(c.packets[3].bytes)

    c.calc_checksums()
    c.encode()

    input = PcapConnector(options.ether_iface)
    input.setfilter("igmp")

    output = PcapConnector(options.ether_iface)
    out = output.write(c.bytes, len(c.bytes))

    #
    # Wait for up to 'count' responses to the query to arrive and print them.
    # If options.igmp_v2_listen is True, also count responses from
    # end-stations which respond with IGMPv2.
    #
    # TODO: Pretty-print IGMPv3 reports.
    #
    count = int(options.count)
    while count > 0:
        packet = input.readpkt()
	chain = packet.chain()
	if ((chain.packets[2].type == IGMP_v3_HOST_MEMBERSHIP_REPORT) or
            ((chain.packets[2].type == IGMP_v2_HOST_MEMBERSHIP_REPORT) and \
             (options.igmp_v2_listen is True))):
            version = 3
            if chain.packets[2].type == IGMP_v2_HOST_MEMBERSHIP_REPORT:
                version = 2
	    #print chain.packets[2].println()
	    print "%s responded to query with IGMPv%d." % \
	        ((inet_ntop(AF_INET, struct.pack('!L', chain.packets[1].src))),
                 version)
	    count -= 1

main()
