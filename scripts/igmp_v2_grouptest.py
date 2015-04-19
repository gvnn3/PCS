#!/usr/bin/env python

from pcs.packets.localhost import *
from pcs.packets.ethernet import *
from pcs.packets.ipv4 import *
from pcs.packets.igmp import *
from pcs.packets.igmpv2 import *
from pcs.packets.payload import *
from pcs import *
from time import sleep

import sys
import signal

# Send an IGMPv2 general or group-specific query.

def results(signum, frame):
    global match

    for addr, got in sorted(match.items()):
        if (got == True):
            print("%s answered %s" % (inet_ntop(AF_INET, struct.pack('!L', addr[0])), inet_ntop(AF_INET, struct.pack('!L', addr[1]))))
        else:
            print("%s NO ANSWER for %s" % (inet_ntop(AF_INET, struct.pack('!L', addr[0])), inet_ntop(AF_INET, struct.pack('!L', addr[1]))))


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

    parser.add_option("-l", "--host_list",
                      dest="hostlist", action="append",
                      help="List of hosts we expect responses from.")

    parser.add_option("-n", "--number",
                      dest="number", default = 1, type=int,
                      help="Query a number of groups starting at "
                      "the one given by -G")

    parser.add_option("-c", "--count",
                      dest="count", default=None,
                      help="Stop after receiving at least count responses.")

    (options, args) = parser.parse_args()

    if options.ether_iface is None or \
       options.ether_source is None or \
       options.ip_source is None or \
       options.count is None:
        print("Non-optional argument missing.")
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

    # Set up our match table
    global match
    match = {}
    for host in options.hostlist:
        for addr in range(group, group + options.number):
            match[(inet_atol(host), (addr))] = False

    signal.signal(signal.SIGINFO, results)

    while (options.number >= 0):

        # Queries don't contain the Router Alert option as they are
        # destined for end stations, not routers.

        c = ethernet(src=ether_atob(options.ether_source),		\
                     dst=ETHER_MAP_IP_MULTICAST(dst)) /		\
            ipv4(flags=IP_DF, ttl=1,				\
                 src=inet_atol(options.ip_source),			\
                 dst=dst + options.number) /   \
            igmp(type=IGMP_HOST_MEMBERSHIP_QUERY, code=maxresp) /	\
            igmpv2(group=(group + options.number))
        c.fixup()

        input = PcapConnector(options.ether_iface)
        input.setfilter("igmp")

        output = PcapConnector(options.ether_iface)
        out = output.write(c.bytes, len(c.bytes))

        options.number -= 1
        
    #
    # Wait for up to 'count' responses to the query to arrive and print them.
    #
    count = int(options.count)
    while count > 0:
        packet = input.readpkt()
        chain = packet.chain()
	if chain.packets[2].type == IGMP_v2_HOST_MEMBERSHIP_REPORT:
	    #print chain.packets[2].println()
	    # print "%s is in %s" % \
	    #     (inet_ntop(AF_INET, struct.pack('!L', chain.packets[1].src)), \
	    #      inet_ntop(AF_INET, struct.pack('!L', chain.packets[3].group)))
            match[(chain.packets[1].src, chain.packets[3].group)] = True
	    count -= 1

    results(0, 0)

main()
