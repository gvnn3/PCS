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

    parser.add_option("-S", "--seconds",
                      dest="seconds", default=1.0,
                      help="Number of seconds between packets.")

    parser.add_option("-c", "--count",
                      dest="count", default=None,
                      help="Stop after sending count packets.")

    (options, args) = parser.parse_args()

    if options.ether_iface is None or \
       options.ether_source is None or \
       options.ip_source is None or \
       options.count is None:
        print "Non-optional argument missing."
        return

    maxresp = 3 * 10

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
        ipv4(flags=IP_DF, ttl=1,				\
             src=inet_atol(options.ip_source),			\
             dst=dst) /						\
        igmp(type=IGMP_v2_HOST_MEMBERSHIP_REPORT, code=maxresp) /	\
        igmpv2(group=group)
    c.fixup()

    output = PcapConnector(options.ether_iface)
    #
    # Send count packets, delayed by seconds
    #
    count = int(options.count)
    if count < 0:
        count = sys.maxint
    while count > 0:
        out = output.write(c.bytes, len(c.bytes))
        count -= 1
        sleep(float(options.seconds))

main()
