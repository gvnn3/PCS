#!/usr/bin/env python

from pcs.packets.localhost import *
from pcs.packets.ethernet import *
from pcs.packets.ipv4 import *
from pcs.packets.igmp import *
from pcs.packets.igmpv2 import *
from pcs.packets.payload import *
from pcs import *
from time import sleep

# Spoof an IGMPv2 HOST LEAVE message.

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
                      help="The IPv4 group to spoof a leave message for.")

    parser.add_option("-A", "--no-router-alert",
                      action="store_true", dest="no_ra",
                      help="Disable the use of the IP Router Alert option.")

    (options, args) = parser.parse_args()

    if options.igmp_group is None or \
       options.ether_source is None or \
       options.ether_iface is None or \
       options.ip_source is None:
           print("A required argument is missing.")
           return

    output = PcapConnector(options.ether_iface)

    c = ethernet(src=ether_atob(options.ether_source),	\
                 dst=ETHER_MAP_IP_MULTICAST(INADDR_ALLRTRS_GROUP)) / \
        ipv4(flags=IP_DF, id=123, ttl=1, 		\
             src=inet_atol(options.ip_source),		\
             dst=INADDR_ALLRTRS_GROUP) /		\
        igmp(type=IGMP_HOST_LEAVE_MESSAGE) /		\
        igmpv2(group=inet_atol(options.igmp_group))
    c.fixup()

    out = output.write(c.bytes, len(c.bytes))

main()
