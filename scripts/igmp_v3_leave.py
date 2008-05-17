#!/usr/bin/env python

from pcs.packets.localhost import *
from pcs.packets.ethernet import *
from pcs.packets.ipv4 import *
from pcs.packets.igmp import *
from pcs.packets.igmpv3 import *
from pcs.packets.payload import *
from pcs import *
from time import sleep

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

    # IGMPv3 Host Reports are always sent to IGMP.MCAST.NET (224.0.0.22),
    # and must always contain the Router Alert option.

    c = ethernet(src=ether_atob(options.ether_source), \
                 dst=ETHER_MAP_IP_MULTICAST(INADDR_ALLRPTS_GROUP)) / \
        ipv4(src=inet_atol(options.ip_source), dst=INADDR_ALLRPTS_GROUP, \
             ttl=1, flags=0x02) / \
        igmp(type=IGMP_v3_HOST_MEMBERSHIP_REPORT) / igmpv3.report()

    # Create an IGMPv3 change-to-include report for the given group
    # with no sources, which means we're leaving the group.
    # TODO Come up with sugar for this.
    rep = c.packets[3]
    rec0 = GroupRecordField("rec0")
    rec0.type.value = IGMP_CHANGE_TO_INCLUDE
    rec0.group.value = inet_atol(options.igmp_group)
    rep.records.append(rec0)
    rep.nrecords = len(rep.records)

    # Add Router Alert option.
    ip = c.packets[1]
    ip.options.append(ipv4opt(IPOPT_RA))

    # Compute outer IP header length. TODO Push this into the framework.
    ip.hlen = len(ip.bytes) >> 2
    ip.length = len(ip.bytes) + len(c.packets[2].bytes) + len(rep.bytes)

    c.calc_checksums()
    c.encode()

    # Send it.
    output = PcapConnector(options.ether_iface)
    out = output.write(c.bytes, len(c.bytes))

main()
