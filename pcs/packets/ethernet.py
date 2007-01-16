import pcs
from pcs.packets.ipv4 import ipv4
from pcs.packets.ipv6 import ipv6
from pcs.packets.arp import arp

ETHERTYPE_IP		= 0x0800	# IP protocol 
ETHERTYPE_ARP		= 0x0806	# Addr. resolution protocol
ETHERTYPE_REVARP	= 0x8035	# reverse Addr. resolution protocol
ETHERTYPE_VLAN		= 0x8100	# IEEE 802.1Q VLAN tagging
ETHERTYPE_IPV6		= 0x86dd	# IPv6

class ethernet(pcs.Packet):

    layout = pcs.Layout()

    def __init__(self, bytes = None):
        """initialize an ethernet packet"""
        src = pcs.StringField("src", 48)
        dst = pcs.StringField("dst", 48)
        type = pcs.Field("type", 16)
        etherlen = 14

        pcs.Packet.__init__(self, [dst, src, type], bytes = bytes)
        self.description = "Ethernet"
        if (bytes != None):
            self.data = self.next(bytes[etherlen:len(bytes)])
        else:
            self.data = None

    def __str__(self):
        """return a human readable version of an Ethernet packet"""
        retval = "Ethernet\n"
        retval += "dst: "
        for byte in range(0,5):
            retval += "%s:" % hex(ord(self.dst[byte]))[2:4]
        retval += "%s" % hex(ord(self.dst[5]))[2:4]

        retval += "\nsrc: "
        for byte in range(0,5):
            retval += "%s:" % hex(ord(self.src[byte]))[2:4]
        retval += "%s" % hex(ord(self.src[5]))[2:4]

        retval += "\ntype: %s" % hex(self.type)

        return retval

    def next(self, bytes):
        """Decode the type of a packet and return the correct higher
        level protocol object"""
        ## the ethertype of the packet
        if self.type == ETHERTYPE_ARP:
            return arp(bytes)
        if self.type == ETHERTYPE_IP:
            return ipv4(bytes)
        if self.type == ETHERTYPE_IPV6:
            return ipv6(bytes)
        return None

#
# Functions defined for the module.
#
def ether_atob(pretty):
    """Take a pretty version of an ethernet address and convert it to a
    string of bytes.

    The input string MUST be of the form xx:yy:zz:aa:bb:cc and leading
    zero's must be supplied.  Nor error checking is performed.
    """
    addr = ""
    for i in 0, 3, 6, 9, 12, 15:
        addr += "%c" % int(pretty[i:i+2], 16)
    return addr


def ether_btoa(bytes):
    """Take a set of bytes and convert them to a pretty version of
    and Ethernet address.

    The input buffer MUST be at least 6 bytes long and bytes after the
    sixth are ignored.  No error checking is performed.
    """

    pretty = ""
    for i in (range(5)):
        pretty += hex(ord(bytes[i]))[2:4] # Strip the 0x from the string
        pretty += ':'
        
    pretty += hex(ord(bytes[5]))[2:4] # Strip the 0x from the string

    return pretty
