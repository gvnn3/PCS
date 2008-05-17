# Copyright (c) 2005, Neville-Neil Consulting
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# Neither the name of Neville-Neil Consulting nor the names of its 
# contributors may be used to endorse or promote products derived from 
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# File: $Id: tcp.py,v 1.5 2006/07/06 09:31:57 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A class that describes a TCP packet.

import sys

import pcs
import tcp_map
from pcs import UnpackError
from pcs.packets import payload

import inspect
import time
import struct

class tcp(pcs.Packet):
    """TCP"""
    _layout = pcs.Layout()
    _map = None
    
    def __init__(self, bytes = None, timestamp = None, **kv):
        """initialize a TCP packet"""
        sport = pcs.Field("sport", 16)
        dport = pcs.Field("dport", 16)
        seq = pcs.Field("sequence", 32)
        acknum = pcs.Field("ack_number", 32)
        off = pcs.Field("offset", 4)
        reserved = pcs.Field("reserved", 6)
        urg = pcs.Field("urgent", 1)
        ack = pcs.Field("ack", 1)
        psh = pcs.Field("push", 1)
        rst = pcs.Field("reset", 1)
        syn = pcs.Field("syn", 1)
        fin = pcs.Field("fin", 1)
        window = pcs.Field("window", 16)
        checksum = pcs.Field("checksum", 16)
        urgp = pcs.Field("urg_pointer",16)
        options = pcs.OptionListField("options")
        pcs.Packet.__init__(self, [sport, dport, seq, acknum, off, reserved,
                                   urg, ack, psh, rst, syn, fin, window,
                                   checksum, urgp, options],
                            bytes = bytes,  **kv)
        self.description = inspect.getdoc(self)
        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        # Decode TCP options.
        if bytes != None:
            data_offset = self.offset * 4        # in bytes
            options_len = data_offset - self.sizeof()

            # Sanity check that the buffer we are given is large enough
            # to contain the TCP header, or else TCP option decode will
            # fail. This usually indicates a problem below, i.e. we
            # tried to copy a segment and didn't create fields to back
            # the options, causing the data to be lost.
            # If options are present then they must fit into the 40 byte
            # option area. We will perform this check during encoding later.

            if data_offset > len(bytes):
                raise UnpackError, \
                      "TCP segment is larger than input (%d > %d)" % \
                      (data_offset, len(bytes))

            if (options_len > 0):
                curr = self.sizeof()
                while (curr < data_offset):
                    option = struct.unpack('!B', bytes[curr])[0]

		    #print "(curr = %d, data_offset = %d, option = %d)" % \
		    #	  (curr, data_offset, option)

                    # Special-case options which do not have a length field.
                    if option == 0:        # end
                        options.append(pcs.Field("end", 8, default = 0))
                        curr += 1
                        #break              # immediately stop processing.
                        continue              # immediately stop processing.
                    elif option == 1:        # nop
                        options.append(pcs.Field("nop", 8, default = 1))
                        curr += 1
                        continue

                    optlen = struct.unpack('!B', bytes[curr+1])[0]
                    if (optlen < 1 or optlen > (data_offset - curr)):
                        raise UnpackError, \
                              "Bad length %d for TCP option %d" % \
                              (optlen, option)

                    # XXX we could break this out into a map.
                    # option lengths include the length of the code byte,
                    # length byte, and the option data. the fly in the
                    # buttermilk of course is that they do not 1:1 map
                    # onto TLVs, see above, but they need to if we plan
                    # to use the existing object model.
		    #print "\t(optlen %d)" % (optlen)

                    if option == 2:        # mss
			# XXX This is being thrown, not sure why.
                        #if optlen != 4:
			#    print options
                        #    raise UnpackError, \
                        #          "Bad length %d for TCP option %d, should be %d" % \
                        #          (optlen, option, 4)
                        value = struct.unpack("!H", bytes[curr+2:curr+4])[0]
			# XXX does tlv encode a length in bits or bytes??
			# 'cuz a second pass spits out 'it's optlen 16'"
			options.append(pcs.TypeLengthValueField("mss", \
				       pcs.Field("t", 8, default = option), \
				       pcs.Field("l", 8, default = optlen), \
				       pcs.Field("v", 16, default = value)))
                        curr += optlen
                    elif option == 3:        # wscale
                        if optlen != 3:
                            raise UnpackError, \
                                  "Bad length %d for TCP option %d, should be %d" % \
                                  (optlen, option, 3)
                        value = struct.unpack("B", bytes[curr+2:curr+3])[0]
			options.append(pcs.TypeLengthValueField("wscale", \
				       pcs.Field("t", 8, default = option), \
				       pcs.Field("l", 8, default = optlen), \
				       pcs.Field("v", 8, default = value)))
                        curr += optlen
                    elif option == 4:        # sackok
                        if optlen != 2:
                            raise UnpackError, \
                                  "Bad length %d for TCP option %d, should be %d" % \
                                  (optlen, option, 2)
		    	options.append(pcs.TypeLengthValueField("sackok", \
		    		       pcs.Field("t", 8, default = option), \
		    		       pcs.Field("l", 8, default = optlen), \
		    		       pcs.Field("v", 0, default = value)))
                        curr += optlen
                    elif option == 5:        # sack
                        # this is a variable length option, the permitted
 		    	# range is 2 + 1..4*sizeof(sackblock) subject
		    	# to any other options.
		    	sacklen = optlen - 2
                        value = struct.unpack("%dB" % sacklen,
		    			      bytes[curr+2:curr+sacklen])[0]
		    	options.append(pcs.TypeLengthValueField("sack", \
		    		       pcs.Field("t", 8, default = option), \
		    		       pcs.Field("l", 8, default = optlen), \
		    		       pcs.Field("v", sacklen * 8, default = value)))
                        curr += optlen
                    elif option == 8:        # tstamp
                        if optlen != 10:
                            raise UnpackError, \
                                  "Bad length %d for TCP option %d, should be %d" % \
                                  (optlen, option, 10)
                        value = struct.unpack("!2I", bytes[curr+2:curr+10])[0]
			options.append(pcs.TypeLengthValueField("tstamp", \
				       pcs.Field("t", 8, default = option), \
				       pcs.Field("l", 8, default = optlen), \
				       pcs.Field("v", 64, default = value)))
                        curr += optlen
                    #elif option == 19:        # md5
                    #    if optlen != 18:
                    #        raise UnpackError, \
                    #              "Bad length %d for TCP option %d, should be %d" % \
                    #              (optlen, option, 18)
                    #    value = struct.unpack("16B", bytes[curr+2:curr+16])[0]
		    #	options.append(pcs.TypeLengthValueField("md5", \
		    #		       pcs.Field("t", 8, default = option), \
		    #		       pcs.Field("l", 8, default = optlen), \
		    #		       pcs.Field("v", 64, default = value)))
                    #    curr += optlen
                    else:
                        #print "warning: unknown option %d" % option
			optdatalen = optlen - 2
			value = struct.unpack("!B", bytes[curr+2:curr+optdatalen])[0]
			options.append(pcs.TypeLengthValueField("unknown", \
				       pcs.Field("t", 8, default = option), \
				       pcs.Field("l", 8, default = optlen), \
				       pcs.Field("v", optdatalen * 8, default = value)))
                        curr += optlen

        if (bytes != None and (self.offset * 4 < len(bytes))):
            self.data = self.next(bytes[(self.offset * 4):len(bytes)],
                                  timestamp = timestamp)
        else:
            self.data = None

    # XXX TCP MUST have it's own next() function so that it can discrimnate
    # on either sport or dport.

    def next(self, bytes, timestamp):
        """Decode higher layer packets contained in TCP."""
        if (self.dport in tcp_map.map):
            return tcp_map.map[self.dport](bytes, timestamp = timestamp)
        if (self.sport in tcp_map.map):
            return tcp_map.map[self.sport](bytes, timestamp = timestamp)
        return None
    
    def __str__(self):
        """Walk the entire packet and pretty print the values of the fields.  Addresses are printed if and only if they are set and not 0."""
        retval = "TCP\n"
        for field in self._layout:
            retval += "%s %s\n" % (field.name, field.value)
        return retval

    def pretty(self, attr):
        """Pretty prting a field"""
        pass

    def cksum(self, ip, data = ""):
        """Calculate the TCP segment checksum outside of a chain."""
        from pcs.packets.ipv4 import ipv4
        from pcs.packets.ipv4 import pseudoipv4
        from socket import IPPROTO_TCP
        tmpip = ipv4.pseudoipv4()
        tmpip.src = ip.src
        tmpip.dst = ip.dst
        tmpip.protocol = IPPROTO_TCP
        tmpip.length = len(self.getbytes()) + len(data)
        pkt = tmpip.getbytes() + self.getbytes() + data
        return ipv4.ipv4_cksum(pkt)

    # XXX The following code is common to both the TCP and UDP modules,
    # and could be moved into another module or class.

    def calc_checksum(self):
        """Calculate and store the checksum for this TCP segment.
           The packet must be part of a chain.
           We attempt to infer whether IPv4 or IPv6 encapsulation
           is in use for the payload. The closest header wins the match.
           The network layer header must immediately precede the TCP
           segment (for now)."""
        from pcs.packets.ipv4 import ipv4
        ip = None
        ip6 = None
        if self._head is not None:
            (ip, iip) = self._head.find_preceding(self, pcs.packets.ipv4.ipv4)
            (ip6, iip6) = self._head.find_preceding(self, pcs.packets.ipv6.ipv6)
        # Either this TCP header is not in a chain, or no IPv4/IPv6
        # outer header was found.
        if ip is None and ip6 is None:
            self.checksum = 0
            self.checksum = ipv4.ipv4_cksum(self.getbytes())
            return
        # If we found both IPv4 and IPv6 headers then we must break the tie.
        # The closest outer header wins and is used for checksum calculation.
        if ip is not None and ip6 is not None:
            assert iip != iip6, "ipv4 and ipv6 cannot be at same index"
            if iip6 > iip:
                ip = None	# ip6 is nearest outer header, ignore ip
            else:
                ip6 = None	# ip is nearest outer header, ignore ip6
        if ip is not None:
            self.calc_checksum_v4(ip)
        else:
            self.calc_checksum_v6(ip6)

    def calc_checksum_v4(self, ip):
        """Calculate and store the checksum for the TCP segment
           when encapsulated as an IPv4 payload with the given header."""
        from pcs.packets.ipv4 import ipv4
        from pcs.packets.ipv4 import pseudoipv4
        from socket import IPPROTO_TCP
        self.checksum = 0
        payload = self._head.collate_following(self)
        pip = pseudoipv4()
        pip.src = ip.src
        pip.dst = ip.dst
        pip.protocol = IPPROTO_TCP
        pip.length = len(self.getbytes()) + len(payload)
        tmpbytes = pip.getbytes() + self.getbytes() + payload
        self.checksum = ipv4.ipv4_cksum(tmpbytes)

    def calc_checksum_v6(self, ip6):
        """Calculate and store the checksum for the TCP segment
           when encapsulated as an IPv6 payload with the given header."""
        from pcs.packets.ipv4 import ipv4
        from pcs.packets.pseudoipv6 import pseudoipv6
        self.checksum = 0
        payload = self._head.collate_following(self)
        pip6 = pseudoipv6()
        pip6.src = ip6.src
        pip6.dst = ip6.dst
        pip6.next_header = ip6.next_header
        pip6.length = len(self.getbytes()) + len(payload)
        tmpbytes = pip6.getbytes() + self.getbytes() + payload
        self.checksum = ipv4.ipv4_cksum(tmpbytes)
