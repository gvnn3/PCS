# Copyright (c) 2007, Neville-Neil Consulting
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
# File: $Id: $
#
# Author: George V. Neville-Neil
#
# Description: SCTP Packet
#
# An SCTP packet is a common header followed by a set of chunks, each
# chunk is its own packet wrt PCS.

import pcs
import tcp_map

class common(pcs.Packet):
    """SCTP common header class"""

    _layout = pcs.Layout()
    
    def __init__(self, bytes=None):
        """common header initialization"""
        sport = pcs.Field("sport", 16)
        dport = pcs.Field("dport", 16)
        tag = pcs.Field("tag", 32)
        checksum = pcs.Field("checksum", 32)
        pcs.Packet.__init__(self, [sport, dport, tag, checksum],
                            bytes = bytes)
        self.description = inspect.getdoc(self)

        if (bytes != None):
            self.data = self.next(bytes[0:len(bytes)])
        else:
            self.data = None

class payload(pcs.Packet):
    """SCTP payload chunk class"""

    _layout = pcs.Layout()
    
    def __init__(self, bytes=None):
        """common header initialization"""
        type = pcs.Field("type", 8, default = 0)
        reserved = pcs.Field("reserved", 5)
        unordered = pcs.Field("unordered", 1)
        beginning = pcs.Field("beginning", 1)
        ending = pcs.Field("ending", 1)
        length = pcs.Field("length", 16)
        tsn = pcs.Field("tsn", 32)
        stream_id = pcs.Field("stream_id", 16)
        stream_seq = pcs.Field("stream_seq", 16)
        ppi = pcs.Field("ppi", 32)
        pcs.Packet.__init__(self,
                            [type, reserved, unordered, beginning, ending, 
                             length, tsn, stream_im, stream_seq, ppi],
                            bytes = bytes)
        self.description = inspect.getdoc(self)

        if (bytes != None):
            self.data = self.next(bytes[0:len(bytes)])
        else:
            self.data = None

# INIT and INIT ACK are basically the same other than the type add
# some parameters

class init(pcs.Packet):
    """SCTP init or init ack chunk"""

    _layout = pcs.Layout()
    
    def __init__(self, bytes=None):
        """init or init ack chunk"""
        type = pcs.Field("type", 8)
        flags = pcs.Field("flags", 8)
        length = pcs.Field("length", 16)
        tag = pcs.Field("tag", 32)
        adv_recv_win_cred = pcs.Field("adv_recv_win_cred", 32)
        outbound_streams = pcs.Field("outbound_streams", 16)
        inbound_streams = pcs.Field("inbound_streams", 16)
        initial_tsn = pcs.Field("initial_tsn", 32)
        pcs.Packet.__init__(self, [type, flags, length, tag, 
                                   adv_recv_win_cred, outbound_streams,
                                   inbound_streams, initial_tsn],
                            bytes = bytes)
        self.description = inspect.getdoc(self)

        if (bytes != None):
            self.data = self.next(bytes[0:len(bytes)])
        else:
            self.data = None

class sack(pcs.Packet):
    """SCTP ACK chunk"""

    _layout = pcs.Layout()
    
    def __init__(self, bytes=None):
        """common header initialization"""
        type = pcs.Field("type", 8, default = 3)
        flags = pcs.Field("flags", 8)
        length = pcs.Field("length", 16)
        cumulative_tsn_ack = pcs.Field("cumulative_tsn_ack", 32)
        adv_recv_win_cred = pcs.Field("adv_recv_win_cred", 32)
        gap_ack_blocks = pcs.Field("gap_ack_blocks", 16)
        duplicate_tsns = pcs.Field("duplicate_tsns", 16)
        pcs.Packet.__init__(self, [type, flag, length,
                                   cumulative_tsn_ack,
                                   adv_recv_win_cred,
                                   gap_ack_blocks,
                                   duplicate_tsns],
                            bytes = bytes)
        self.description = inspect.getdoc(self)

        if (bytes != None):
            self.data = self.next(bytes[0:len(bytes)])
        else:
            self.data = None

class heartbeat(pcs.Packet):
    """SCTP heartbeat chunk"""

    _layout = pcs.Layout()
    
    def __init__(self, bytes=None):
        """common header initialization"""
        type = pcs.Field("type", 8, default = 4)
        flags = pcs.Field("flags", 8)
        length = pcs.Field("length", 16)
        pcs.Packet.__init__(self, [type, flags, length],
                            bytes = bytes)
        self.description = inspect.getdoc(self)

        if (bytes != None):
            self.data = self.next(bytes[0:len(bytes)])
        else:
            self.data = None

class abort(pcs.Packet):
    """SCTP abort chunk"""

    _layout = pcs.Layout()
    
    def __init__(self, bytes=None):
        """common header initialization"""
        type = pcs.Field("type", 8, default = 6)
        reserved = pcs.Field("reserved", 7)
        tag = pcs.Field("tag", 1)
        length = pcs.Field("length", 16)
        pcs.Packet.__init__(self, [type, reserved, tag, length],
                            bytes = bytes)
        self.description = inspect.getdoc(self)

        if (bytes != None):
            self.data = self.next(bytes[0:len(bytes)])
        else:
            self.data = None

class shutdown(pcs.Packet):
    """SCTP shutdown chunk"""

    _layout = pcs.Layout()
    
    def __init__(self, bytes=None):
        """common header initialization"""
        type = pcs.Field("type", 8, default = 7)
        flags = pcs.Field("flags", 8)
        length = pcs.Field("length", 16, default = 8)
        cumulative_tsn = pcs.Field("cumulative_tsn", 32)
        pcs.Packet.__init__(self, [type, flags, length, cumulative_tsn],
                            bytes = bytes)
        self.description = inspect.getdoc(self)

        if (bytes != None):
            self.data = self.next(bytes[0:len(bytes)])
        else:
            self.data = None

class shutdown_ack(pcs.Packet):
    """SCTP Shutdown ACK Chunk"""

    _layout = pcs.Layout()
    
    def __init__(self, bytes=None):
        """common header initialization"""
        type = pcs.Field("type", 8, default = 1)
        flags = pcs.Field("flags", 8)
        length = pcs.Field("length", 16, default = 4)
        pcs.Packet.__init__(self, [type, flags, length],
                            bytes = bytes)
        self.description = inspect.getdoc(self)

        if (bytes != None):
            self.data = self.next(bytes[0:len(bytes)])
        else:
            self.data = None

class operation_error(pcs.Packet):
    """SCTP operation error chunk"""

    _layout = pcs.Layout()
    
    def __init__(self, bytes=None):
        """common header initialization"""
        type = pcs.Field("type", 8, default = 9)
        flags = pcs.Field("flags", 8)
        length = pcs.Field("length", 16)
        pcs.Packet.__init__(self, [type, flags, length],
                            bytes = bytes)
        self.description = inspect.getdoc(self)

        if (bytes != None):
            self.data = self.next(bytes[0:len(bytes)])
        else:
            self.data = None

class cookie_echo(pcs.Packet):
    """SCTP Cookie Echo Chunk"""

    _layout = pcs.Layout()
    
    def __init__(self, bytes=None):
        """common header initialization"""
        type = pcs.Field("type", 8, default = 10)
        flags = pcs.Field("flags", 8)
        length = pcs.Field("length", 16)
        pcs.Packet.__init__(self, [type, flags, length],
                            bytes = bytes)
        self.description = inspect.getdoc(self)

        if (bytes != None):
            self.data = self.next(bytes[0:len(bytes)])
        else:
            self.data = None

class cookie_ack(pcs.Packet):
    """SCTP Cookie ACK"""

    _layout = pcs.Layout()
    
    def __init__(self, bytes=None):
        """common header initialization"""
        type = pcs.Field("type", 8, default = 11)
        flags = pcs.Field("flags", 8)
        length = pcs.Field("length", 16, default = 4)
        pcs.Packet.__init__(self, [type, flags, length],
                            bytes = bytes)
        self.description = inspect.getdoc(self)

        if (bytes != None):
            self.data = self.next(bytes[0:len(bytes)])
        else:
            self.data = None

class shutdown_complete(pcs.Packet):
    """SCTP Shutodwn Complete"""

    _layout = pcs.Layout()
    
    def __init__(self, bytes=None):
        """common header initialization"""
        type = pcs.Field("type", 8, default = 14)
        reserved = pcs.Field("reserved", 7)
        tag = pcs.Field("tag", 1)
        length = pcs.Field("length", 16, default = 4)
        pcs.Packet.__init__(self, [type, reserved, tag, length],
                            bytes = bytes)
        self.description = inspect.getdoc(self)

        if (bytes != None):
            self.data = self.next(bytes[0:len(bytes)])
        else:
            self.data = None
