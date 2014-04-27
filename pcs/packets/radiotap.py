# Copyright (c) 2008, Bruce M. Simpson.
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
# Neither the names of the author(s) or names of contributors may be
# used to endorse or promote products derived from this software without
# specific prior written permission.
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
# Author: Bruce M. Simpson
#
# Description: The Ethernet packet class

import pcs
import pcs.packets.payload
#import pcs.packets.ieee80211   #notyet

import struct
import time

# TODO: Move this into pcap.pyx.
DLT_IEEE802_11_RADIO = 127      # 802.11 with radiotap in front

#
# radiotap TLV IDs.
#
# The tag is effectively in the header field 'present', the
# lengths are not encoded in the packet; the values appear in
# order according to the ordinal value of each bit.
#
IEEE80211_RADIOTAP_TSFT = 0
IEEE80211_RADIOTAP_FLAGS = 1
IEEE80211_RADIOTAP_RATE = 2
IEEE80211_RADIOTAP_CHANNEL = 3
IEEE80211_RADIOTAP_FHSS = 4
IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5
IEEE80211_RADIOTAP_DBM_ANTNOISE = 6
IEEE80211_RADIOTAP_LOCK_QUALITY = 7
IEEE80211_RADIOTAP_TX_ATTENUATION = 8
IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9
IEEE80211_RADIOTAP_DBM_TX_POWER = 10
IEEE80211_RADIOTAP_ANTENNA = 11
IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12
IEEE80211_RADIOTAP_DB_ANTNOISE = 13
IEEE80211_RADIOTAP_XCHANNEL = 18
IEEE80211_RADIOTAP_EXT = 31

#
# IEEE80211_RADIOTAP_CHANNEL TLV contents.
#
IEEE80211_CHAN_TURBO = 0x00010
IEEE80211_CHAN_CCK = 0x00020
IEEE80211_CHAN_OFDM = 0x00040
IEEE80211_CHAN_2GHZ = 0x00080
IEEE80211_CHAN_5GHZ = 0x00100
IEEE80211_CHAN_PASSIVE = 0x00200
IEEE80211_CHAN_DYN = 0x00400
IEEE80211_CHAN_GFSK = 0x00800
IEEE80211_CHAN_GSM = 0x01000
IEEE80211_CHAN_STURBO = 0x02000
IEEE80211_CHAN_HALF = 0x04000
IEEE80211_CHAN_QUARTER = 0x08000
IEEE80211_CHAN_HT20 = 0x10000
IEEE80211_CHAN_HT40U = 0x20000
IEEE80211_CHAN_HT40D = 0x40000

#
# IEEE80211_RADIOTAP_FLAGS TLV contents.
#
IEEE80211_RADIOTAP_F_CFP = 0x01
IEEE80211_RADIOTAP_F_SHORTPRE = 0x02
IEEE80211_RADIOTAP_F_WEP = 0x04
IEEE80211_RADIOTAP_F_FRAG = 0x08
IEEE80211_RADIOTAP_F_FCS = 0x10
IEEE80211_RADIOTAP_F_DATAPAD = 0x20
IEEE80211_RADIOTAP_F_BADFCS = 0x40
IEEE80211_RADIOTAP_F_SHORTGI = 0x80

# To assist in printing CHANNEL and XCHANNEL.
channel_bits = "\x05TURBO\x06CCK\x07OFDM\x082GHZ"\
               "\x095GHZ\x0aPASSIVE\x0bDYN\x0cGFSK"\
               "\x0dGSM\x0eSTURBO\x0fHALF\x10QUARTER"\
               "\x11HT20\x12HT40U\x13HT40D"

# To assist in printing FLAGS.
flag_bits = "\x01CFP\x02SHORTPRE\x03WEP"\
            "\x04FRAG\x05FCS\x06DATAPAD"\
            "\x07BADFCS\x08SHORTGI"

def _channel(n, x):
    """Given a tuple returned by struct.unpack(), produce a list
       of decoded fields for a CHANNEL TLV."""
    assert isinstance(n, str)
    assert isinstance(x, tuple)
    ret = []
    ret += pcs.Field("chan_mhz", 8, default=x[0])
    ret += pcs.Field("chan_flags", 8, default=x[1])
    return ret

def _xchannel(n, x):
    """Given a tuple returned by struct.unpack(), produce a list
       of decoded fields for an XCHANNEL TLV."""
    assert isinstance(n, str)
    assert isinstance(x, tuple)
    ret = []
    ret += pcs.Field("xchan_flags", 32, default=x[0])
    ret += pcs.Field("xchan_mhz", 16, default=x[1])
    ret += pcs.Field("xchan_num", 8, default=x[2])
    ret += pcs.Field("xchan_hdbm", 8, default=x[3])
    return ret

#
# bitvalue: ( name1st, bitwidth, packfmt, makefieldfunc )
#
# XXX TODO: Force little-endian conversion if writing fields.
#
_vmap = {
        IEEE80211_RADIOTAP_TSFT: \
                ( "tsft", 64, '<Q', \
                  lambda n, x: [pcs.Field(n, 64, default=x[0])] ),
        IEEE80211_RADIOTAP_FLAGS:
                ( "flags", 8, '<B', \
                  lambda n, x: [pcs.Field(n, 8, default=x[0])] ),
        IEEE80211_RADIOTAP_RATE:
                ( "rate", 8, '<B', \
                  lambda n, x: [pcs.Field(n, 8, default=x[0])] ),
        IEEE80211_RADIOTAP_CHANNEL: \
                ( "chan_mhz", 32, '<HH', _channel ),
        IEEE80211_RADIOTAP_FHSS:
                ( "fhss", 16, '<H', \
                  lambda n, x: [pcs.Field(n, 8, default=x[0])] ),
        IEEE80211_RADIOTAP_DBM_ANTSIGNAL: \
                ( "dbm_antsignal", 8, '<b', \
                  lambda x: [pcs.Field(n, 8, default=x[0])] ),
        IEEE80211_RADIOTAP_DBM_ANTNOISE: \
                ( "dbm_antnoise", 8, '<b', \
                  lambda n, x: [pcs.Field(n, 8, default=x[0])] ),
        IEEE80211_RADIOTAP_LOCK_QUALITY: \
                ( "lock_quality", 16, '<H', \
                  lambda n, x: [pcs.Field(n, 16, default=x[0])] ),
        IEEE80211_RADIOTAP_TX_ATTENUATION: \
                ( "tx_attentuation", 16, '<H', \
                  lambda n, x: [pcs.Field(n, 16, default=x[0])] ),
        IEEE80211_RADIOTAP_DB_TX_ATTENUATION: \
                ( "db_tx_attentuation", 16, '<H', \
                  lambda n, x: [pcs.Field(n, 16, default=x[0])] ),
        IEEE80211_RADIOTAP_DBM_TX_POWER: \
                ( "dbm_tx_power", 8, '<b', \
                  lambda n, x: [pcs.Field(n, 8, default=x[0])] ),
        IEEE80211_RADIOTAP_ANTENNA: \
                ( "antenna", 8, '<B', \
                  lambda n, x: [pcs.Field(n, 8, default=x[0])] ),
        IEEE80211_RADIOTAP_DB_ANTSIGNAL: \
                ( "db_antsignal", 8, '<B', \
                  lambda n, x: [pcs.Field(n, 8, default=x[0])] ),
        IEEE80211_RADIOTAP_DB_ANTNOISE: \
                ( "db_antnoise", 8, '<B', \
                  lambda n, x: [pcs.Field(n, 8, default=x[0])] ),
        IEEE80211_RADIOTAP_XCHANNEL:
                ( "xchan_flags", 8, '<IHBb', _xchannel )
}

class radiotap(pcs.Packet):
    """Radiotap"""

    _layout = pcs.Layout()
    _bits = "\x01TSFT\x02FLAGS\x03RATE\x04CHANNEL"\
            "\x05FHSS\x06DBM_ANTSIGNAL\x07DBM_ANTNOISE"\
            "\x08LOCK_QUALITY\x09TX_ATTENUATION\x0aDB_TX_ATTENUATION"\
            "\x0bDBM_TX_POWER\x0cANTENNA\x0dDB_ANTSIGNAL"\
            "\x0eDB_ANTNOISE\x13XCHANNEL\x20EXT"

    def __init__(self, bytes = None, timestamp = None, **kv):
        """initialize an ethernet packet"""
        version = pcs.Field("version", 8)               # currently 0.
        pad = pcs.Field("pad", 8)
        len = pcs.Field("len", 16)                      # inclusive.
        present = pcs.Field("present", 32)              # Bit mask.
        tlvs = pcs.OptionListField("tlvs")

        pcs.Packet.__init__(self, [version, pad, len, present, tlvs], \
                            bytes = bytes, **kv)
        self.description = "initialize an ethernet packet"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = self.sizeof()
            curr = offset
            remaining = min(len(bytes), self.len) - offset
            # Force little-endian conversion.
            # TODO: Process the EXT bit.
            he_prez = struct.unpack('<i', bytes[4:4])
            for i in range(IEEE80211_RADIOTAP_TSFT, \
                            IEEE80211_RADIOTAP_XCHANNEL+1):
                if (he_prez & (1 << i)) != 0:
                    if i in _vmap:
                        vt = _vmap[i]
                        vname = vt[0]
                        vbytes = vt[1] >> 3
                        vfmt = vt[2]
                        vfunc = vt[3]
                        if remaining >= vbytes:
                            value = struct.unpack(vfmt, bytes[curr:vlen])
                            fields = vfunc(vname, value)
                            for f in fields:
                                tlvs._options.append(f)
                            curr += vlen
                            remaining -= vlen
                        else:
                            break
            # XXX TODO: always decode next header as a full 802.11 header.
            self.data = payload.payload(bytes[curr:remaining], \
                                        timestamp = timestamp)
        else:
            self.data = None

    def __str__(self):
        """Walk the entire packet and pretty print the values of the fields."""
        s = self._descr[self.type] + "\n"
        for fn in self._layout:
            f = self._fieldnames[fn.name]
            if fn.name == "present":
                bs = bsprintf(f.value, self._bits)
                retval += "%s %s\n" % (fn.name, bs)
            else:
                retval += "%s %s\n" % (fn.name, f.value)
        return retval
