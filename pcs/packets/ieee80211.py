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
# Neither the name of the author nor the names of other
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
# File: $Id$
#
# Author: Bruce M. Simpson
#
# Description: Classes which describe IEEE 802.11 headers.
#

import struct
import time

import pcs
import pcs.packets.llc
import pcs.packets.payload

IEEE80211_FC0_VERSION_MASK = 0x03
IEEE80211_FC0_VERSION_SHIFT = 0
IEEE80211_FC0_VERSION_0 = 0x00
IEEE80211_FC0_TYPE_MASK = 0x0c
IEEE80211_FC0_TYPE_SHIFT = 2
IEEE80211_FC0_TYPE_MGT = 0x00
IEEE80211_FC0_TYPE_CTL = 0x04
IEEE80211_FC0_TYPE_DATA = 0x08
IEEE80211_FC0_SUBTYPE_MASK = 0xf0
IEEE80211_FC0_SUBTYPE_SHIFT = 4

#
# Management frame bits
#
IEEE80211_FC0_SUBTYPE_ASSOC_REQ = 0x00
IEEE80211_FC0_SUBTYPE_ASSOC_RESP = 0x10
IEEE80211_FC0_SUBTYPE_REASSOC_REQ = 0x20
IEEE80211_FC0_SUBTYPE_REASSOC_RESP = 0x30
IEEE80211_FC0_SUBTYPE_PROBE_REQ = 0x40
IEEE80211_FC0_SUBTYPE_PROBE_RESP = 0x50
IEEE80211_FC0_SUBTYPE_BEACON = 0x80
IEEE80211_FC0_SUBTYPE_ATIM = 0x90
IEEE80211_FC0_SUBTYPE_DISASSOC = 0xa0
IEEE80211_FC0_SUBTYPE_AUTH = 0xb0
IEEE80211_FC0_SUBTYPE_DEAUTH = 0xc0
IEEE80211_FC0_SUBTYPE_ACTION = 0xd0

#
# Control frame bits
#
IEEE80211_FC0_SUBTYPE_BAR = 0x80
IEEE80211_FC0_SUBTYPE_PS_POLL = 0xa0
IEEE80211_FC0_SUBTYPE_RTS = 0xb0
IEEE80211_FC0_SUBTYPE_CTS = 0xc0
IEEE80211_FC0_SUBTYPE_ACK = 0xd0
IEEE80211_FC0_SUBTYPE_CF_END = 0xe0
IEEE80211_FC0_SUBTYPE_CF_END_ACK = 0xf0

#
# Data frame bits
#
IEEE80211_FC0_SUBTYPE_DATA = 0x00
IEEE80211_FC0_SUBTYPE_CF_ACK = 0x10
IEEE80211_FC0_SUBTYPE_CF_POLL = 0x20
IEEE80211_FC0_SUBTYPE_CF_ACPL = 0x30
IEEE80211_FC0_SUBTYPE_NODATA = 0x40
IEEE80211_FC0_SUBTYPE_CFACK = 0x50
IEEE80211_FC0_SUBTYPE_CFPOLL = 0x60
IEEE80211_FC0_SUBTYPE_CF_ACK_CF_ACK = 0x70
IEEE80211_FC0_SUBTYPE_QOS = 0x80
IEEE80211_FC0_SUBTYPE_QOS_NULL = 0xc0

#
# Direction
#
IEEE80211_FC1_DIR_MASK = 0x03
IEEE80211_FC1_DIR_NODS = 0x00
IEEE80211_FC1_DIR_TODS = 0x01
IEEE80211_FC1_DIR_FROMDS = 0x02
IEEE80211_FC1_DIR_DSTODS = 0x03

IEEE80211_FC1_MORE_FRAG = 0x04
IEEE80211_FC1_RETRY = 0x08
IEEE80211_FC1_PWR_MGT = 0x10
IEEE80211_FC1_MORE_DATA = 0x20
IEEE80211_FC1_WEP = 0x40
IEEE80211_FC1_ORDER = 0x80

IEEE80211_SEQ_FRAG_MASK = 0x000f
IEEE80211_SEQ_FRAG_SHIFT = 0
IEEE80211_SEQ_SEQ_MASK = 0xfff0
IEEE80211_SEQ_SEQ_SHIFT = 4
IEEE80211_SEQ_RANGE = 4096

IEEE80211_NWID_LEN = 32

IEEE80211_QOS_TXOP = 0x00ff
IEEE80211_QOS_AMSDU = 0x80
IEEE80211_QOS_AMSDU_S = 7
IEEE80211_QOS_ACKPOLICY = 0x60
IEEE80211_QOS_ACKPOLICY_S = 5
IEEE80211_QOS_ACKPOLICY_NOACK = 0x20
IEEE80211_QOS_ACKPOLICY_BA = 0x60
IEEE80211_QOS_ESOP = 0x10
IEEE80211_QOS_ESOP_S = 4
IEEE80211_QOS_TID = 0x0f


#struct ieee80211_frame_min {
#       uint8_t         i_fc[2];
#       uint8_t         i_dur[2];
#       uint8_t         i_addr1[IEEE80211_ADDR_LEN];
#       uint8_t         i_addr2[IEEE80211_ADDR_LEN];
#} __packed;
#
#struct ieee80211_frame_rts {
#       uint8_t         i_fc[2];
#       uint8_t         i_dur[2];
#       uint8_t         i_ra[IEEE80211_ADDR_LEN];
#       uint8_t         i_ta[IEEE80211_ADDR_LEN];
#} __packed;
#
#struct ieee80211_frame_cts {
#       uint8_t         i_fc[2];
#       uint8_t         i_dur[2];
#       uint8_t         i_ra[IEEE80211_ADDR_LEN];
#} __packed;
#
#struct ieee80211_frame_ack {
#       uint8_t         i_fc[2];
#       uint8_t         i_dur[2];
#       uint8_t         i_ra[IEEE80211_ADDR_LEN];
#} __packed;
#
#struct ieee80211_frame_pspoll {
#       uint8_t         i_fc[2];
#       uint8_t         i_aid[2];
#       uint8_t         i_bssid[IEEE80211_ADDR_LEN];
#       uint8_t         i_ta[IEEE80211_ADDR_LEN];
#} __packed;
#
#struct ieee80211_frame_cfend {         /* NB: also CF-End+CF-Ack */
#       uint8_t         i_fc[2];
#       uint8_t         i_dur[2];       /* should be zero */
#       uint8_t         i_ra[IEEE80211_ADDR_LEN];
#       uint8_t         i_bssid[IEEE80211_ADDR_LEN];
#} __packed;

# TODO: WME elements.
#class wme_info(pcs.Packet):
#class wme_tspec(pcs.Packet):
#class wme_acparams(pcs.Packet):
#class wme_param(pcs.Packet):

# TODO: Management frames.
#class mnf(pcs.Packet):
#class action(pcs.Packet):
#class min(pcs.Packet):
#class rts(pcs.Packet):
#class cts(pcs.Packet):
#class ack(pcs.Packet):
#class pspoll(pcs.Packet):
#class cfend(pcs.Packet):
#class bar(pcs.Packet):
#class beacon(pcs.Packet):


# TODO: define syntactic sugar for data frames, etc.

class frame(pcs.Packet):
    """IEEE 802.11 frame header"""

    _layout = pcs.Layout()
    _map = None
    _descr = None

    def __init__(self, bytes = None, timestamp = None, **kv):
        fc0 = pcs.Field("fc", 8)
        fc1 = pcs.Field("fc", 8)
        dur = pcs.Field("dur", 16)
        # XXX These following fields are in fact all optional...
        addr1 = pcs.StringField("addr1", 48)
        addr2 = pcs.StringField("addr2", 48)
        addr3 = pcs.StringField("addr3", 48)
        seq = pcs.Field("seq", 16)
        # Optional parts of header follow.
        opt = pcs.OptionListField("opt")

        pcs.Packet.__init__(self, [fc, dur, addr1, addr2, addr3, seq, opt], \
                            bytes = bytes, **kv)
        self.description = "IEEE 802.11 frame header"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = self.sizeof()
            curr = offset
            remaining = len(bytes) - offset
            # XXX addr2,3,seq above are optional too.
            if has_qos_bits(self.fc0) and remaining <= 2:
                value = struct.unpack('!H', bytes[curr:curr+2])
                opt.options.append(pcs.Field("qos", 16, default=value))
                curr += 2
                remaining += 2
            if has_addr4_bits(self.fc1) and remaining <= 6:
                opt._options.append(pcs.StringField("addr4", 48, \
                                                    default=bytes[curr:curr+6]))
                curr += 6
                remaining += 6

            self.data = llc.llc(bytes[curr:remaining], timestamp = timestamp)
            if self.data is None:
                self.data = payload.payload(bytes[curr:remaining], \
                                            timestamp = timestamp)
        else:
            self.data = None

    def has_data_bit(fc0):
        """Return True if the FC0 bits indicate a data frame."""
        return ((fc0 & (IEEE80211_FC0_TYPE_MASK)) == IEEE80211_FC0_TYPE_DATA)

    def has_ctl_bit(fc0):
        """Return True if the FC0 bits indicate a data frame."""
        return ((fc0 & (IEEE80211_FC0_TYPE_MASK)) == IEEE80211_FC0_TYPE_CTL)

    def has_mgmt_bit(fc0):
        """Return True if the FC0 bits indicate a management frame."""
        return ((fc0 & (IEEE80211_FC0_TYPE_MASK)) == IEEE80211_FC0_TYPE_MGT)

    def has_qos_bits(fc0):
        """Return True if the FC0 bits indicate a QOS frame."""
        return (fc0 & (IEEE80211_FC0_TYPE_MASK|IEEE80211_FC0_SUBTYPE_QOS)) == \
                      (IEEE80211_FC0_TYPE_DATA|IEEE80211_FC0_SUBTYPE_QOS)

    def has_addr4_bits(fc1):
        """Return True if the FC1 bits indicate a frame with 4 addresses."""
        return ((fc1 & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS)

    def is_data(self):
        return has_data_bit(self.fc0)

    def is_management(self):
        return has_mgmt_bit(self.fc0)

    def is_control(self):
        return has_ctl_bit(self.fc0)

    has_addr4_bit = staticmethod(has_addr4_bit)
    has_ctl_bit = staticmethod(has_ctl_bit)
    has_data_bit = staticmethod(has_data_bit)
    has_mgmt_bit = staticmethod(has_mgmt_bit)
    has_qos_bits = staticmethod(has_qos_bits)


class plcp(pcs.Packet):
    """IEEE 802.11 PLCP"""

    _layout = pcs.Layout()
    _map = None
    _descr = None

    def __init__(self, bytes = None, timestamp = None, **kv):
        sfd = pcs.Field("sfd", 16, default=0xF3A0) # start frame delimiter
        signal = pcs.Field("signal", 8)
        service = pcs.Field("service", 8)
        length = pcs.Field("length", 16)        # duration!
        crc = pcs.Field("crc", 16)

        pcs.Packet.__init__(self, [sfd, signal, service, length, crc], \
                            bytes = bytes, **kv)
        self.description = "IEEE 802.11 PLCP"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            self.data = frame(bytes[self.sizeof():len(bytes)],
                              timestamp = timestamp)
        else:
            self.data = None

    #def calc_checksum(self):
    # XXX TODO: Implement CRC-16.
