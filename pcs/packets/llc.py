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
# Description: Classes which describe IEEE 802.2 LLC/SNAP headers.
#

import struct
import time

import pcs
from pcs.packets import payload
from . import ethernet_map

#
# Unnumbered LLC frame control values
#
LLC_UI = 0x3
LLC_UI_P = 0x13
LLC_DISC = 0x43
LLC_DISC_P = 0x53
LLC_UA = 0x63
LLC_UA_P = 0x73
LLC_TEST = 0xe3
LLC_TEST_P = 0xf3
LLC_FRMR = 0x87
LLC_FRMR_P = 0x97
LLC_DM = 0x0f
LLC_DM_P = 0x1f
LLC_XID = 0xaf
LLC_XID_P = 0xbf
LLC_SABME = 0x6f
LLC_SABME_P = 0x7f

#
# Supervisory LLC frame control values
#
LLC_RR = 0x01
LLC_RNR = 0x05
LLC_REJ = 0x09
LLC_INFO = 0x00

#
# Common SAPs.
#
LLC_8021D_LSAP = 0x42
LLC_X25_LSAP = 0x7e
LLC_SNAP_LSAP = 0xaa
LLC_ISO_LSAP = 0xfe

# This is a case where there is more than one discriminator.
class llc(pcs.Packet):
    """IEEE 802.2 LLC"""

    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        dsap = pcs.Field("dsap", 8)
        ssap = pcs.Field("ssap", 8)
        control = pcs.Field("control", 8)       # snd_x2 in an I-frame.
        opt = pcs.OptionListField("opt")

        pcs.Packet.__init__(self, [dsap, ssap, opt], bytes = bytes, **kv)
        self.description = "IEEE 802.2 LLC"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = self.sizeof()
            curr = offset
            remaining = len(bytes) - offset
            # TODO: Decode other fields.
            # For now, just do the minimum to parse 802.11 and 802.1d frames.
            if self.ssnap == LLC_8021D_LSAP and \
               self.dsnap == LLC_8021D_LSAP and \
               self.control == LLC_UI:
                from .ieee8021d import bpdu
                self.data = bpdu(bytes[curr:remaining], timestamp = timestamp)
            elif self.ssnap == LLC_SNAP_LSAP and \
               self.dsnap == LLC_SNAP_LSAP and \
               self.control == LLC_UI and remaining <= 3:
                oui = pcs.StringField("oui", 24, default=bytes[curr:curr+3])
                curr += 3
                remaining -= 3
                if oui.value == "\x00\x00\x00" and remaining <= 2:
                    etype = pcs.Field("etype", 16, bytes[curr:curr+2],
                                      discriminator=True) # XXX
                    curr += 2
                    remaining -= 2
                    self.data = self.next(bytes[curr:remaining], \
                                          timestamp = timestamp)
            if self.data is None:
               self.data = payload.payload(bytes[curr:remaining], \
                                           timestamp = timestamp)
        else:
            self.data = None

    def next(self, bytes, timestamp):
        """Decapsulate Ethernet SNAP header."""
        oui = None
        etype = None
        for o in self.opt._options:
            if o.name == 'oui':
                oui = o.value
            if o.name == 'etype':
                etype = o.value
            if oui is not None and etype is not None:
                break
        if oui is not None and oui.value == "\x00\x00\x00" and \
           etype is not None:
            return ethernet_map.map[etype](bytes, timestamp=timestamp)
        return None

    def has_i_bit(dsap):
        return ((dsap & 0x80) == 0x80)

    def has_g_bit(dsap):
        return not has_i_bit(ssap)

    def has_c_bit(ssap):
        return ((ssap & 0x80) == 0x80)

    def has_r_bit(ssap):
        return not has_c_bit(ssap)

    def is_individual(self):
        return has_i_bit(self.dsap)

    def is_group(self):
        return has_g_bit(self.dsap)

    def is_command(self):
        return has_c_bit(self.ssap)

    def is_response(self):
        return has_r_bit(self.ssap)

    has_i_bit = staticmethod(has_i_bit)
    has_g_bit = staticmethod(has_g_bit)
    has_c_bit = staticmethod(has_c_bit)
    has_r_bit = staticmethod(has_r_bit)
