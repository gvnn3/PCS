# Copyright (c) 2006, Neville-Neil Consulting
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
# Description: Packet description and functions for Yahoo Messenger packets

import pcs

import inspect
import time

# ymsg packet = { int magic = "YMSG", short version, short id, short
# len (does not include header), short command, int status, int
# sessionid, data[]} data is a set of key/value pairs keys must always
# be ascii representations of positive integers keys and values are
# terminated by 0xc0 0x80 and that's all she wrote I'm looking for
# things that have odd #s of c080 separated terms, that don't end in
# c080, that have keys that aren't integers, etc..

class ymsg_hdr(pcs.Packet):
    """YMSG"""
    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None):
        """Define the fields for a Yahoo Messenger header.

        The header is followed by a set of key value pairs, defined in
        the ymsgkv class.
        """

        version = pcs.Field("version", 16)
        id = pcs.Field("id", 16)
        length = pcs.Field("length", 16)
        command = pcs.Field("command", 16)
        status = pcs.Field("status", 32)
        session = pcs.Field("session", 32)
        pcs.Packet.__init__(self,
                            [version, id, length, command, status, session],
                            bytes = bytes)
        self.description = inspect.getdoc(self)
        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp


class ymsg_key_value(pcs.Packet):

    _layout = pcs.Layout()

    def __init__(self, bytes = None):
        """The actual message is a set of key/value pairs encoded
        after the header.
        """
        key = pcs.LengthValueField("key", 16)
        value = pcs.LengthValueField("value", 16)
        pcs.Packet.__init__(self,
                            [key, value],
                            bytes = bytes)


        
