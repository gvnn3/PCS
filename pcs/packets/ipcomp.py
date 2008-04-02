# Copyright (c) 2006, Clément Lecigne
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
# File: $Id $
#
# Author: Clément Lecigne
#
# Description: A class which implements IP payload Compression packets

import pcs

#socket module already defines it.
#IPPROTO_IPCOMP = 108

class ipcomp(pcs.Packet):

    _layout = pcs.Layout()

    def __init__(self, bytes = None):
        "A class that contains the IPComp header. RFC3173"
        nx = pcs.Field("next_header", 8)
        flags = pcs.Field("flags", 8)
        cpi = pcs.Field("cpi", 16)
        pcs.Packet.__init__(self, [nx, flags, cpi], bytes = bytes)

    def __str__(self):
        """Walk the entire packet and pretty print the values
        of the fields.  Addresses are printed if and only if 
        they are set and not 0."""
        retval = ""
        for field in self._layout:
            retval += "%s %d\n" % (field.name, field.value)
        return retval
