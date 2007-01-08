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
# File: $Id: pcs.py,v 1.6 2006/07/06 10:07:45 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A packet module for Python.  We will package the
# individual protocols separately.

# We need the struct module to pack our class into a byte string.
import struct

import itertools

def attribreprlist(obj, attrs):
    return map(lambda x, y = obj: '%s: %s' % (x, repr(getattr(y, x))), itertools.ifilter(lambda x, y = obj: hasattr(y, x), attrs))

class Field(object):
    """A field is a name, a type, a width in bits, and possibly a default
value.  These classes are used by the packet to define the layout of
the data and how it is addressed."""
    
    def __init__(self, name = "", width = 1, type = None, default = None):
        self.name = name
        self.width = width
        self.type = type
        self.default = default
        
    def __repr__(self):
        return "<pcs.Field  name %s, %d bits, type %s, default %s>" % \
               (self.name, self.width, self.type, self.default)

class Layout(list):
    """The layout is a special attribute of a Packet which implements
    the layout of the packet on the wire.  It is actually a list of
    Fields and is implemented as a descriptor.  A layout can only be
    set or get, but never deleted."""

    length = 0
    
    def __get__(self, obj, typ=None): 
        return self.layout

    # Update the layout itself.  Right now this does not handle
    # removing fields or anything else but must do so in future.
    # XXX Add code to check the type of the value, it must be a
    # list of Field objects

    def __set__(self, obj, value): 
        self.layout = value
        for field in self.layout:
            # This is a special case, we don't want to recurse back
            # through the encapsulating class's __setattr__ routine.
            # We want to set this directly in the class's dictionary
            if field.default == None:
                obj.__dict__[field.name] = 0
            else:
                obj.__dict__[field.name] = field.default

class FieldError(Exception):
    """When a programmer tries to set a field that is not in the
    layout this exception is raised."""

    def __init__(self, message):
        self.message = message
        

class Packet(object):
    """A Packet is a base class for building real packets."""

    # The layout is a list of fields without values that indicate how
    # the data in the packet is to be layed in terms of ordering and
    # bit widths.  The update() method, below, uses this list to build
    # the data in the packet.  The actual data is kept in
    # auto-generated class entries that are built whenever the layout
    # is changed.  A layout is implemented as a descriptor, above,
    # with only get() and set() methods and so cannot be deleted.
    # This allows the programmer to set fields in what might be
    # considered a natural way with a foo.bar = baz type of syntax.

    # The bytes are the actual bytes in network byte order of a fully
    # formed packet.  Packets are always fully formed as any setting
    # of a packet field generates a call to the update() method.

    _bytes = ""
    def getbytes(self):
        if self._needencode:
            self._needencode = False
            self.encode()
        return self._bytes

    # decode must be defined before its used in the property
    # that is set below it.
    def decode(self, bytes):
        """Reset the bytes field and then update the associated
        attributes of the packet.  This method is used when a packet
        is read in raw form."""
        self._bytes = bytes
        curr = 0
        byteBR = 8
        for field in self.layout:
            if curr > len(bytes):
                break
            if field.type is str:
                packarg = "%ds" % (field.width / 8)
                end = curr + field.width / 8
                real_value = struct.unpack(packarg, bytes[curr:end])[0]
                curr += field.width / 8
            else: 
                real_value = 0
                fieldBR = field.width
                while fieldBR > 0 and curr < len(bytes):
                    if fieldBR < byteBR:
                        shift = byteBR - fieldBR
                        value = ord(self._bytes[curr]) >> shift
                        byteBR -= fieldBR
                        fieldBR = 0 # next field
                    elif fieldBR > byteBR:
                        shift = fieldBR - byteBR
                        mask = 2 ** byteBR - 1
                        value = (ord(self._bytes[curr]) & mask)
                        fieldBR -= byteBR
                        byteBR = 8
                        curr += 1 # next byte
                    elif fieldBR == byteBR:
                        mask = 2 ** byteBR - 1
                        value = ord(self._bytes[curr]) & mask
                        fieldBR -= byteBR
                        byteBR = 8
                        curr += 1 # next byte
                    real_value += value << fieldBR
            object.__setattr__(self, field.name, real_value)

    bytes = property(getbytes, decode)

    bit_length = 0

    def __init__(self, layout = None, bytes = None):
        self.layout = layout
        self._needencode = True
        if bytes != None:
            self.decode(bytes)

    def __setattr__(self, name, value):
        """Setting the layout is a special case because of the
        ramifications this has on the packet.  Only fields represented
        in the layout may be set, no other attributes may be added"""

        # Check for overflow
#        if != "layout" && name in self.layout
#            try:
#                value < self._fieldnames[name]
            
        # First do the actual setting then handle the special cases
        object.__setattr__(self, name, value)

        if name == '_fieldnames':
            return

        # See if we're modifying a value that is controlled by the
        # layout.  If we are we need to update the bytes in the packet
        # so call update after we set the field.
        if (name != "layout"):
            if name in self._fieldnames:
                self._needencode = True
                return
        else:
            self._fieldnames = {}
            for field in self.layout:
                self._fieldnames[field.name] = True

    def __eq__(self, other):
        """Do a comparison of the packets data, including fields and bytes."""
        if (type(self) != type(other)):
            return False
        if (self.bytes != other.bytes):
            return False
        for field in self.layout:
            if self.__dict__[field.name] != other.__dict__[field.name]:
                return False
        return True

    def __ne__(self, other):
        """Do a comparison of the packets data, including fields and bytes."""
        return not self.__eq__(other)

    def __repr__(self):
        """Walk the entire packet and return the values of the fields."""
        if hasattr(self, 'description'):
            name = self.description
        else:
            name = 'Packet'
        return '<%s: %s>' % (name, ', '.join(attribreprlist(self, self._fieldnames.iterkeys())))

    def __str__(self):
        """Pretty print, with returns, the fields of the packet."""
        retval = ""
        for field in self.layout:
            retval += "%s %s\n" % (field.name, self.__dict__[field.name])
        return retval

    def __len__(self):
        "Return the count of the number of bytes in the packet."
        return len(self.bytes)

    def toXML(self):
        pass

    def fromXML(self):
        pass

    def toHTML(self):
        pass

    def fromHTML(self):
        pass

    def encode(self):
        """Update the internal bytes representing the packet.  This
        function ought to be considered private to the class."""

        # Encode the fields, which are a set of bit widths and values
        # into a byte string.  This is achieved by walking the list of
        # fields, and then packing them, byte by byte, into a byte
        # string.  The algorithm below hurts my head, as I'm not very
        # smart so it is heavily commented.
        #
        # fieldBR is the bits remaining in the field to be encoded
        # byteBR is the bits remaining in the current byte being encoded
        #
        
        byteBR = 8
        byte = 0
        bytearray = []
        for field in self.layout:
            value = object.__getattribute__(self, field.name)
            if type(value) is str:
                packarg = "%ds" % (field.width / 8)
                bytearray.append(struct.pack(packarg, value))
                continue
            fieldBR = field.width
            while byteBR > 0:
                if fieldBR < byteBR:
                    shift = byteBR - fieldBR
                    byteBR -= fieldBR
                    mask = ((2 ** shift) - 1) << shift
                    byte = (byte | ((value << shift) & mask))
                    # Done with the field, not with the byte get new field
                    break
                elif fieldBR > byteBR:
                    shift = fieldBR - byteBR
                    fieldBR -= byteBR
                    mask = ((2 ** byteBR) - 1)
                    byte = (byte | ((value >> shift) & mask))
                    bytearray.append(struct.pack('B', byte))
                    byteBR = 8
                    byte = 0
                    # Done with this byte, but not the field, get a new byte
                elif fieldBR == byteBR:
                    mask = ((2 ** byteBR) - 1)
                    byte = (byte | (value & mask))
                    bytearray.append(struct.pack('B', byte))
                    byte = 0
                    byteBR = 8
                    # Done with the byte and the field have a nice day
                    break

        self._bytes = ''.join(bytearray) # Install the new value
                
class Chain(list):
    """A chain is simply a list of packets.  Chains are used to
    aggregate related sub packets into one chunk for transmission."""

    packets = []
    bytes = ""

    def __init__(self, packets = None):
        list.__init__(self)
        self.packets = packets
        self.encode()

    def __eq__(self, other):
        if len(self.packets) != len(other.packets):
            return False
        for i in range(len(self.packets)):
            if self.packets[i] != other.packets[i]:
                return False
        return True
            
    def __ne__(self, other):
        return not self.__eq__(other)
            
    def __str__(self):
        retval = ""
        for packet in self.packets:
            retval += "%s " % packet.__str__()
        return retval
    
    def append(self, packet):
        """Append a packet to a chain.  Appending a packet requires
        that we update the bytes as well."""
        self.packets.append(packet)
        self.encode()

    def encode(self):
        for packet in self.packets:
            self.bytes += packet.bytes
    
    def decode(self, bytes):
        for packet in self.packets:
            packet.decode(packet.bytes)


class InvalidConnectorError(Exception):
    """If you specify a connetor type not in the known list we raise this
    error."""
    def __init__(self, message):
        self.message = message

class Connector(object):
    """Connectors are a way of have a very generic socket like
    mechanism over which the packets can be sent.  Unlike the current
    split between sockets, which work OK down to almost the RAW layer,
    and low level stuff like pcap and bpf, connectors will are a
    unifying mechanism so you can write packets over any of the
    available APIs and the connector will do the right thing.

    The Connector class is a virtual base class upon which all the
    real classes are based."""

    def __init__():
        pass

    def read():
        pass

    def write():
        pass

    def send():
        pass

    def sendto():
        pass

    def recv():
        pass

    def recvfrom():
        pass

    def close():
        pass

class PcapConnector(Connector):
    """A connector for protocol capture and injection using the pcap library
    """

    def __init__(self, name):
        from pcap import pcap
        try:
            self.file = pcap(name)
        except:
            raise

        # Grab the underlying pcap objects members for convenienc
        self.dloff = self.file.dloff
        self.setfilter = self.file.setfilter
        
    def read(self):
        return self.file.next()[1]

    def recv(self):
        return self.file.next()[1]
    
    def recvfrom(self):
        return self.file.next()[1]

    def write(self, packet, bytes):
        return self.file.inject(packet, bytes)

    def send(self, packet, bytes):
        return self.file.inject(packet, bytes)

    def sendto(self, packet, bytes):
        return self.file.inject(packet, bytes)

class UDP4Connector(Connector):
    """A connector for IPv4 UDP sockets
    """

    def __init__(self, name = None):
        from pcap import pcap
        try:
            self.file = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        except:
            raise

        # Grab the underlying pcap objects members for convenienc
        self.dloff = self.file.dloff
        self.setfilter = self.file.setfilter
        
    def read(self):
        return self.file.next()[1]

    def recv(self):
        return self.file.next()[1]
    
    def recvfrom(self):
        return self.file.next()[1]

    def write(self, packet, bytes):
        return self.file.inject(packet, bytes)

    def send(self, packet, bytes):
        return self.file.inject(packet, bytes)

    def sendto(self, packet, bytes):
        return self.file.inject(packet, bytes)

