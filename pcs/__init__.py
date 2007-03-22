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
# File: $Id: __init__.py,v 1.9 2006/09/05 07:30:56 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A packet module for Python.  We will package the
# individual protocols separately.

"""PCS aka Packet Construction Set

PCS is a set of Python modules and objects that make building network
protocol testing tools easier for the protocol developer.  The core of
the system is the pcs module itself which provides the necessary
functionality to create classes that implement packets.

In PCS every packet is a class and the layout of the packet is defined
by a Layout class which contains a set of Fields.  Fields can be from
1 to many bits, so it is possible to build packets with arbitrary
width bit fields.  Fields know about the widths and will throw
exceptions when they are overloaded.

Every Packet object, that is an object instantiated from a specific
PCS packet class, has a field named bytes which shows the
representation of the data in the packet at that point in time.  It is
the bytes field that is used when transmitting the packet on the wire.

For more information please see the manual, called pcs, and available in various
formats after installation.
"""

__revision__ = "$Id: __init__.py,v 1.9 2006/09/05 07:30:56 gnn Exp $"

# We need the struct module to pack our class into a byte string.
import struct

# We need the socket module for to implement some of the Connector classes.
from socket import *

import pcs.pcap as pcap

import itertools

def attribreprlist(obj, attrs):
    return map(lambda x, y = obj: '%s: %s' % (x, repr(getattr(y, x))), itertools.ifilter(lambda x, y = obj: hasattr(y, x), attrs))

class FieldBoundsError(Exception):
    """When a programmer tries to set a field with an inappropriately
    sized piece of data this exception is raised."""

    def __init__(self, message):
        self.message = message
    def __str__(self):
        return repr(self.message)
    
class Field(object):
    """A field is a name, a type, a width in bits, and possibly a
default value.  These classes are used by the packet to define the
layout of the data and how it is addressed."""
    
    def __init__(self, name = "", width = 1, default = None):
        """initialize a field

        name - a string name
        width - a width in bits
        default - a default value
        """
        ## the name of the Field
        self.name = name
        ## the width, in bites, of the field's data
        self.width = width
        ## the default value of the field, must fit into bits
        self.default = default
        
    def __repr__(self):
        """return an appropriate representation for the Field object"""
        return "<pcs.Field  name %s, %d bits, type %s, default %s>" % \
               (self.name, self.width, self.type, self.default)

    def decode(self, bytes, curr, byteBR):
        """Decode a field and return the value and the updated current
        pointer into the bytes array"""
        real_value = 0
        fieldBR = self.width
        while fieldBR > 0 and curr < len(bytes):
            if fieldBR < byteBR:
                shift = byteBR - fieldBR
                value = ord(bytes[curr]) >> shift
                byteBR -= fieldBR
                fieldBR = 0 # next field
            elif fieldBR > byteBR:
                shift = fieldBR - byteBR
                mask = 2 ** byteBR - 1
                value = (ord(bytes[curr]) & mask)
                fieldBR -= byteBR
                byteBR = 8
                curr += 1 # next byte
            elif fieldBR == byteBR:
                mask = 2 ** byteBR - 1
                value = ord(bytes[curr]) & mask
                fieldBR -= byteBR
                byteBR = 8
                curr += 1 # next byte
            real_value += value << fieldBR
        return [real_value, curr, byteBR]

    def encode(self, bytearray, value, byte, byteBR):
        """encode the a field into the bytes necessary to transmit it
        as part of a packet

        bytearray - the array of bytes that will be returned
        value - the value to encode
        byte - the byte we are encoding, we can encode partial bytes
        byteBR - the bits remaining in the current byte being encoded.
        """
        # The algorithm below hurts my head, as I'm not very
        # smart so it is heavily commented.
        #
        # fieldBR is the bits remaining in the field to be encoded
        # byteBR is the bits remaining in the current byte being encoded
        
        fieldBR = self.width
        while byteBR > 0:
            if fieldBR < byteBR:
                shift = byteBR - fieldBR
                byteBR -= fieldBR
                mask = ((2 ** fieldBR) - 1) << shift
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

        return [byte, byteBR]

    def reset(self):
        """Return a resonable value to use in resetting a field of this type."""
        return 0

    def bounds(self, value):
        """Check the bounds of this field."""
        if ((value == None) or
            (value < 0) or
            (value > (2 ** self.width) - 1)):
            raise FieldBoundsError, "Value must be between 0 and %d" % (2 ** self.width - 1)
        
class FieldAlignmentError(Exception):
    """When a programmer tries to decode a field that is not
    on a byte boundary this exception is raised."""
    
    def __init__(self, message):
        """set the FieldAlignmentError message"""
        ## the message that will be output when this error is raised
        self.message = message

class StringField(object):
    """A string field is a name, a width in bits, and possibly a
default value.  The data is to be interpreted as a string, but does
not encode the length into the packet.  Length encoded values are
handled by the LengthValueField."""
    
    def __init__(self, name = "", width = 1, default = None):
        """initialtize a StringField"""
        ## the name of the StringField
        self.name = name
        ## the width, in bits, of the StringField
        self.width = width
        ## the default value, if any, of the StringField
        self.default = default
        
    def __repr__(self):
        """return a human readable form of a StringFeild object"""
        return "<pcs.StringField  name %s, %d bits, type %s, default %s>" % \
               (self.name, self.width, self.type, self.default) # 

    def decode(self, bytes, curr, byteBR):
        """Decode the field and return the value as well as the new
        current position in the bytes array."""
        # byteBR == 8 is the neutral state
        if (byteBR != None and byteBR != 8):
            raise FieldAlignmentError, "Strings must start on a byte boundary"
        packarg = "%ds" % (self.width / 8)
        end = curr + self.width / 8
        value = struct.unpack(packarg, bytes[curr:end])[0]
        curr += self.width / 8
        return [value, curr, byteBR]

    def encode(self, bytearray, value, byte, byteBR):
        """Encode a string field, make sure the bytes are aligned."""
        if (byteBR != None and byteBR != 8):
            raise FieldAlignmentError, "Strings must start on a byte boundary"
        packarg = "%ds" % (self.width / 8)
        bytearray.append(struct.pack(packarg, value))
        return [byte, byteBR]

    def reset(self):
        """Return a resonable value to use in resetting a field of this type."""
        return ""

    def bounds(self, value):
        """Check the bounds of this field."""
        if (value == None) or (len (value) > (self.width / 8)):
            raise FieldBoundsError, "Value must be between 0 and %d bytes long" % (self.width / 8)

class LengthValueField(Field):
    """A length value field handles parts of packets where a length
    and value are encoded toghther, usually used to shove strings into
    packets.
    """

    def __init__(self, name = "", width = 8, default = None):
        self.name = name
        self.width = width
        self.default = default

    def __repr__(self):
        return "<pcs.LengthValueField value name %s, length name %s," \
               "width %d>" % (self.name, self.length_name, self.width)

    def decode(self, bytes, curr, byteBR):
        # Grab the length from the packet
        if (byteBR != None and byteBR != 8):
            raise FieldAlignmentError, "LengthValue Fields must start on a byte boundary"
        if self.width == 8:
            packarg = "B"
        elif self.width == 16:
            packarg = "H"
        elif self.width == 32:
            packarg = "I"
        width = self.width / 8
        length = struct.unpack(packarg, bytes[curr:curr+width])[0]
        curr += width
        # Now grab the data of that length
        packarg ="%ds" % length
        value = struct.unpack(packarg, bytes[curr:curr+length])[0]
        curr += length
        return [value, curr, byteBR]
        
    def encode(self, bytearray, value, byte, byteBR):
        """Encode a LengthValue field.
           Make sure to check the byte alignment."""
        if (byteBR != None and byteBR != 8):
            raise FieldAlignmentError, "LengthValue Fields must start on a byte boundary"
        # Put the length into the packet first.
        if self.width == 8:
            packarg = "B"
        elif self.width == 16:
            packarg = "H"
        elif self.width == 32:
            packarg = "I"
        length = len(value)
        # Now put the data into the packet after the length
        bytearray.append(struct.pack(packarg, length))
        packarg = "%ds" % length
        bytearray.append(struct.pack(packarg, value))
        return [byte, byteBR]

    def reset(self):
        """Return a resonable value to use in resetting a field of this type."""
        return ""

    def bounds(self, value):
        """Check the bounds of this field."""
        if ((value == None) or
            (len (value) > (((2 ** self.width) - 1) / 8))):
            raise FieldBoundsError, "Value must be between 0 and %d bytes long" % (((2 ** self.width) - 1) / 8)

class Layout(list):
    """The layout is a special attribute of a Packet which implements
    the layout of the packet on the wire.  It is actually a list of
    Fields and is implemented as a descriptor.  A layout can only be
    set or get, but never deleted."""

    def __get__(self, obj, typ=None): 
        """return the Layout"""
        ## the layout is the ordering of the fields in the packet
        return self.layout

    # Update the layout itself.  Right now this does not handle
    # removing fields or anything else but must do so in future.
    # XXX Add code to check the type of the value, it must be a
    # list of Field objects

    def __set__(self, obj, value): 
        """set the layout

        obj - the object we are about to set
        value - the value we are setting the field to
        """
        self.layout = value
        for field in self.layout:
            # This is a special case, we don't want to recurse back
            # through the encapsulating class's __setattr__ routine.
            # We want to set this directly in the class's dictionary
            if field.default == None:
                obj.__dict__[field.name] = field.reset()
            else:
                obj.__dict__[field.name] = field.default

class FieldError(Exception):
    """When a programmer tries to set a field that is not in the
    layout this exception is raised."""

    def __init__(self, message):
        """set the error message when this error is raised"""
        ## the error message passed when this error is raised
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
        """return the bytes of the packet"""
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
            [value, curr, byteBR]  = field.decode(bytes, curr, byteBR)
            object.__setattr__(self, field.name, value)

    bytes = property(getbytes, decode)

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
            [byte, byteBR] = field.encode(bytearray, value, byte, byteBR)

        self._bytes = ''.join(bytearray) # Install the new value

    def __init__(self, layout = None, bytes = None):
        """initialize a Packet object

        layout - the layout of the packet, a list of Field objects
        bytes - if the packet is being set up now the bytes to set in it
        """
        self._fieldnames = {}
        # The layout of the Packet, a list of Field objects.
        self.layout = layout
        self._needencode = True
        if bytes != None:
            self.decode(bytes)

    def __add__(self, layout = None):
        """add two packets together

        This is really an append operation, of one packet after another.
        """
        for field in layout:
            self.layout.append(field)
            self._needencode = True

    def __setattr__(self, name, value):
        """Setting the layout is a special case because of the
        ramifications this has on the packet.  Only fields represented
        in the layout may be set, no other attributes may be added"""

        # Handle special fields first.
        if name == '_fieldnames':
            object.__setattr__(self, name, value)
            return

        if name != "layout":
            for field in self.layout:
                if field.name == name:
                    field.bounds(value)

        object.__setattr__(self, name, value)

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

    def println(self):
        """Print the packet in line format."""
        return self.__repr__()

    def __str__(self):
        """Pretty print, with returns, the fields of the packet."""
        retval = ""
        if hasattr(self, 'description'):
            retval += "%s\n" % self.description
        for field in self.layout:
            retval += "%s %s\n" % (field.name, self.__dict__[field.name])
        return retval

    def __len__(self):
        """Return the count of the number of bytes in the packet."""
        return len(self.bytes)

    def chain(self):
        """Return the packet and its next packets as a chain."""
        packet_list = []
        done = False
        packet = self
        while not done:
            packet_list.append(packet)
            if (packet.data != None):
                packet = packet.data
            else:
                done = True
        return Chain(packet_list)
        
    def toXML(self):
        """Transform the Packet into XML."""
        pass

    def fromXML(self):
        """Create a Packet from XML."""
        pass

    def toHTML(self):
        """Transform a Packet to HTML."""
        pass

    def fromHTML(self):
        """Create a Packet from HTML."""
        pass

class Chain(list):
    """A chain is simply a list of packets.  Chains are used to
    aggregate related sub packets into one chunk for transmission."""

    def __init__(self, packets = None):
        """initialize a Chain object

        packets - an optionl array of packets to add to the new Chain
        """
        list.__init__(self)
        self.packets = packets
        self.encode()

    def __eq__(self, other):
        """test two Chain objects for equality

        Two chains are equal iff they have the same packets and their
        packets have the same data in them."""
        if len(self.packets) != len(other.packets):
            return False
        for i in range(len(self.packets)):
            if self.packets[i] != other.packets[i]:
                return False
        return True
            
    def __ne__(self, other):
        """test two Chain objects for inequality"""
        return not self.__eq__(other)
            
    def __str__(self):
        """return a pretty printed Chain"""
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
        """Encode all the packets in a chain into a set of bytes for the Chain"""
        self.bytes = ""
        for packet in self.packets:
            self.bytes += packet.bytes
    
    def decode(self, bytes):
        """Decode all the bytes of all the packets in a Chain into the underlying packets"""
        for packet in self.packets:
            packet.decode(packet.bytes)

    def calc_checksum(self):
        """Calculate a checksum for the whole chain based on RFC 792

        In this calculation any packet that specifically calls out a
        checksum field will have that field zeroed first before the
        checksum is calculated.
        """
        total = 0
        bytes = ""
        for packet in self.packets:
            if (hasattr(packet, 'checksum')):
                packet.checksum = 0
            bytes = bytes + packet.bytes
        if len(bytes) % 2 == 1:
            bytes += "\0"
        for i in range(len(bytes)/2):
            total += (struct.unpack("!H", bytes[2*i:2*i+2])[0])
        total = (total >> 16) + (total & 0xffff)
        total += total >> 16
        return ~total


class ConnNotImpError(Exception):
    """Calling a method that is not implemented raises this exception.

    The base class, and some of the derived classes do not implement
    every moethod that could be.  This exception is meant to catch and
    report thos instances.
    """

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

    def __init__(self):
        raise ConnNotImpError, "Cannot use base class"

    def accept(self):
        raise ConnNotImpError, "Cannot use base class"

    def bind(self):
        raise ConnNotImpError, "Cannot use base class"

    def connect(self):
        raise ConnNotImpError, "Cannot use base class"

    def listen(self):
        raise ConnNotImpError, "Cannot use base class"

    def read(self):
        raise ConnNotImpError, "Cannot use base class"

    def write(self):
        raise ConnNotImpError, "Cannot use base class"

    def send(self):
        raise ConnNotImpError, "Cannot use base class"

    def sendto(self):
        raise ConnNotImpError, "Cannot use base class"

    def recv(self):
        raise ConnNotImpError, "Cannot use base class"

    def recvfrom(self):
        raise ConnNotImpError, "Cannot use base class"

    def close(self):
        raise ConnNotImpError, "Cannot use base class"

class UnpackError(Exception):
    """Error raised when we fail to unpack a packet."""
    def __init__(self, message):
        self.message = message

class PcapConnector(Connector):
    """A connector for protocol capture and injection using the pcap library

    The Pcap connector looks like all the rest of the connectors for
    PCS with the differnece that it provides direct network access and
    bypasses all the protocol stacks on a system.  The usual
    precautions about routing, framing and the like apply so do not
    use this connector if you're not prepared to do all the protocol
    work on your own.
    """

    def __init__(self, name = None):
        """initialize a PcapConnector object

        name - the name of a file or network interface to open
        """
        try:
            self.file = pcap.pcap(name)
        except:
            raise

        # Grab the underlying pcap objects members for convenienc
        self.dloff = self.file.dloff
        self.setfilter = self.file.setfilter
        self.dlink = self.file.datalink()
        
    def read(self):
        """read a packet from a pcap file or interface

        returns the packet as a bytearray
        """
        return self.file.next()[1]

    def recv(self):
        """recv a packet from a pcap file or interface"""
        return self.file.next()[1]
    
    def recvfrom(self):
        """recvfrom a packet from a pcap file or interface"""
        return self.file.next()[1]

    def readpkt(self):
        """read a packet from a pcap file or interfaces returning an
        appropriate packet object

        This is the most usefule method for use by naive applications
        that do not wish to interrogate the underlying packet data."""
        packet = self.file.next()[1]
        return self.unpack(packet, self.dlink, self.dloff)

    def write(self, packet, bytes):
        """Write a packet to a pcap file or network interface.

        bytes - the bytes of the packet, and not the packet object
"""
        return self.file.inject(packet, bytes)

    def send(self, packet, bytes):
        """Write a packet to a pcap file or network interface.

        bytes - the bytes of the packet, and not the packet object"""
        return self.file.inject(packet, bytes)

    def sendto(self, packet, bytes):
        """Write a packet to a pcap file or network interface.

        bytes - the bytes of the packet, and not the packet object"""
        return self.file.inject(packet, bytes)

    def unpack(self, packet, dlink, dloff):
        """turn a packet into a set of bytes appropriate to transmit

        packet - a Packet object
        dlink - a data link layer as defined in the pcap module
        dloff - a datalink offset as defined in the pcap module
        """
        import packets.ethernet
        import packets.localhost

        if dlink == pcap.DLT_EN10MB:
            return packets.ethernet.ethernet(packet)
        elif dlink == pcap.DLT_NULL:
            return packets.localhost.localhost(packet)
        else:
            raise UnpackError, "Could not interpret packet"
                
    def close(self):
        """Close the pcap file or interface."""
        self.file.close()

class PcapDumpConnector(Connector):
    """A connector for dumping packets to a file for later re-use.

    The PcapDump connector allows the programmer to write libpcap
    compatible files full of packets.  Unlike the PcapConnector it
    does not alloww the programmer to read from a dump file, for that
    the PcapConnector class should be used.
    """

    def __init__(self, dumpfile = None, dumptype = None):
        """initialize a pcap dump connector"""
        from pcap import pcap
        try:
            self.file = pcap(dumpfile = dumpfile, dumptype=dumptype)
        except:
            raise

        # Grab the underlying pcap objects members for convenience
        self.dloff = self.file.dloff
        self.setfilter = self.file.setfilter
        
    def write(self, packet):
        """write a packet to the dumpfile"""
        if type(packet) is buffer:
            packarg = "%ds" % len(packet)
            packet = struct.unpack(packarg, packet)[0]
        return self.file.dump(packet)

    def send(self, packet):
        """send a packet to the dumpfile

        calls the write() method"""
        return self.file.dump(packet)

    def sendto(self, packet, header):
        """sendto a packet to the dumpfile

        calls the write() method"""
        return self.file.dump(packet)

    def close(self):
        """close the dumpfile"""
        self.file.dump_close()

class IP4Connector(Connector):
    """Base class for all IPv4 connectors.

    This class implements all the necessary functions for a plain IPv4
    based connector.  In particular the data access methods, such as
    read, write, etc. likely do not need to be overridden by the sub classes.
    """

    def __init__(self, name = None):
        """initialize an IP4Connector"""
        try:
            self.file = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
        except:
            raise

    def connect(self, address):
        """connect to a foreign IPv4 address"""
        return self.file.connect(address)

    def read(self, len):
        """read data from an IPv4 socket"""
        return self.file.recv(len)

    def recv(self, len, flags = 0):
        """recv data from an IPv4 socket"""
        return self.file.recv(len, flags)
    
    def recvfrom(self, len, flags = 0):
        """recvfrom data from an IPv4 socket"""
        return self.file.recvfrom(len, flags)

    def write(self, packet, flags = 0):
        """write data to an IPv4 socket"""
        return self.file.sendall(packet, flags)

    def send(self, packet, flags = 0):
        """send data to an IPv4 socket"""
        return self.file.send(packet, flags)

    def sendto(self, packet, addr, flags = 0):
        """sendto data to an IPv4 socket"""
        return self.file.sendto(packet, flags, addr)

    def close(self):
        """close an IPv4 Connector"""
        self.file.close()
    
class UDP4Connector(IP4Connector):
    """A connector for IPv4 UDP sockets
    """

    def __init__(self, address = None, port = None):
        """initialize a UDPv4 connector

        address - an optional address to connect to
        port - an optional port to connect to
        """
        try:
            self.file = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        except:
            raise

        if (address != None and port != None):
            try:
                self.file.connect([address, port])
            except:
                raise

class TCP4Connector(IP4Connector):
    """A connector for IPv4 TCP sockets

    The TCP4Connector implements a IPv4 TCP connection
    """

    def __init__(self, addr = None, port = None ):
        """initialize a TCP4Connector class for TCP over IPv4"""
        try:
            self.file = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        except:
            raise

        if (addr != None and port != None):
            try:
                self.file.connect((addr, port))
            except:
                raise

class SCTP4Connector(IP4Connector):
    """A connector for IPv4 SCTP sockets

    The TCP4Connector implements a IPv4 SCTP connection
    """

    def __init__(self, addr = None, port = None ):
        """initialize a SCTP4Connector class for TCP over IPv4"""
        try:
            self.file = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)
        except:
            raise

        if (addr != None and port != None):
            try:
                self.file.connect((addr, port))
            except:
                raise

class IP6Connector(Connector):
    """Base class for all IPv6 connectors.

    This class implements all the necessary functions for a plain IPv6
    based connector.  In particular the data access methods, such as
    read, write, etc. likely do not need to be overridden by the sub classes.
    """

    def __init__(self, name = None):
        """initialize an IPPConnector class for raw IPv6 access"""
        try:
            self.file = socket(AF_INET6, SOCK_RAW, IPPROTO_IP)
        except:
            raise

    def read(self, len):
        """read from an IPv6 connection"""
        return self.file.recv(len)

    def recv(self, len, flags = 0):
        """recv from an IPv6 connection"""
        return self.file.recv(len, flags)
    
    def recvfrom(self, len, flags = 0):
        """readfrom on an IPv6 connection"""
        return self.file.recvfrom(len, flags)

    def write(self, packet, flags = 0):
        """write to an IPv6 connection"""
        return self.file.sendall(packet, flags)

    def send(self, packet, flags = 0):
        """send to an IPv6 connection"""
        return self.file.send(packet, flags)

    def sendto(self, packet, addr, flags = 0):
        """sendto to an IPv6 connection"""
        return self.file.sendto(packet, flags, addr)

    def mcast(self, iface):
        """set IP6 connector into multicast mode"""
        import dl
        _libc = dl.open('libc.so')
        ifn = _libc.call('if_nametoindex', iface)
        self.sock.setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 1)
        self.sock.setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 5)
        self.sock.setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_IF, ifn)


class UDP6Connector(IP6Connector):
    """A connector for IPv6 UDP sockets """

    def __init__(self, name = None):
        """initialize a UDPv6 connector"""
        try:
            self.file = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        except:
            raise

        if (address != None and port != None):
            try:
                self.file.connect([address, port])
            except:
                raise

class TCP6Connector(IP6Connector):
    """A connector for IPv4 TCP sockets

    The TCP4Connector implements a IPv4 TCP connection
    """

    def __init__(self, name = None):
        """initialize a TCPv6 connector"""
        try:
            self.file = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)
        except:
            raise

        if (address != None and port != None):
            try:
                self.file.connect([address, port])
            except:
                raise

class SCTP6Connector(IP6Connector):
    """A connector for IPv6 SCTP sockets

    The SCTP  implements a IPv4 TCP connection
    """

    def __init__(self, name = None):
        """initialize a SCTP6Connector"""
        try:
            self.file = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP)
        except:
            raise

        if (address != None and port != None):
            try:
                self.file.connect([address, port])
            except:
                raise

###
### Convenience functions and adjuncts to certain probelmatic bits of Python
### network code.
###

def inet_atol(string):
    """convert an ascii IPv4 address into a Long"""
    from socket import inet_aton
    value = 0
    addr = inet_aton(string)
    for i in range(4):
        value += ord(addr[i]) << (3 - i) * 8
    return value

