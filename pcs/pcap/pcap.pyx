#
# pcap.pyx
#
# $Id: pcap.pyx,v 1.20 2005/10/16 23:00:11 dugsong Exp $

"""packet capture library

This module provides a high level interface to packet capture systems.
All packets on the network, even those destined for other hosts, are
accessible through this mechanism.
"""

__author__ = 'Dug Song <dugsong@monkey.org>'
__maintainer__ = 'George Neville-Neil <gnn@neville-neil.com>'
__copyright__ = 'Copyright (c) 2004 Dug Song'
__license__ = 'BSD license'
__url__ = 'http://pcs.sf.net'
__version__ = '1.1'
__revison__ = '2'

import sys
import calendar
import time

cdef extern from "Python.h":
    object PyBuffer_FromMemory(char *s, int len)
    int    PyGILState_Ensure()
    void   PyGILState_Release(int gil)
    void   Py_BEGIN_ALLOW_THREADS()
    void   Py_END_ALLOW_THREADS()

cimport bpf
import bpf

from bpf cimport bpf_insn
from bpf cimport bpf_program
from bpf cimport bpf_timeval

cdef extern from "pcap.h":
    struct pcap_stat:
        unsigned int ps_recv
        unsigned int ps_drop
        unsigned int ps_ifdrop
    struct pcap_pkthdr:
        bpf_timeval ts
        unsigned int caplen
        unsigned int len
    ctypedef struct pcap_t:
        int __xxx
    ctypedef struct pcap_dumper_t:
        int __xxx
    ctypedef enum pcap_direction_t:
        __xxx

ctypedef void (*pcap_handler)(void *arg, pcap_pkthdr *hdr, char *pkt)

cdef extern from "pcap.h":
    pcap_t *pcap_open_live(char *device, int snaplen, int promisc,
                           int to_ms, char *errbuf)
    pcap_t *pcap_open_dead(int linktype, int snaplen)
    pcap_t *pcap_open_offline(char *fname, char *errbuf)
    pcap_dumper_t *pcap_dump_open(pcap_t *p, char *fname)
    void pcap_dump_close(pcap_dumper_t *p)
    int     pcap_compile(pcap_t *p, bpf_program *fp, char *str, int optimize,
                         unsigned int netmask)
    int     pcap_setfilter(pcap_t *p, bpf_program *fp)
    void    pcap_freecode(bpf_program *fp)
    int     pcap_setdirection(pcap_t *p, pcap_direction_t d)
    int     pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback,
                          unsigned char *arg)
    unsigned char *pcap_next(pcap_t *p, pcap_pkthdr *hdr)
    int     pcap_datalink(pcap_t *p)
    int     pcap_snapshot(pcap_t *p)
    int     pcap_stats(pcap_t *p, pcap_stat *ps)
    char   *pcap_geterr(pcap_t *p)
    void    pcap_close(pcap_t *p)
    int     pcap_inject(pcap_t *p, char *buf, int size)
    void    pcap_dump(pcap_dumper_t *p, pcap_pkthdr *h, char *sp)
    int     pcap_get_selectable_fd(pcap_t *)
    int     pcap_setnonblock(pcap_t *p, int nonblock, char *errbuf)
    int     pcap_getnonblock(pcap_t *p, char *errbuf)
    char   *pcap_lookupdev(char *errbuf)
    int     pcap_compile_nopcap(int snaplen, int dlt, bpf_program *fp,
                                char *str, int optimize, unsigned int netmask)

cdef extern from "pcap_ex.h":
    int     pcap_ex_immediate(pcap_t *p)
    char   *pcap_ex_name(char *name)
    void    pcap_ex_setup(pcap_t *p)
    int     pcap_ex_next(pcap_t *p, pcap_pkthdr **hdr, char **pkt)
    char   *pcap_ex_lookupdev(char *errbuf)

# XXX Lacks size_t; known Pyrex limitation
cdef extern from *:
    void  free(void *ptr)
    char *strdup(char *src)
    int   printf(char *, ...)

cdef struct pcap_handler_ctx:
    void *callback
    void *args
    int   got_exc

cdef void __pcap_handler(void *arg, pcap_pkthdr *hdr, char *pkt):
    cdef pcap_handler_ctx *ctx
    cdef int gil
    ctx = <pcap_handler_ctx *>arg
    gil = PyGILState_Ensure()
    try:
        (<object>ctx.callback)(hdr.ts.tv_sec + (hdr.ts.tv_usec/1000000.0),
                               PyBuffer_FromMemory(pkt, hdr.caplen),
                               *(<object>ctx.args))
    except:
        ctx.got_exc = 1
    PyGILState_Release(gil)

PCAP_D_INOUT = 0
PCAP_D_IN = 1
PCAP_D_OUT = 2

DLT_NULL =	0
DLT_EN10MB =	1
DLT_EN3MB =	2
DLT_AX25 =	3
DLT_PRONET =	4
DLT_CHAOS =	5
DLT_IEEE802 =	6
DLT_ARCNET =	7
DLT_SLIP =	8
DLT_PPP =	9
DLT_FDDI =	10
# XXX - Linux
DLT_LINUX_SLL =	113
# XXX - OpenBSD
DLT_PFLOG =	117
DLT_PFSYNC =	18
if sys.platform.find('openbsd') != -1:
    DLT_LOOP =		12
    DLT_RAW =		14
else:
    DLT_LOOP =		108
    DLT_RAW =		12

dltoff = { DLT_NULL:4, DLT_EN10MB:14, DLT_IEEE802:22, DLT_ARCNET:6,
          DLT_SLIP:16, DLT_PPP:4, DLT_FDDI:21, DLT_PFLOG:48, DLT_PFSYNC:4,
          DLT_LOOP:4, DLT_RAW:0, DLT_LINUX_SLL:16 }

def compile(char *str, int snaplen=65536, int dlt=DLT_RAW, int optimize=1,
            long netmask=0):
    """Compile a pcap filter expression to a BPF program.
       This is not a class method, because we want to do the same
       from within the pcap class."""
    cdef bpf_program prog
    cdef int rc
    prog.bf_len = 0
    prog.bf_insns = NULL
    rc = pcap_compile_nopcap(snaplen, dlt, &prog, str, optimize, netmask)
    if rc == -1:
        raise OSError
    # Python-ize the bpf_program. Note that this simply wraps the buffer
    # which pcap just allocated in the C library heap.
    pb = bpf.progbuf(<object> &prog, None)
    program = pb.__program__()
    return program

cdef class pcap:
    """pcap(name=None, snaplen=65535, promisc=True, immediate=False) -> packet capture object
    
    Open a handle to a packet capture descriptor.
    
    Keyword arguments:
    name      -- name of a network interface or dumpfile to open,
                 or None to open the first available up interface
    snaplen   -- maximum number of bytes to capture for each packet
    promisc   -- boolean to specify promiscuous mode sniffing
    immediate -- disable buffering, if possible
    dumpfile  -- name of a dumpfile to open, if necessary
    dumptype  -- only open a dumpfile and specify its type
    """
    cdef pcap_t *__pcap
    cdef char *__name
    cdef char *__filter
    cdef char __ebuf[256]
    cdef int __dloff
    cdef pcap_dumper_t *__dumper

    def __init__(self, name=None, snaplen=65535, promisc=True,
                 timeout_ms=500, immediate=False,
                 dumpfile="", dumptype=None):
        global dltoff
        cdef char *p

        if dumptype != None:
            try:
                self.__pcap = pcap_open_dead(dumptype, snaplen)
            except:
                raise OSError, "Internal error pcap_open_dead."
            p = dumpfile
        else:
            if not name:
                p = pcap_ex_lookupdev(self.__ebuf)
                if p == NULL:
                    raise OSError, self.__ebuf
            else:
                p = name
                    
            self.__pcap = pcap_open_offline(p, self.__ebuf)
                    
            if not self.__pcap:
                self.__pcap = pcap_open_live(pcap_ex_name(p), snaplen,
                                             promisc, timeout_ms,
                                             self.__ebuf)

        if not self.__pcap:
            raise OSError, self.__ebuf
                        
        if dumpfile != "":
            self.__dumper = pcap_dump_open(self.__pcap, dumpfile)
            if not self.__dumper:
                raise OSError, pcap_geterr(self.__pcap)
            
        self.__name = strdup(p)
        self.__filter = strdup("")
        try:
            dlt = pcap_datalink(self.__pcap)
            self.__dloff = dltoff[dlt]
        except KeyError: pass
        if immediate and pcap_ex_immediate(self.__pcap) < 0:
            raise OSError, "couldn't set BPF immediate mode"
            
    property name:
        """Network interface or dumpfile name."""
        def __get__(self):
            return self.__name

    property snaplen:
        """Maximum number of bytes to capture for each packet."""
        def __get__(self):
            return pcap_snapshot(self.__pcap)
        
    property dloff:
        """Datalink offset (length of layer-2 frame header)."""
        def __get__(self):
            return self.__dloff

    property filter:
        """Current packet capture filter."""
        def __get__(self):
            return self.__filter
    
    property fd:
        """File descriptor (or Win32 HANDLE) for capture handle."""
        def __get__(self):
            return pcap_get_selectable_fd(self.__pcap)
        
    def fileno(self):
        """Return file descriptor (or Win32 HANDLE) for capture handle."""
        return pcap_get_selectable_fd(self.__pcap)
    
    def setfilter(self, value, optimize=1):
        """Set packet capture filter using a filter expression."""
        cdef bpf_program fcode
        free(self.__filter)
        self.__filter = strdup(value)
        if pcap_compile(self.__pcap, &fcode, self.__filter, optimize, 0) < 0:
            raise OSError, pcap_geterr(self.__pcap)
        #printf("%p: %d %p\n", <void *>&fcode, fcode.bf_len, <void  *>fcode.bf_insns)
        if pcap_setfilter(self.__pcap, &fcode) < 0:
            raise OSError, pcap_geterr(self.__pcap)
        pcap_freecode(&fcode)

    def setbpfprogram(self, object bpfprogram):
        """Set packet capture filter using a pre-compiled BPF program."""
        cdef object pbp
        cdef bpf_program *bp
        #cdef int i
        if not isinstance(bpfprogram, bpf.program):
            raise ValueError, ""
        # cast to temporary required.
        pbp = bpf.program.__progbuf__(bpfprogram)
        #printf("%p\n", <void *>pbp)
        bp = bpf.progbuf.__bpf_program__(pbp)
        #printf("%p: %d %p\n", <void *>bp, bp[0].bf_len, <void  *>bp[0].bf_insns)
        #for 0 <= i < bp[0].bf_len:
        #    printf("%d %x\n", i, bp[0].bf_insns[i].code)
        if pcap_setfilter(self.__pcap, bp) < 0:
            raise OSError, pcap_geterr(self.__pcap)

    def compile(self, value, optimize=True, netmask=0):
        """Compile a filter expression to a BPF program for this pcap.
           Return the filter as a bpf program."""
        cdef bpf_program fcode
        if pcap_compile(self.__pcap, &fcode, value, optimize, netmask) < 0:
            raise OSError, pcap_geterr(self.__pcap)
        pb = bpf.progbuf(<object>&fcode, None)
        program = pb.__program__()
        return program

    def setdirection(self, value):
        """Set BPF capture direction."""
        if pcap_setdirection(self.__pcap, value) < 0:
            raise OSError, pcap_geterr(self.__pcap)

    def setnonblock(self, nonblock=True):
        """Set non-blocking capture mode."""
        pcap_setnonblock(self.__pcap, nonblock, self.__ebuf)
    
    def getnonblock(self):
        """Return non-blocking capture mode as boolean."""
        ret = pcap_getnonblock(self.__pcap, self.__ebuf)
        if ret < 0:
            raise OSError, self.__ebuf
        elif ret:
            return True
        return False
    
    def datalink(self):
        """Return datalink type (DLT_* values)."""
        return pcap_datalink(self.__pcap)
    
    def next(self):
        """Return the next (timestamp, packet) tuple, or None on error."""
        cdef pcap_pkthdr hdr
        cdef char *pkt
        pkt = <char *>pcap_next(self.__pcap, &hdr)
        if not pkt:
            return None
        return (hdr.ts.tv_sec + (hdr.ts.tv_usec / 1000000.0),
                PyBuffer_FromMemory(pkt, hdr.caplen))

    def __add_pkts(self, ts, pkt, pkts):
        pkts.append((ts, pkt))
    
    def readpkts(self):
        """Return a list of (timestamp, packet) tuples received in one buffer."""
        pkts = []
        self.dispatch(-1, self.__add_pkts, pkts)
        return pkts
    
    def dispatch(self, cnt, callback, *args):
        """Collect and process packets with a user callback,
        return the number of packets processed, or 0 for a savefile.
        
        Arguments:
        
        cnt      -- number of packets to process;
                    or 0 to process all packets until an error occurs,
                    EOF is reached, or the read times out;
                    or -1 to process all packets received in one buffer
        callback -- function with (timestamp, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
        """
        cdef pcap_handler_ctx ctx
        cdef int n

        ctx.callback = <void *>callback
        ctx.args = <void *>args
        ctx.got_exc = 0
        n = pcap_dispatch(self.__pcap, cnt, __pcap_handler,
                          <unsigned char *>&ctx)
        if ctx.got_exc:
            exc = sys.exc_info()
            raise exc[0], exc[1], exc[2]
        return n

    def loop(self, callback, *args):
        """Loop forever, processing packets with a user callback.
        The loop can be exited with an exception, including KeyboardInterrupt.
        
        Arguments:

        callback -- function with (timestamp, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
        """
        cdef pcap_pkthdr *hdr
        cdef char *pkt
        cdef int n
        pcap_ex_setup(self.__pcap)
        while 1:
            Py_BEGIN_ALLOW_THREADS
            n = pcap_ex_next(self.__pcap, &hdr, &pkt)
            Py_END_ALLOW_THREADS
            if n == 1:
                callback(hdr.ts.tv_sec + (hdr.ts.tv_usec / 1000000.0),
                         PyBuffer_FromMemory(pkt, hdr.caplen), *args)
            elif n == -1:
                raise KeyboardInterrupt
            elif n == -2:
                break
    
    def inject(self, packet, len):
        """Inject a packet onto an interface.
        May or may not work depending on platform.

        Arguments:

        packet -- a pointer to the packet in memory
        """
        cdef int n
        n = pcap_inject(self.__pcap, packet, len)
        if (n < 0):
            raise OSError, pcap_geterr(self.__pcap)

        return n
    
    def dump(self, packet, header=None):
        """Dump a packet to a previously opened save file.

        Arguments:

        packet -- the packet
        header -- a pcap header provided by the caller
        A user supplied header MUST contain the following fields
            header.sec: The timestamp in seconds from the Unix epoch
            header.usec: The timestamp in micro seconds
            header.caplen: Length of packet present
            header.len: Total length of packet
        """
        cdef pcap_pkthdr hdr
        if header != None:
            hdr.ts.tv_sec = header.sec
            hdr.ts.tv_usec = header.usec
            hdr.caplen = header.caplen
            hdr.len = len(packet)
        else:
            hdr.ts.tv_sec = calendar.timegm(time.gmtime())
            hdr.ts.tv_usec = 0
            hdr.caplen = len(packet)
            hdr.len = len(packet)

        pcap_dump(self.__dumper, &hdr, packet)

    def dump_close(self):
        pcap_dump_close(self.__dumper)

    def close(self):
        if self.__pcap:
            pcap_close(self.__pcap)
            self.__pcap = NULL

    def geterr(self):
        """Return the last error message associated with this handle."""
        return pcap_geterr(self.__pcap)
    
    def stats(self):
        """Return a 3-tuple of the total number of packets received,
        dropped, and dropped by the interface."""
        cdef pcap_stat pstat
        if pcap_stats(self.__pcap, &pstat) < 0:
            raise OSError, pcap_geterr(self.__pcap)
        return (pstat.ps_recv, pstat.ps_drop, pstat.ps_ifdrop)

    def __iter__(self):
        pcap_ex_setup(self.__pcap)
        return self

    def __next__(self):
        cdef pcap_pkthdr *hdr
        cdef char *pkt
        cdef int n
        while 1:
            Py_BEGIN_ALLOW_THREADS
            n = pcap_ex_next(self.__pcap, &hdr, &pkt)
            Py_END_ALLOW_THREADS
            if n == 1:
                return (hdr.ts.tv_sec + (hdr.ts.tv_usec / 1000000.0),
                        PyBuffer_FromMemory(pkt, hdr.caplen))
            elif n == -1:
                raise KeyboardInterrupt
            elif n == -2:
                raise StopIteration
    
    def __dealloc__(self):
        if self.__name:
            free(self.__name)
        if self.__filter:
            free(self.__filter)
        if self.__pcap:
            pcap_close(self.__pcap)

def ex_name(char *foo):
    return pcap_ex_name(foo)

def lookupdev():
    """Return the name of a network device suitable for sniffing."""
    cdef char *p, ebuf[256]
    p = pcap_ex_lookupdev(ebuf)
    if p == NULL:
        raise OSError, ebuf
    return p

