#
# bpf.pyx
#
# $Id$

"""BPF library

This module provides utilities for working with BPF programs.
"""

__author__ = 'Bruce M. Simpson <bms@incunabulum.net>'
__maintainer__ = 'Bruce M. Simpson <bms@incunabulum.net>'
__copyright__ = 'Copyright (c) 2008 Bruce M. Simpson'
__license__ = 'BSD license'
__url__ = 'http://pcs.sf.net'
__version__ = '1.0'
__revison__ = '0'

import sys
import calendar
import time

cdef extern from "pcap.h":
    int     bpf_filter(bpf_insn *insns, char *buf, int len, int caplen)
    int     bpf_validate(bpf_insn *insns, int len)
    char   *bpf_image(bpf_insn *insns, int n)

# XXX Lacks size_t; known Pyrex limitation
cdef extern from *:
    void  free(void *ptr)
    void *malloc(unsigned int len)
    int   printf(char *, ...)

BPF_LD = 0x00
BPF_LDX = 0x01
BPF_ST = 0x02
BPF_STX = 0x03
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_MISC = 0x07

BPF_W = 0x00
BPF_H = 0x08
BPF_B = 0x10

BPF_IMM = 0x00
BPF_ABS = 0x20
BPF_IND = 0x40
BPF_MEM = 0x60
BPF_LEN = 0x80
BPF_MSH = 0xa0

BPF_ADD = 0x00
BPF_SUB = 0x10
BPF_MUL = 0x20
BPF_DIV = 0x30
BPF_OR = 0x40
BPF_AND = 0x50
BPF_LSH = 0x60
BPF_RSH = 0x70
BPF_NEG = 0x80
BPF_JA = 0x00
BPF_JEQ = 0x10
BPF_JGT = 0x20
BPF_JGE = 0x30
BPF_JSET = 0x40

BPF_K = 0x00
BPF_X = 0x08

BPF_A = 0x10

BPF_TAX = 0x00
BPF_TXA = 0x80

cdef class op:
    """Class which wraps a C bpf_insn struct."""
    cdef bpf_insn insn

    property code:
        def __get__(self):
            return self.insn.code
        def __set__(self, unsigned short value):
            self.insn.code = value

    property jt:
        def __get__(self):
            return self.insn.jt
        def __set__(self, unsigned char value):
            self.insn.jt = value

    property jf:
        def __get__(self):
            return self.insn.jf
        def __set__(self, unsigned char value):
            self.insn.jf = value

    property k:
        def __get__(self):
            return self.insn.k
        def __set__(self, unsigned int value):
            self.insn.k = value

    def __init__(self, unsigned short code, unsigned char jt,
                 unsigned char jf, unsigned int k):
        """Construct a BPF instruction."""
        self.insn.code = code
        self.insn.jt = jt
        self.insn.jf = jf
        self.insn.k = k

    def disassemble(self, unsigned int n=0):
        """Return a single string of disassembly for this instruction.
           n is an optional index number."""
        cdef char *p
        p = bpf_image(&self.insn, n)
        return p

    def _copyout(self, ip):
        (<bpf_insn *> ip)[0] = self.insn

# The following class wrappers are purely for the user's convenience.

cdef class ld(op):
    def __init__(self, unsigned int k):
        op.__init__(self, BPF_LD|BPF_IMM, 0, 0, k)

cdef class ldw(op):
    def __init__(self, where=None):
        if isinstance(where, int):
            op.__init__(self, BPF_LD|BPF_W|BPF_ABS, 0, 0, where)
        elif isinstance(where, list) and len(where) == 1 \
             and isinstance(where[0], int):
            op.__init__(self, BPF_LD|BPF_W|BPF_IND, 0, 0, where[0])
        else:
            raise ValueError

cdef class ldh(op):
    def __init__(self, where=None):
        if isinstance(where, int):
            op.__init__(self, BPF_LD|BPF_H|BPF_ABS, 0, 0, where)
        elif isinstance(where, list) and len(where) == 1 \
             and isinstance(where[0], int):
            op.__init__(self, BPF_LD|BPF_H|BPF_IND, 0, 0, where[0])
        else:
            raise ValueError

cdef class ldb(op):
    def __init__(self, where=None):
        if isinstance(where, int):
            op.__init__(self, BPF_LD|BPF_B|BPF_ABS, 0, 0, where)
        elif isinstance(where, list) and len(where) == 1 \
             and isinstance(where[0], int):
            op.__init__(self, BPF_LD|BPF_B|BPF_IND, 0, 0, where[0])
        else:
            raise ValueError

cdef class ldlen(op):
    def __init__(self):
        op.__init__(self, BPF_LD|BPF_W|BPF_LEN, 0, 0, 0)

cdef class ldx(op):
    def __init__(self, where=None):
        if isinstance(where, int):
            op.__init__(self, BPF_LDX|BPF_IMM, 0, 0, where)
        elif isinstance(where, list) and len(where) == 1 \
             and isinstance(where[0], int):
            # Lame trick to use python list syntax for indirects.
            op.__init__(self, BPF_LDX|BPF_MEM, 0, 0, where[0])
        else:
            raise ValueError

cdef class ldxlen(op):
    def __init__(self):
        op.__init__(self, BPF_LDX|BPF_W|BPF_LEN, 0, 0, 0)

cdef class ldxmsh(op):
    def __init__(self, unsigned int k):
        op.__init__(self, BPF_LDX|BPF_MSH|BPF_B, 0, 0, k)

cdef class st(op):
    def __init__(self, unsigned int k):
        op.__init__(self, BPF_ST, 0, 0, k)

cdef class stx(op):
    def __init__(self, unsigned int k):
        op.__init__(self, BPF_STX, 0, 0, k)

cdef class ret(op):
    def __init__(self, k=None):
        if k is None:
            op.__init__(self, BPF_RET|BPF_A, 0, 0, 0)
        elif isinstance(k, int):
            op.__init__(self, BPF_RET|BPF_K, 0, 0, k)
        else:
            raise ValueError

cdef class add(op):
    def __init__(self, k=None):
        if k is None:
            op.__init__(self, BPF_ALU|BPF_ADD|BPF_X, 0, 0, 0)
        elif isinstance(k, int):
            op.__init__(self, BPF_ALU|BPF_ADD|BPF_K, 0, 0, k)
        else:
            raise ValueError

cdef class sub(op):
    def __init__(self, k=None):
        if k is None:
            op.__init__(self, BPF_ALU|BPF_SUB|BPF_X, 0, 0, 0)
        elif isinstance(k, int):
            op.__init__(self, BPF_ALU|BPF_SUB|BPF_K, 0, 0, k)
        else:
            raise ValueError

cdef class mul(op):
    def __init__(self, k=None):
        if k is None:
            op.__init__(self, BPF_ALU|BPF_MUL|BPF_X, 0, 0, 0)
        elif isinstance(k, int):
            op.__init__(self, BPF_ALU|BPF_MUL|BPF_K, 0, 0, k)
        else:
            raise ValueError

cdef class div(op):
    def __init__(self, k=None):
        if k is None:
            op.__init__(self, BPF_ALU|BPF_DIV|BPF_X, 0, 0, 0)
        elif isinstance(k, int):
            op.__init__(self, BPF_ALU|BPF_DIV|BPF_K, 0, 0, k)
        else:
            raise ValueError

cdef class or_(op):
    def __init__(self, k=None):
        if k is None:
            op.__init__(self, BPF_ALU|BPF_OR|BPF_X, 0, 0, 0)
        elif isinstance(k, int):
            op.__init__(self, BPF_ALU|BPF_OR|BPF_K, 0, 0, k)
        else:
            raise ValueError

cdef class and_(op):
    def __init__(self, k=None):
        if k is None:
            op.__init__(self, BPF_ALU|BPF_AND|BPF_X, 0, 0, 0)
        elif isinstance(k, int):
            op.__init__(self, BPF_ALU|BPF_AND|BPF_K, 0, 0, k)
        else:
            raise ValueError

cdef class lsh(op):
    def __init__(self, k=None):
        if k is None:
            op.__init__(self, BPF_ALU|BPF_LSH|BPF_X, 0, 0, 0)
        elif isinstance(k, int):
            op.__init__(self, BPF_ALU|BPF_LSH|BPF_K, 0, 0, k)
        else:
            raise ValueError

cdef class rsh(op):
    def __init__(self, k=None):
        if k is None:
            op.__init__(self, BPF_ALU|BPF_RSH|BPF_X, 0, 0, 0)
        elif isinstance(k, int):
            op.__init__(self, BPF_ALU|BPF_RSH|BPF_K, 0, 0, k)
        else:
            raise ValueError

cdef class neg(op):
    def __init__(self):
        op.__init__(self, BPF_ALU|BPF_NEG, 0, 0, 0)

cdef class ja(op):
    def __init__(self, unsigned int k):
        op.__init__(self, BPF_JMP|BPF_JA, 0, 0, k)

cdef class jeq(op):
    def __init__(self, unsigned char jt=0, unsigned char jf=0, k=None):
        if k is None:
            op.__init__(self, BPF_JMP|BPF_JEQ|BPF_X, jt, jf, 0)
        elif isinstance(k, int):
            op.__init__(self, BPF_JMP|BPF_JEQ|BPF_K, jt, jf, k)
        else:
            raise ValueError

cdef class jgt(op):
    def __init__(self, unsigned char jt=0, unsigned char jf=0, k=None):
        if k is None:
            op.__init__(self, BPF_JMP|BPF_JGT|BPF_X, jt, jf, 0)
        elif isinstance(k, int):
            op.__init__(self, BPF_JMP|BPF_JGT|BPF_K, jt, jf, k)
        else:
            raise ValueError

cdef class jge(op):
    def __init__(self, unsigned char jt=0, unsigned char jf=0, k=None):
        if k is None:
            op.__init__(self, BPF_JMP|BPF_JGE|BPF_X, jt, jf, 0)
        elif isinstance(k, int):
            op.__init__(self, BPF_JMP|BPF_JGE|BPF_K, jt, jf, k)
        else:
            raise ValueError

cdef class jset(op):
    def __init__(self, unsigned char jt=0, unsigned char jf=0, k=None):
        if k is None:
            op.__init__(self, BPF_JMP|BPF_JSET|BPF_X, jt, jf, 0)
        elif isinstance(k, int):
            op.__init__(self, BPF_JMP|BPF_JSET|BPF_K, jt, jf, k)
        else:
            raise ValueError

cdef class tax(op):
    def __init__(self):
        op.__init__(self, BPF_MISC|BPF_TAX, 0, 0, 0)

cdef class txa(op):
    def __init__(self):
        op.__init__(self, BPF_MISC|BPF_TXA, 0, 0, 0)

cdef class progbuf:
    """Private class which manages a C bpf_program struct and
       a copy of a list of 'op' as an immutable contiguous buffer.

       NOTE WELL: This class uses the same internal representation
       and allocation semantics as libpcap does, so that the output
       of pcap_compile*() may be passed around."""

    #cdef bpf_program bp
    # TODO: Check that we don't exceed BPF_MAXINSNS normally 512.
    # bpf programs must be 32-bit aligned, assume malloc does this.

    def __init__(self, pbp, list li=None):
        cdef unsigned int i
        cdef unsigned int ninsns
        cdef bpf_insn *bufp
        cdef bpf_insn *ip

        #printf("__init__(%p) called\n", <void *>self)

        # Deal with the pcap case upfront.
        if pbp is not None:
            self.bp = (<bpf_program *> pbp)[0]
            #printf("__init__(%p) returning\n", <void *>self)
            return

        self.bp.bf_len = 0
        self.bp.bf_insns = NULL

        ninsns = len(li)
        if ninsns == 0:
            return
        if not isinstance(li[0], op):
            raise ValueError

        # We have to use malloc to match pcap's semantics.
        #printf("__init__(%p) is calling malloc(%u)\n", <void *>self,
        #       ninsns * sizeof(bpf_insn))
        bufp = <bpf_insn*> malloc(ninsns * sizeof(bpf_insn))
        if bufp == NULL:
            raise MemoryError, 'malloc'

        ip = bufp
        for 0 <= i < ninsns:
            li[i]._copyout(<object> ip)
            ip = ip + 1

        self.bp.bf_len = ninsns
        self.bp.bf_insns = bufp
        #printf("__init__(%p) returning\n", <void *>self)

    def __dealloc__(self):
        #printf("__deallocate__(%p) called\n", <void *>self)
        if self.bp.bf_insns != NULL:
            free(self.bp.bf_insns)

    def __program__(self):
        """Convert a progbuf to a program.
           Add a reference to ourselves so the original behaviour
           is preserved."""
        cdef unsigned int i
        cdef unsigned int n
        cdef bpf_insn *ip
        li = []
        n = self.bp.bf_len
        if n > 0:
            ip = self.bp.bf_insns
            for 0 <= i < n:
                li.append(op(ip[0].code, ip[0].jt, ip[0].jf, ip[0].k))
                ip = ip + 1
        return program(li, self)

    cdef bpf_program *__bpf_program__(self):
        """Return the internal representation."""
        return &self.bp

    def validate(self):
        """Return boolean True if BPF program is valid."""
        return bool(bpf_validate(self.bp.bf_insns, self.bp.bf_len) != 0)

    def filter(self, char *buf, unsigned int buflen):
        """Return boolean match for buf against our filter."""
        return bool(bpf_filter(self.bp.bf_insns, buf, buflen, buflen) != 0)

# program acts as a proxy for progbuf.
cdef class program:
    """program() -> BPF program object"""

    #cdef list insns

    property instructions:
        """List of instructions."""
        def __get__(self):
            return self.insns
        def __set__(self, list value):
            self.insns = value

    def __init__(self, list instructions=None, object progbuf=None):
        """Construct a BPF program object."""
        self.progbuf = progbuf
        if instructions is not None:
            self.insns = instructions
        else:
            self.insns = []

    cdef __progbuf__(self):
        """Return a lazy-allocated progbuf object.
           XXX We can't fully lazy-allocate without implementing list.
           It holds a contiguous copy of all of the BPF instructions
           in a C bpf_program struct, suitable for passing to kernel
           and pcap APIs."""
        cdef progbuf pbp
        pbp = progbuf(None, self.insns)
        self.progbuf = pbp
        return pbp

    def disassemble(self):
        """Return a list of strings, each is a disassembled BPF opcode."""
        cdef unsigned int i
        cdef list result
        i = 0
        result = []
        for insn in self.insns:
            result.append(insn.disassemble(i))
            i = i + 1
        return result

    def filter(self, char *buf):
        """Return boolean match for buf against our filter."""
        cdef unsigned int buflen
        buflen = len(buf)
        return self.__progbuf__().filter(buf, buflen)

    def validate(self):
        """Return boolean True if BPF program is valid."""
        return self.__progbuf__().validate()
