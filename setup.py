#!/usr/bin/env python
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
# File: $Id: setup.py,v 1.4 2006/09/05 07:36:27 gnn Exp $
#            setup.py,v 1.14 2005/10/16 23:07:03 dugsong Exp $
#
# Author: George V. Neville-Neil
#
# Description: The setup script for all of the Packet Construction Set
#

from distutils.core import setup
from distutils.command import config, clean
from distutils.extension import Extension
from Cython.Distutils import build_ext
import glob, os, sys


# XXX The Pyrex Distutils extension is currently unable to propagate
# dependencies on *.pxd files. If you change them you SHOULD rebuild from
# scratch to be sure dependencies are not stale.

pcap = Extension(name='pcs.pcap',
                 sources=[ 'pcs/pcap/pcap.pyx', 'pcs/pcap/pcap_ex.c' ],
                 include_dirs=["/usr/include"],
                 library_dirs=["/usr/lib"],
                 libraries=["pcap"]
	)

bpf = Extension(name='pcs.bpf',
                 sources=[ 'pcs/bpf/bpf.pyx' ],
                 include_dirs=["/usr/include"],
                 library_dirs=["/usr/lib"],
                 libraries=["pcap"]
	)

clock = Extension(name='pcs.clock',
                  sources=[ 'pcs/clock/clock.pyx' ],
                  library_dirs=[],
                  libraries=[],
	)

pcs_cmds = { 'build_ext':build_ext }

setup(name='pcs',
      version='0.6',
      description='Packet Construction Set',
      author='George V. Neville-Neil',
      author_email='gnn@neville-neil.com',
      url='http://pcs.sf.net',
      packages = ['pcs', 'pcs.packets'],
      cmdclass=pcs_cmds,
      ext_modules = [ bpf, clock, pcap ],
      )


