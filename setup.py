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

class config_pcap(config.config):
    description = 'configure pcap paths'
    user_options = [ ('with-pcap=', None,
                      'path to pcap build or installation directory') ]
    
    def initialize_options(self):
        config.config.initialize_options(self)
        self.dump_source = 0
        self.noisy = 1
        self.with_pcap = None

    def _write_config_h(self, cfg):
        # XXX - write out config.h for pcap_ex.c
        d = {}
        if os.path.exists(os.path.join(cfg['include_dirs'][0], 'pcap-int.h')):
            d['HAVE_PCAP_INT_H'] = 1
        buf = open(os.path.join(cfg['include_dirs'][0], 'pcap.h')).read()
        if buf.find('pcap_file(') != -1:
            d['HAVE_PCAP_FILE'] = 1
        if buf.find('pcap_compile_nopcap(') != -1:
            d['HAVE_PCAP_COMPILE_NOPCAP'] = 1
        if buf.find('pcap_setnonblock(') != -1:
            d['HAVE_PCAP_SETNONBLOCK'] = 1
        f = open('pcs/pcap/config.h', 'w')
        for k, v in d.iteritems():
            f.write('#define %s %s\n' % (k, v))
        f.close()
    
    def _pcap_config(self, dirs=[ None ]):
        cfg = {}
        if not dirs[0]:
            dirs = [ '/usr', sys.prefix ] + glob.glob('/opt/libpcap*') + \
                   glob.glob('../libpcap*') + glob.glob('../wpdpack*')
        for d in dirs:
            for sd in ('include/pcap', 'include', ''):
                incdirs = [ os.path.join(d, sd) ]
                if os.path.exists(os.path.join(d, sd, 'pcap.h')):
                    cfg['include_dirs'] = [ os.path.join(d, sd) ]
                    for sd in ('lib', ''):
                        for lib in (('pcap', 'libpcap.a'),
                                    ('pcap', 'libpcap.dylib'),
                                    ('wpcap', 'wpcap.lib')):
                            if os.path.exists(os.path.join(d, sd, lib[1])):
                                cfg['library_dirs'] = [ os.path.join(d, sd) ]
                                cfg['libraries'] = [ lib[0] ]
                                if lib[0] == 'wpcap':
                                    cfg['libraries'].append('iphlpapi')
                                    cfg['extra_compile_args'] = \
                                        [ '-DWIN32', '-DWPCAP' ]
                                print 'found', cfg
                                self._write_config_h(cfg)
                                return cfg
        raise "couldn't find pcap build or installation directory"
    
    def run(self):
        self._pcap_config([ self.with_pcap ])

# XXX The Pyrex Distutils extension is currently unable to propagate
# dependencies on *.pxd files. If you change them you SHOULD rebuild from
# scratch to be sure dependencies are not stale.

pcap = Extension(name='pcs.pcap',
                 sources=[ 'pcs/pcap/pcap.pyx', 'pcs/pcap/pcap_ex.c' ],
                 include_dirs=["/usr/include/pcap"],
                 library_dirs=["/usr/lib"],
                 libraries=["pcap"]
	)

bpf = Extension(name='bpf',
                 sources=[ 'pcs/bpf/bpf.pyx' ],
                 include_dirs=["/usr/include/pcap"],
                 library_dirs=["/usr/lib"],
                 libraries=["pcap"]
	)

clock = Extension(name='pcs.clock',
                  sources=[ 'pcs/clock/clock.pyx' ],
                  library_dirs=[],
                  libraries=[],
	)

pcs_cmds = { 'config': config_pcap, 'build_ext':build_ext }

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


