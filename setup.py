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
import cPickle, glob, os, sys

pcap_config = {}
pcap_cache = 'pcs/pcap/config.pkl'

class config_pcap(config.config):
    description = 'configure pcap paths'
    user_options = [ ('with-pcap=', None,
                      'path to pcap build or installation directory') ]
    
    def initialize_options(self):
        config.config.initialize_options(self)
        self.dump_source = 0
        #self.noisy = 0
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
    
    def _pcap_config(self, dirs=[ None ]):
        cfg = {}
        if not dirs[0]:
            dirs = [ '/usr', sys.prefix ] + glob.glob('/opt/libpcap*') + \
                   glob.glob('../libpcap*') + glob.glob('../wpdpack*')
        for d in dirs:
            for sd in ('include', 'include/pcap', ''):
                incdirs = [ os.path.join(d, sd) ]
                if os.path.exists(os.path.join(d, sd, 'pcap.h')):
                    cfg['include_dirs'] = [ os.path.join(d, sd) ]
                    cfg['include_dirs'] += ["pcs/bpf"]
                    for sd in ('lib64', 'lib', ''):
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

    def _rt_config(self):
        """Some systems keep their POSIX clock routines in librt."""
        cfg = {}
        dirs = [ '/', '/usr', sys.prefix ]
        for d in dirs:
            for sd in ['lib']:
                for lib in [('rt', 'librt.so')]:
                    #print "looking in", os.path.join(d, sd), "for", lib[1]
                    if os.path.exists(os.path.join(d, sd, lib[1])):
                        cfg['rt_library_dirs'] = [ os.path.join(d, sd) ]
                        cfg['rt_libraries'] = [ lib[0] ]
                        print 'found', cfg
                        return cfg

    def run(self):
        #config.log.set_verbosity(0)
        pfile = open(pcap_cache, 'wb')
        cPickle.dump(self._pcap_config([ self.with_pcap ]), pfile)
        cPickle.dump(self._rt_config(), pfile)
        self.temp_files.append(pcap_cache)

class clean_pcap(clean.clean):
    def run(self):
        clean.clean.run(self)
        if self.all and os.path.exists(pcap_cache):
            print "removing '%s'" % pcap_cache
            os.unlink(pcap_cache)

if len(sys.argv) > 1 and sys.argv[1] == 'build':
    try:
        pcap_config = cPickle.load(open(pcap_cache))
    except IOError:
        print >>sys.stderr, 'run "%s config" first!' % sys.argv[0]
        sys.exit(1)

# XXX The Pyrex Distutils extension is currently unable to propagate
# dependencies on *.pxd files. If you change them you SHOULD rebuild from
# scratch to be sure dependencies are not stale.

pcap = Extension(name='pcs.pcap',
                 sources=[ 'pcs/pcap/pcap.pyx', 'pcs/pcap/pcap_ex.c' ],
                 include_dirs=pcap_config.get('include_dirs', ''),
                 library_dirs=pcap_config.get('library_dirs', ''),
                 libraries=pcap_config.get('libraries', ''),
                 extra_compile_args=pcap_config.get('extra_compile_args', '')
	)

bpf = Extension(name='pcs.bpf',
                 sources=[ 'pcs/bpf/bpf.pyx' ],
                 include_dirs=pcap_config.get('include_dirs', ''),
                 library_dirs=pcap_config.get('library_dirs', ''),
                 libraries=pcap_config.get('libraries', ''),
                 extra_compile_args=pcap_config.get('extra_compile_args', '')
	)

clock = Extension(name='pcs.clock',
                  sources=[ 'pcs/clock/clock.pyx' ],
                  library_dirs=pcap_config.get('rt_library_dirs', ''),
                  libraries=pcap_config.get('rt_libraries', '')
	)

#fast = Extension(name='pcs.fast',
#                  sources=[ 'pcs/fast.pyx' ],
#	)


# XXX Distutils only allows a single command class, direct everything
# to the configuration wrapper for pcap.
pcs_cmds = { 'config':config_pcap, 'clean':clean_pcap, 'build_ext':build_ext }

setup(name='pcs',
      version='0.5',
      description='Packet Construction Set',
      author='George V. Neville-Neil',
      author_email='gnn@neville-neil.com',
      url='http://pcs.sf.net',
      packages = ['pcs', 'pcs.packets'],
      cmdclass=pcs_cmds,
#      ext_modules = [ fast, bpf, clock, pcap ],
      ext_modules = [ bpf, clock, pcap ],
      )
