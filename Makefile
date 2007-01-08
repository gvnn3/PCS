#
#
# File: $Id: Makefile,v 1.2 2006/06/15 07:52:02 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Makefile for building distributions of PCS.  
install::
	python setup.py install

dist::
	python setup.py sdist

clean::
	rm -rf dist build MANIFEST