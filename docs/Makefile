#
# File: $Id: Makefile,v 1.1 2006/06/15 07:52:02 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Documentation Makefile for PCS.  You can build various versions of
# the docs from here.

.SUFFIXES: .tex .pdf

SRCS= pcs.tex design.tex

all: ${SRCS:S/.tex/.pdf/} man latex

.tex.pdf:
	pdflatex ${.IMPSRC}

man::
	doxygen
clean::
	rm -rf *.pdf *.html *.out *.log Web/html man latex