#
#
# File: Makefile
#
# Author: George V. Neville-Neil
#
# Makefile for running PCS regression tests.

PYTHON	= python

.PHONY: test

TESTS:= $(wildcard *test.py)

test: 
	for file in $(TESTS); do\
		echo Running test $$file; \
		sudo $(PYTHON) $$file; \
	done