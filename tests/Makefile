#
#
# File: Makefile
#
# Author: George V. Neville-Neil
#
# Makefile for running PCS regression tests.

PYTHON	= python3.3

.PHONY: test

TESTS:= $(wildcard *test.py)

test: 
	for file in $(TESTS); do\
		echo Running test $$file; \
		sudo $(PYTHON) $$file; \
	done

test-local: 
	for file in $(TESTS); do\
		echo Running test $$file; \
		sudo $(PYTHON) $$file -l; \
	done

