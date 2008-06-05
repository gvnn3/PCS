#
#
# File: Makefile
#
# Author: George V. Neville-Neil
#
# Makefile for running PCS regression tests.

PYTHON	= python

PYVERSIONS = python2.3 python2.4 python2.5

.PHONY: test

TESTS:= $(wildcard *test.py)

test: 
	for file in $(TESTS); do\
		echo Running test $$file; \
		sudo PYTHONPATH=${PYTHONPATH} $(PYTHON) $$file; \
	done

test-local: 
	for file in $(TESTS); do\
		echo Running test $$file; \
		sudo $(PYTHON) $$file -l; \
	done

test-versions:
	for version in $(PYVERSIONS); do\
		echo testing version $$version; \
		for file in $(TESTS); do\
			echo Running test $$file; \
			sudo PYTHONPATH=${PYTHONPATH} $$version $$file -l; \
		done \
	done
