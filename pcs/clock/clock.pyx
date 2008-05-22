#
# bpf.pyx
#
# $Id$

"""Clock module

This module provides a Python front-end for POSIX clocks.
"""

__author__ = 'Bruce M. Simpson <bms@incunabulum.net>'
__maintainer__ = 'Bruce M. Simpson <bms@incunabulum.net>'
__copyright__ = 'Copyright (c) 2008 Bruce M. Simpson'
__license__ = 'BSD license'
__url__ = 'http://pcs.sf.net'
__version__ = '1.0'
__revison__ = '0'

# Most of these are simply stubbed on Windows, because
# supporting them properly requires Vista/Longhorn.

ctypedef int clockid_t

# POSIX clock IDs
CLOCK_REALTIME = 0
CLOCK_VIRTUAL = 1
CLOCK_PROF = 2
CLOCK_MONOTONIC = 4

# FreeBSD-specific clock IDs
IF UNAME_SYSNAME == "FreeBSD":
    CLOCK_UPTIME = 5
    CLOCK_UPTIME_PRECISE = 7
    CLOCK_UPTIME_FAST = 8
    CLOCK_REALTIME_PRECISE = 9
    CLOCK_REALTIME_FAST = 10
    CLOCK_MONOTONIC_PRECISE = 11
    CLOCK_MONOTONIC_FAST = 12
    CLOCK_SECOND = 13

cdef extern from "time.h":
    struct timespec:
        unsigned int tv_sec
        long tv_nsec

cdef extern from "time.h":
    int clock_gettime(clockid_t clock_id, timespec *tp)
    int clock_settime(clockid_t clock_id, timespec *tp)
    int clock_getres(clockid_t clock_id, timespec *tp)

def gettime(clockid_t clock_id):
    """Get the time kept by a POSIX clock. Return float or None."""
    IF UNAME_SYSNAME == "Windows":
        return None
    ELSE:
        cdef timespec t
        cdef int rc
        cdef double result
        rc = clock_gettime(clock_id, &t)
        if rc != 0:
            return None
        result = _timespec_to_double(&t)
        return result		# implicit conversion C double->Python Float

def settime(clockid_t clock_id, double value):
    """Set the time for a POSIX clock. Return boolean success."""
    IF UNAME_SYSNAME == "Windows":
        return False
    ELSE:
        cdef timespec t
        cdef int rc
        # implicit conversion Python float->C double
        _double_to_timespec(value, &t)
        rc = clock_settime(clock_id, &t)
        return bool(rc == 0)

def getres(clockid_t clock_id):
    """Get the resolution of a POSIX clock. Return float or None."""
    IF UNAME_SYSNAME == "Windows":
        return None
    ELSE:
        cdef timespec t
        cdef int rc
        cdef double result
        rc = clock_getres(clock_id, &t)
        if rc != 0:
            return None
        result = _timespec_to_double(&t)
        return result

# This looks gnarly. We need to preserve the precision of the POSIX
# timespec, but doing this needs to be somewhat munged to use plain
# C arithmetic in Pyrex syntax.

cdef void _double_to_timespec(double f, timespec *tp):
    """Convert a double to a normalized timespec."""
    tp[0].tv_sec = <unsigned int>f
    tp[0].tv_nsec = <unsigned int>((f - (<double>tp[0].tv_nsec)) *
                                    1000000000 + 0.5e-9)
    if tp[0].tv_nsec >= 1000000000:
        tp[0].tv_sec = tp[0].tv_sec + (tp[0].tv_nsec / 1000000000)
        tp[0].tv_nsec = tp[0].tv_nsec % 1000000000

cdef double _timespec_to_double(timespec *tp):
    """Convert a normalized timespec to a double."""
    cdef double result
    result = tp[0].tv_sec * 1.0
    result = result + (tp[0].tv_nsec * 1.0e-9)
    return result
