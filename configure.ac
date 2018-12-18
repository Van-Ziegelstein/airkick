#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([airkick], [1.0], [vanziegelstein@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([src/housekeeping.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_LANG([C])
AC_PROG_CC_STDC

# Checks for libraries.
AC_CHECK_LIB([iw], [iw_mac_aton], [], [
             echo "Missing dependency: iw library from wireless-tools."
	     exit -1])
AC_CHECK_LIB([net], [libnet_compute_crc], [], [
             echo "Missing dependency: libnet."
	     exit -1])
AC_CHECK_LIB([pcap], [pcap_loop], [], [
             echo "Missing dependency: pcap library."
	     exit -1])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT