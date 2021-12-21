#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.70])
AC_INIT([airkick],[1.2.4],[vanziegelstein@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([src/housekeeping.h])
AC_CONFIG_HEADERS([config.h])

# Some preprocessor macros
AC_DEFINE([MAX_CON_DEFAULT], [10], [Default maximum of tracked connections])
AC_DEFINE([FLUSH_PERIOD], [600], [Time frame (in seconds) after which the connection backlog is flushed])
AC_DEFINE([STRERROR_BUFFSIZE], [1024], [Size of the error code buffer for strerror_r])
AC_DEFINE([MAX_CAP_SIZE], [4096], [Max capture length for packets])

# Checks for programs.
AC_PROG_CC
AC_LANG([C])

# Checks for libraries.
AC_CHECK_LIB([iw], [iw_mac_aton], [], [
             echo "Missing dependency: iw library from wireless-tools."
	     exit -1])
AC_CHECK_LIB([mnl], [mnl_nlmsg_get_payload], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_attr_get_type], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_attr_type_valid], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_attr_validate2], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_attr_validate], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_socket_close], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_attr_get_payload_len], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_attr_get_u8], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_attr_get_str], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_attr_next], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_attr_ok], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_attr_parse], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_socket_open], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_socket_bind], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_socket_get_fd], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_socket_recvfrom], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_cb_run], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_socket_sendto], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([mnl], [mnl_nlmsg_put_extra_header], [], [
	      echo "Missing dependency: mnl libary from netlink."
	      exit -1])
AC_CHECK_LIB([pcap], [pcap_loop], [], [
             echo "Missing dependency: pcap library."
	     exit -1])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h unistd.h math.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([memset munmap regcomp])

AC_CONFIG_FILES([Makefile src/Makefile data/Makefile])
AC_OUTPUT
