dnl Process this file with autoconf to produce a configure script
AC_INIT([osmo-mitm], 0.0.0)

AM_INIT_AUTOMAKE([foreign dist-bzip2 subdir-objects])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL

dnl checks for header files
AC_HEADER_STDC

dnl checks for libraries
LIBOSMOCORE_REQUIRED_VERSION=0.3.9
LIBOSMOGSM_REQUIRED_VERSION=0.3.3
PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore  >= $LIBOSMOCORE_REQUIRED_VERSION)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= $LIBOSMOGSM_REQUIRED_VERSION)

AC_MSG_NOTICE(CPPFLAGS is $CPPFLAGS)
AC_MSG_NOTICE(CFLAGS is $CFLAGS)
AC_MSG_NOTICE(LIBOSMOCORE_CFLAGS is $LIBOSMOCORE_CFLAGS)
AC_MSG_NOTICE(LIBOSMOGSM_CFLAGS is $LIBOSMOGSM_CFLAGS)

AC_CONFIG_FILES([
	Makefile 
	src/Makefile
])
AC_OUTPUT
