#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([PMEM], [0.1], [rekall-discuss@googlegroups.com])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_CONFIG_MACRO_DIR([m4])

SO_VERSION=0:0:0

AC_CONFIG_SRCDIR([.])
AC_CONFIG_HEADERS([config.h])

AC_LANG(C++)

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

AC_ARG_ENABLE([linux-pmem],
  AS_HELP_STRING([--enable-linux-pmem], [Build the LinuxPmem imager.]))

AM_CONDITIONAL([STATIC_BUILD], [test x$enable_linux_pmem = xyes])

MINGW_AC_WIN32_NATIVE_HOST
AM_CONDITIONAL([WIN32_NATIVE_HOST], [test x$mingw_cv_win32_host = xyes])

GCC_AC_LINUX_NATIVE_HOST
AM_CONDITIONAL([LINUX_NATIVE_HOST], [test x$gcc_cv_linux_host = xyes])

GCC_AC_OSX_NATIVE_HOST
AM_CONDITIONAL([OSX_NATIVE_HOST], [test x$gcc_cv_osx_host = xyes])


# Checks for libraries.
#AC_CHECK_LIB([aff4], [AFF4_version], [], [
#  echo AFF4 library not found. Please download from www.aff4.org.
#  exit -1
#])
AC_CHECK_LIB([pcre++], [main], [], [AC_MSG_ERROR([pcre++ library (libpcre++-dev) not found])])

# We store machine stats in Yaml so this is a hard requirement.
AS_IF([test "x$enable_yaml" = "xyes"],
  AC_CHECK_LIB([yaml-cpp], [main], [], [
    echo libyaml-cpp not found. On debian systems this is provided by
    echo apt-get install libyaml-cpp-dev
    exit -1
  ])
)

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_INT32_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

AM_PROG_AR
LT_INIT
AM_CONDITIONAL(GCC, test "$GCC" = yes)   # let the Makefile know if we're gcc

AC_ARG_ENABLE([static-binaries],
  AS_HELP_STRING([--enable-static-binaries], [Build completely static binaries.]))

AM_CONDITIONAL([STATIC_BUILD], [test x$enable_static_binaries = xyes])

# Checks for library functions.
AC_CHECK_FUNCS([ftruncate localtime_r memset setenv])

AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)
AC_SUBST(SO_VERSION)

AC_CONFIG_FILES([
        Makefile
        ])

AC_OUTPUT
