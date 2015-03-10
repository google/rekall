# http://gnu-autoconf.7623.n7.nabble.com/detecting-windows-td14077.html

# MINGW_AC_WIN32_NATIVE_HOST
# --------------------------
# Check if the runtime platform is a native Win32 host.
#
AC_DEFUN([MINGW_AC_WIN32_NATIVE_HOST],
  [AC_CACHE_CHECK([whether we are building for a Win32 host], [mingw_cv_win32_host],
     AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#ifdef _WIN32
 choke me
#endif
])], [mingw_cv_win32_host=no], [mingw_cv_win32_host=yes]))

])# MINGW_AC_WIN32_NATIVE_HOST

# GCC_AC_LINUX_NATIVE_HOST
# --------------------------
# Check if the runtime platform is a native linux host.
#
AC_DEFUN([GCC_AC_LINUX_NATIVE_HOST],
  [AC_CACHE_CHECK([whether we are building for a linux host], [gcc_cv_linux_host],
     AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#ifdef __linux__
 choke me
#endif
])], [gcc_cv_linux_host=no], [gcc_cv_linux_host=yes]))

])

# GCC_AC_OSX_NATIVE_HOST
# --------------------------
# Check if the runtime platform is a native linux host.
#
AC_DEFUN([GCC_AC_OSX_NATIVE_HOST],
  [AC_CACHE_CHECK([whether we are building for a osx host], [gcc_cv_osx_host],
     AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#if defined(__APPLE__) && defined(__MACH__)
 choke me
#endif
])], [gcc_cv_osx_host=no], [gcc_cv_osx_host=yes]))

])
