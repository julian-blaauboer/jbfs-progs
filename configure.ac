AC_PREREQ([2.70])
AC_INIT([jbfs-progs], [0.2.0-alpha], [julian.blaauboer@gmail.com])
AC_CONFIG_SRCDIR([common/jbfs.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strtoul])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_CONFIG_FILES([Makefile
		 mkfs/Makefile
		 version.h])

AC_OUTPUT
