AC_PREREQ(2.67)
AC_INIT(libcurvecpr-glib, 0.1.0, nfontes+libcurvecpr@cynigram.com, libcurvecpr-glib)
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AC_CONFIG_SRCDIR([libcurvecpr-glib/include/curvecpr_glib.h])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Library version.
CURVECPR_GLIB_LIBRARY_VERSION=1:0:0
AC_SUBST(CURVECPR_GLIB_LIBRARY_VERSION)

# Checks for programs.
AM_PROG_AR

AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PROG_MAKE_SET

AM_PROG_CC_C_O

PKG_PROG_PKG_CONFIG

# Checks for libraries.
PKG_CHECK_MODULES([CHECK], [check >= 0.9.8])
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.34.0])
PKG_CHECK_MODULES([LIBCURVECPR], [libcurvecpr >= 0.1.2])
PKG_CHECK_MODULES([LIBSODIUM], [libsodium >= 0.4.3])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([errno.h stdint.h string.h], [], [AC_MSG_ERROR([missing required header file(s)])])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for compiler flags.
CCHECKFLAGS="-Wno-error"
AX_CHECK_COMPILE_FLAG([-Werror=unknown-warning-option], [CCHECKFLAGS="$CCHECKFLAGS -Werror=unknown-warning-option"], [], [-Werror])
AX_CHECK_COMPILE_FLAG([-Werror=unused-command-line-argument], [CCHECKFLAGS="$CCHECKFLAGS -Werror=unused-command-line-argument"], [], [-Werror])

CPPFLAGS="$CPPFLAGS -D_FORTIFY_SOURCE=2"
AX_APPEND_COMPILE_FLAGS([-fno-strict-aliasing -fno-strict-overflow], [], [$CCHECKFLAGS])
AX_CHECK_LINK_FLAG([-fstack-protector], [AX_APPEND_COMPILE_FLAGS([-fstack-protector], [], [$CCHECKFLAGS])], [], [], [$CCHECKFLAGS])
AX_CHECK_LINK_FLAG([-fstack-protector-all], [AX_APPEND_COMPILE_FLAGS([-fstack-protector-all], [], [$CCHECKFLAGS])], [], [], [$CCHECKFLAGS])
AX_APPEND_COMPILE_FLAGS([ dnl
    -Wall -Wextra -Wcast-qual -Wcast-align -Winline -Wmissing-prototypes -Wmissing-declarations dnl
    -Wwrite-strings -Wredundant-decls -Wpointer-arith -Wchar-subscripts -Wshadow -Wstrict-prototypes dnl
    -Wvariable-decl -Winit-self -Wdiv-by-zero -Wsometimes-uninitialized -Wbad-function-cast -Wcomment dnl
    -Wfloat-equal -Wformat=2 -Wimplicit -Wnormalized=id -Woverride-init -Wparentheses -Wswitch-enum dnl
    -Wno-unused-parameter dnl
], [], [$CCHECKFLAGS])
AX_APPEND_LINK_FLAGS([-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack], [], [$CCHECKFLAGS])

# Done!
AC_CONFIG_FILES([
    libcurvecpr-glib/include/Makefile
    libcurvecpr-glib/lib/Makefile
    libcurvecpr-glib/test/Makefile
    libcurvecpr-glib/Makefile
    libcurvecpr-glib/libcurvecpr-glib.pc
    Makefile
])
AC_OUTPUT
