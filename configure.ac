AC_INIT([libciphrtxt], [0.1], [https://github.com/jadeblaquiere/ctclient/issues])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_PROG_CC
AM_PROG_AR
LT_INIT
AC_CHECK_LIB([gmp], [__gmpz_realloc])
AC_CHECK_LIB([ecc], [mpFp_init])
AC_CHECK_LIB([fspke], [CHKPKE_init_Gen])
AC_CHECK_LIB([sodium], [crypto_scalarmult_ed25519])
PKG_CHECK_MODULES([CHECK], [check])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_OUTPUT([Makefile src/Makefile include/Makefile tests/Makefile])
