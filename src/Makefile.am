BUILT_SOURCES=ciphrtxt_asn1_tab.c
lib_LTLIBRARIES=libciphrtxt.la
libciphrtxt_la_SOURCES = keys.c ciphrtxt_asn1_tab.c
libciphrtxt_la_CFLAGS = -Wall -fno-builtin-memset -I ../include -I $(prefix)/include/pbc
libciphrtxt_la_LDFLAGS = -version-info 1:1:0
CLEANFILES=ciphrtxt_asn1_tab.c
ciphrtxt_asn1_tab.c: ciphrtxt.asn
	asn1Parser ciphrtxt.asn
