noinst_PROGRAMS = test_keys
TESTS = test_keys

test_keys_SOURCES = test_keys.c
test_keys_CFLAGS = -Wall -I ../include $(CFLAGS) -I $(prefix)/include/pbc $(CHECK_CFLAGS)
test_keys_LDADD = -L../src/.libs/ -lciphrtxt -lfspke -lecc -lgmp -lpbc -ltasn1 $(LDFLAGS) $(CHECK_LIBS)

