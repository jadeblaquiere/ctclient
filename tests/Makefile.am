noinst_PROGRAMS = test_keys test_message test_postage
TESTS = test_keys test_message test_postage

test_keys_SOURCES = test_keys.c
test_keys_CFLAGS = -Wall -I ../include $(CFLAGS) -I $(prefix)/include/pbc $(CHECK_CFLAGS)
test_keys_LDADD = -L../src/.libs/ -lciphrtxt -ltasn1 $(LDFLAGS) $(CHECK_LIBS)

test_message_SOURCES = test_message.c
test_message_CFLAGS = -Wall -I ../include $(CFLAGS) -I $(prefix)/include/pbc $(CHECK_CFLAGS)
test_message_LDADD = -L../src/.libs/ -lciphrtxt -ltasn1 $(LDFLAGS) $(CHECK_LIBS)

test_postage_SOURCES = test_postage.c
test_postage_CFLAGS = -Wall -I ../include $(CFLAGS) -I $(prefix)/include/pbc $(CHECK_CFLAGS)
test_postage_LDADD = -L../src/.libs/ -lciphrtxt -ltasn1 $(LDFLAGS) $(CHECK_LIBS)
