TESTS = test_keys test_message test_postage test_utime test_nak test_client test_rawmessage
MTESTS = mtest_nak
noinst_PROGRAMS = $(TESTS) $(MTESTS)

test_keys_SOURCES = test_keys.c
test_keys_CFLAGS = -Wall -I ../include $(CFLAGS) -I $(prefix)/include/pbc $(CHECK_CFLAGS)
test_keys_LDADD = -L../src/.libs/ -lciphrtxt -ltasn1 $(LDFLAGS) $(CHECK_LIBS)

test_message_SOURCES = test_message.c
test_message_CFLAGS = -Wall -I ../include $(CFLAGS) -I $(prefix)/include/pbc $(CHECK_CFLAGS)
test_message_LDADD = -L../src/.libs/ -lciphrtxt -ltasn1 $(LDFLAGS) $(CHECK_LIBS)

test_postage_SOURCES = test_postage.c
test_postage_CFLAGS = -Wall -I ../include $(CFLAGS) -I $(prefix)/include/pbc $(CHECK_CFLAGS)
test_postage_LDADD = -L../src/.libs/ -lciphrtxt -ltasn1 $(LDFLAGS) $(CHECK_LIBS)

test_utime_SOURCES = test_utime.c
test_utime_CFLAGS = -Wall -I ../include $(CFLAGS) -I $(prefix)/include/pbc $(CHECK_CFLAGS)
test_utime_LDADD = -L../src/.libs/ -lciphrtxt -ltasn1 $(LDFLAGS) $(CHECK_LIBS)

test_nak_SOURCES = test_nak.c
test_nak_CFLAGS = -Wall -I ../include $(CFLAGS) -I $(prefix)/include/pbc $(CHECK_CFLAGS)
test_nak_LDADD = -L../src/.libs/ -lciphrtxt -ltasn1 $(LDFLAGS) $(CHECK_LIBS)

mtest_nak_SOURCES = mtest_nak.c
mtest_nak_CFLAGS = -Wall -I ../include $(CFLAGS) -I $(prefix)/include/pbc $(CHECK_CFLAGS)
mtest_nak_LDADD = -L../src/.libs/ -lciphrtxt -ltasn1 $(LDFLAGS) $(CHECK_LIBS)

test_client_SOURCES = test_client.c
test_client_CFLAGS = -Wall -I ../include $(CFLAGS) -I $(prefix)/include/pbc $(CHECK_CFLAGS)
test_client_LDADD = -L../src/.libs/ -lciphrtxt -ltasn1 $(LDFLAGS) $(CHECK_LIBS)

test_rawmessage_SOURCES = test_rawmessage.c
test_rawmessage_CFLAGS = -Wall -I ../include $(CFLAGS) -I $(prefix)/include/pbc $(CHECK_CFLAGS)
test_rawmessage_LDADD = -L../src/.libs/ -lciphrtxt -ltasn1 $(LDFLAGS) $(CHECK_LIBS)
