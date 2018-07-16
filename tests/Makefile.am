noinst_PROGRAMS = test_keys test_message test_postage test_utime test_nak
TESTS = test_keys test_message test_postage test_utime test_nak

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
