noinst_PROGRAMS = test_keys test_message
TESTS = test_keys test_message

test_keys_SOURCES = test_keys.c
test_keys_CFLAGS = -Wall -I ../include $(CFLAGS) -I $(prefix)/include/pbc $(CHECK_CFLAGS)
test_keys_LDADD = -L../src/.libs/ -lciphrtxt -ltasn1 $(LDFLAGS) $(CHECK_LIBS)

test_message_SOURCES = test_message.c
test_message_CFLAGS = -Wall -I ../include $(CFLAGS) -I $(prefix)/include/pbc $(CHECK_CFLAGS)
test_message_LDADD = -L../src/.libs/ -lciphrtxt -ltasn1 $(LDFLAGS) $(CHECK_LIBS)
