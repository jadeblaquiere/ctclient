noinst_PROGRAMS = ctkey_gen 

ctkey_gen_SOURCES = ctkey_gen.c b64file.c
ctkey_gen_CFLAGS = -Wall -I ../include -I $(prefix)/include/pbc $(CFLAGS)
ctkey_gen_LDADD = -L../src/.libs/ -lciphrtxt -lfspke -lpbc -lecc -lgmp -ltasn1 -lpopt -lb64 $(LDFLAGS)
