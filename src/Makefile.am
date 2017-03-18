AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS)
AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include

CFLAGS = -g -O0

sbin_PROGRAMS = osmomitm dummycoder

osmomitm_SOURCES = osmo-mitm.c shared/osmo_mcast_sock.c shared/virtual_um.c
osmomitm_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)

dummycoder_SOURCES = dummy_coder_cipherer.c coder.c cipherer.c
dummycoder_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)