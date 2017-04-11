AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS)
AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include

CFLAGS = -g -O0

sbin_PROGRAMS = osmomitmsimple osmomitmsetupmanip dummycoder

osmomitmsimple_SOURCES = osmo_mitm.c mitm_handler_simple.c shared/osmo_mcast_sock.c shared/virtual_um.c
osmomitmsimple_LDADD = $(LIBOSMOCORE_LIBS)

osmomitmsetupmanip_SOURCES = osmo_mitm.c mitm_handler_setup_manip.c shared/osmo_mcast_sock.c shared/virtual_um.c coder.c shared/common_util.c lapdm_util.c
osmomitmsetupmanip_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)

dummycoder_SOURCES = dummy_coder_cipherer.c coder.c cipherer.c
dummycoder_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)