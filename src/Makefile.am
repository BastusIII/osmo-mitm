AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS)
AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include

CFLAGS = -g -O0

sbin_PROGRAMS = osmomitmsimple dummycoder osmomitmsetupmanip osmomitmimsicatcher 

osmomitmsimple_SOURCES = osmo_mitm.c shared/osmo_mcast_sock.c shared/virtual_um.c mitm_handler_simple.c
osmomitmsimple_LDADD = $(LIBOSMOCORE_LIBS)

osmomitmimsicatcher_SOURCES = osmo_mitm.c shared/osmo_mcast_sock.c shared/virtual_um.c mitm_handler_imsi_catcher.c shared/common_util.c lapdm_util.c l1_util.c subscriber_mapping.c
osmomitmimsicatcher_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)

osmomitmsetupmanip_SOURCES = osmo_mitm.c shared/osmo_mcast_sock.c shared/virtual_um.c mitm_handler_setup_manip.c shared/common_util.c lapdm_util.c l1_util.c subscriber_mapping.c coder.c
osmomitmsetupmanip_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)

dummycoder_SOURCES = dummy_coder_cipherer.c coder.c cipherer.c
dummycoder_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)