AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS)
AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include

sbin_PROGRAMS = osmomitm
osmomitm_SOURCES = osmo-mitm.c shared/osmo_mcast_sock.c shared/virtual_um.c
osmomitm_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)
