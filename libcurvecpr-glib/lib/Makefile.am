lib_LTLIBRARIES = libcurvecpr-glib.la

libcurvecpr_glib_la_CPPFLAGS = -I$(top_srcdir)/libcurvecpr-glib/include
libcurvecpr_glib_la_CFLAGS = @GLIB_CFLAGS@ @LIBCURVECPR_CFLAGS@
libcurvecpr_glib_la_LDFLAGS = -version-info $(CURVECPR_GLIB_LIBRARY_VERSION) @GLIB_LIBS@ @LIBCURVECPR_LIBS@
libcurvecpr_glib_la_SOURCES = \
    client_messager_glib.c \
    messager_glib.c \
    server_glib.c \
    server_messager_glib.c
