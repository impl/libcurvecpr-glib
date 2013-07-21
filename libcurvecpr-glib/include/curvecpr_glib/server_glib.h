#ifndef __CURVECPR_GLIB_SERVER_GLIB_H
#define __CURVECPR_GLIB_SERVER_GLIB_H

#include <curvecpr/server.h>
#include <curvecpr/session.h>

#include <glib.h>

struct curvecpr_server_glib_session {
    struct curvecpr_session session;
    GData *privs;
};

struct curvecpr_server_glib;

struct curvecpr_server_glib_ops {
    int (*connected)(struct curvecpr_server_glib *sg, struct curvecpr_server_glib_session *sgs, void *priv);
    void (*disconnected)(struct curvecpr_server_glib *sg, struct curvecpr_server_glib_session *sgs);

    int (*send)(struct curvecpr_server_glib *sg, struct curvecpr_server_glib_session *sgs, void *priv, const unsigned char *buf, size_t num);
    int (*recv)(struct curvecpr_server_glib *sg, struct curvecpr_server_glib_session *sgs, void *priv, const unsigned char *buf, size_t num);

    int (*next_nonce)(struct curvecpr_server_glib *sg, unsigned char *destination, size_t num);
};

struct curvecpr_server_glib_cf {
    /* Any extensions. */
    unsigned char my_extension[16];

    /* Curve25519 public/private keypairs. */
    unsigned char my_global_pk[32];
    unsigned char my_global_sk[32];

    struct curvecpr_server_glib_ops ops;

    void *priv;
};

struct curvecpr_server_glib {
    struct curvecpr_server_glib_cf cf;

    struct curvecpr_server server;

    GHashTable *sessions;
};

void curvecpr_server_glib_new (struct curvecpr_server_glib *sg, struct curvecpr_server_glib_cf *cf);
void curvecpr_server_glib_dealloc (struct curvecpr_server_glib *sg);
void curvecpr_server_glib_refresh_temporal_keys (struct curvecpr_server_glib *sg);
int curvecpr_server_glib_send_by_pk (struct curvecpr_server_glib *sg, const unsigned char their_session_pk[32], void *priv, const unsigned char *buf, size_t num);
int curvecpr_server_glib_send (struct curvecpr_server_glib *sg, struct curvecpr_server_glib_session *sgs, void *priv, const unsigned char *buf, size_t num);
int curvecpr_server_glib_recv (struct curvecpr_server_glib *sg, void *priv, const unsigned char *buf, size_t num, struct curvecpr_server_glib_session **sgs_stored);
int curvecpr_server_glib_get_session (struct curvecpr_server_glib *sg, const unsigned char their_session_pk[32], struct curvecpr_server_glib_session **sgs_stored);
int curvecpr_server_glib_dealloc_session (struct curvecpr_server_glib *sg, struct curvecpr_server_glib_session *sgs);

#endif
