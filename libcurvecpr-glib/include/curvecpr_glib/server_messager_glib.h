#ifndef __CURVECPR_GLIB_SERVER_MESSAGER_GLIB_H
#define __CURVECPR_GLIB_SERVER_MESSAGER_GLIB_H

#include <curvecpr_glib/server_glib.h>

#include <curvecpr/block.h>

struct curvecpr_server_messager_glib;

struct curvecpr_server_messager_glib_ops {
    int (*connected)(struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs, void *priv);
    void (*disconnected)(struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs);

    int (*send)(struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs, const unsigned char *buf, size_t num);
    int (*recv)(struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs, const unsigned char *buf, size_t num);
    void (*finished)(struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs, enum curvecpr_block_eofflag flag);

    void (*put_session_priv)(struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs, void *priv);

    int (*next_nonce)(struct curvecpr_server_messager_glib *smg, unsigned char *destination, size_t num);
};

struct curvecpr_server_messager_glib_cf {
    /* Any extensions. */
    unsigned char my_extension[16];

    /* Curve25519 public/private keypairs. */
    unsigned char my_global_pk[32];
    unsigned char my_global_sk[32];

    /* Messager configuration. */
    crypto_uint64 pending_maximum;
    unsigned int sendmarkq_maximum;
    unsigned int recvmarkq_maximum;

    struct curvecpr_server_messager_glib_ops ops;

    void *priv;

};

struct curvecpr_server_messager_glib {
    struct curvecpr_server_messager_glib_cf cf;

    struct curvecpr_server_glib sg;
};

void curvecpr_server_messager_glib_new (struct curvecpr_server_messager_glib *smg, struct curvecpr_server_messager_glib_cf *cf);
void curvecpr_server_messager_glib_dealloc (struct curvecpr_server_messager_glib *smg);
void curvecpr_server_messager_glib_refresh_temporal_keys (struct curvecpr_server_messager_glib *smg);
int curvecpr_server_messager_glib_send_by_pk (struct curvecpr_server_messager_glib *smg, const unsigned char their_session_pk[32], const unsigned char *buf, size_t num);
int curvecpr_server_messager_glib_send (struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs, const unsigned char *buf, size_t num);
int curvecpr_server_messager_glib_recv (struct curvecpr_server_messager_glib *smg, void *priv, const unsigned char *buf, size_t num, struct curvecpr_server_glib_session **sgs_stored);
int curvecpr_server_messager_glib_get_session (struct curvecpr_server_messager_glib *smg, const unsigned char their_session_pk[32], struct curvecpr_server_glib_session **sgs_stored);
int curvecpr_server_messager_glib_dealloc_session (struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs);
unsigned char curvecpr_server_messager_glib_session_is_finished (struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs);
int curvecpr_server_messager_glib_finish_session (struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs);
int curvecpr_server_messager_glib_process_session_sendq (struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs);
long long curvecpr_server_messager_glib_next_session_timeout (struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs);

#endif
