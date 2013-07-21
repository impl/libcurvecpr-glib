#include "config.h"

#include <curvecpr_glib/server_glib.h>

#include <curvecpr/bytes.h>
#include <curvecpr/server.h>

#include <errno.h>

#include <glib.h>

static int _put_session (struct curvecpr_server *server, const struct curvecpr_session *s, void *priv, struct curvecpr_session **s_stored)
{
    struct curvecpr_server_glib *sg = server->cf.priv;

    struct curvecpr_server_glib_session *sgs;

    sgs = g_slice_new(struct curvecpr_server_glib_session);
    curvecpr_bytes_copy(&sgs->session, s, sizeof(struct curvecpr_session));
    g_datalist_init(&sgs->privs);

    curvecpr_session_set_priv(&sgs->session, sgs);

    if (sg->cf.ops.connected) {
        if (sg->cf.ops.connected(sg, sgs, priv)) {
            g_slice_free(struct curvecpr_server_glib_session, sgs);
            return 1;
        }
    }

    g_hash_table_replace(sg->sessions, sgs->session.their_session_pk, sgs);

    if (s_stored)
        *s_stored = &sgs->session;

    return 0;
}

static int _get_session (struct curvecpr_server *server, const unsigned char their_session_pk[32], struct curvecpr_session **s_stored)
{
    struct curvecpr_server_glib *sg = server->cf.priv;

    struct curvecpr_server_glib_session *sgs;
    if (curvecpr_server_glib_get_session(sg, their_session_pk, &sgs))
        return 1;

    *s_stored = &sgs->session;

    return 0;
}

static int _send (struct curvecpr_server *server, struct curvecpr_session *s, void *priv, const unsigned char *buf, size_t num)
{
    struct curvecpr_server_glib *sg = server->cf.priv;

    /* NB: During connection establishment, s->priv will be null! */
    if (s->priv) {
        struct curvecpr_server_glib_session *sgs = s->priv;

        return sg->cf.ops.send(sg, sgs, priv, buf, num);
    } else {
        /* We want clients to be able to take advantage of the data structure
           if they like, however. */
        int ret;

        struct curvecpr_server_glib_session sgs = { .privs = NULL };
        curvecpr_bytes_copy(&sgs.session, s, sizeof(struct curvecpr_session));
        g_datalist_init(&sgs.privs);

        curvecpr_session_set_priv(s, &sgs);

        ret = sg->cf.ops.send(sg, &sgs, priv, buf, num);

        curvecpr_session_set_priv(s, NULL);

        g_datalist_clear(&sgs.privs);

        return ret;
    }
}

static int _recv (struct curvecpr_server *server, struct curvecpr_session *s, void *priv, const unsigned char *buf, size_t num)
{
    struct curvecpr_server_glib *sg = server->cf.priv;

    struct curvecpr_server_glib_session *sgs = s->priv;

    return sg->cf.ops.recv(sg, sgs, priv, buf, num);
}

static int _next_nonce (struct curvecpr_server *server, unsigned char *destination, size_t num)
{
    struct curvecpr_server_glib *sg = server->cf.priv;

    return sg->cf.ops.next_nonce(sg, destination, num);
}

static guint _ght_key_hash_func (gconstpointer key)
{
    const unsigned char *key_bytes = key;

    int i;
    guint r = 5381;

    for (i = 0; i < 32; ++i)
        r = r * 33 + key_bytes[i];

    return r;
}

static gboolean _ght_key_equal_func (gconstpointer a, gconstpointer b)
{
    const unsigned char *a_bytes = a;
    const unsigned char *b_bytes = b;

    return curvecpr_bytes_equal(a_bytes, b_bytes, 32);
}

static void _ght_value_destroy_func (gpointer data)
{
    struct curvecpr_server_glib_session *sgs = data;

    g_datalist_clear(&sgs->privs);
    g_slice_free(struct curvecpr_server_glib_session, sgs);
}

void curvecpr_server_glib_new (struct curvecpr_server_glib *sg, struct curvecpr_server_glib_cf *cf)
{
    struct curvecpr_server_cf server_cf = {
        .ops = {
            .put_session = _put_session,
            .get_session = _get_session,

            .send = _send,
            .recv = _recv,

            .next_nonce = _next_nonce
        },
        .priv = sg
    };

    curvecpr_bytes_zero(sg, sizeof(struct curvecpr_server_glib));

    if (cf)
        curvecpr_bytes_copy(&sg->cf, cf, sizeof(struct curvecpr_server_glib_cf));

    /* Server configuration. */
    curvecpr_bytes_copy(server_cf.my_extension, sg->cf.my_extension, 16);

    curvecpr_bytes_copy(server_cf.my_global_pk, sg->cf.my_global_pk, 32);
    curvecpr_bytes_copy(server_cf.my_global_sk, sg->cf.my_global_sk, 32);

    /* Initialize server. */
    curvecpr_server_new(&sg->server, &server_cf);

    /* Create hash table for storing sessions. */
    sg->sessions = g_hash_table_new_full(_ght_key_hash_func, _ght_key_equal_func, NULL, _ght_value_destroy_func);
}

void curvecpr_server_glib_dealloc (struct curvecpr_server_glib *sg)
{
    g_hash_table_destroy(sg->sessions);
}

void curvecpr_server_glib_refresh_temporal_keys (struct curvecpr_server_glib *sg)
{
    curvecpr_server_refresh_temporal_keys(&sg->server);
}

int curvecpr_server_glib_send_by_pk (struct curvecpr_server_glib *sg, const unsigned char their_session_pk[32], void *priv, const unsigned char *buf, size_t num)
{
    struct curvecpr_server_glib_session *sgs;

    if (curvecpr_server_glib_get_session(sg, their_session_pk, &sgs))
        return -EINVAL;

    return curvecpr_server_glib_send(sg, sgs, priv, buf, num);
}

int curvecpr_server_glib_send (struct curvecpr_server_glib *sg, struct curvecpr_server_glib_session *sgs, void *priv, const unsigned char *buf, size_t num)
{
    return curvecpr_server_send(&sg->server, &sgs->session, priv, buf, num);
}

int curvecpr_server_glib_recv (struct curvecpr_server_glib *sg, void *priv, const unsigned char *buf, size_t num, struct curvecpr_server_glib_session **sgs_stored)
{
    struct curvecpr_session *s;
    int result = curvecpr_server_recv(&sg->server, priv, buf, num, &s);

    if (result == 0 && sgs_stored)
        *sgs_stored = s->priv;

    return result;
}

int curvecpr_server_glib_get_session (struct curvecpr_server_glib *sg, const unsigned char their_session_pk[32], struct curvecpr_server_glib_session **sgs_stored)
{
    struct curvecpr_server_glib_session *sgs = g_hash_table_lookup(sg->sessions, their_session_pk);
    if (!sgs)
        return -EINVAL;

    *sgs_stored = sgs;

    return 0;
}

int curvecpr_server_glib_dealloc_session (struct curvecpr_server_glib *sg, struct curvecpr_server_glib_session *sgs)
{
    if (sg->cf.ops.disconnected)
        sg->cf.ops.disconnected(sg, sgs);

    return !g_hash_table_remove(sg->sessions, sgs->session.their_session_pk);
}
