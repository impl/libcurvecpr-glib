#include "config.h"

#include <curvecpr_glib/server_messager_glib.h>

#include <curvecpr_glib/messager_glib.h>
#include <curvecpr_glib/server_glib.h>

#include <curvecpr/block.h>
#include <curvecpr/bytes.h>

#include <errno.h>

#include <glib.h>

static G_DEFINE_QUARK (-server-messager-glib-messager-quark, _messager);
static G_DEFINE_QUARK (-server-messager-glib-server-quark, _server);

static int _messager_glib_send (struct curvecpr_messager_glib *mg, const unsigned char *buf, size_t num)
{
    struct curvecpr_server_glib_session *sgs = mg->cf.priv;

    struct curvecpr_server_glib *sg = g_datalist_id_get_data(&sgs->privs, _server_quark());

    /* We have an unencrypted message packed and ready to be encrypted. */
    return curvecpr_server_glib_send(sg, sgs, NULL, buf, num);
}

static int _messager_glib_recv (struct curvecpr_messager_glib *mg, const unsigned char *buf, size_t num)
{
    struct curvecpr_server_glib_session *sgs = mg->cf.priv;

    struct curvecpr_server_glib *sg = g_datalist_id_get_data(&sgs->privs, _server_quark());
    struct curvecpr_server_messager_glib *smg = sg->cf.priv;

    /* We have a decrypted, extracted message buffer ready to be passed along
       to user code. */
    return smg->cf.ops.recv(smg, sgs, buf, num);
}

static void _messager_glib_finished (struct curvecpr_messager_glib *mg, enum curvecpr_block_eofflag flag)
{
    struct curvecpr_server_glib_session *sgs = mg->cf.priv;

    struct curvecpr_server_glib *sg = g_datalist_id_get_data(&sgs->privs, _server_quark());
    struct curvecpr_server_messager_glib *smg = sg->cf.priv;

    if (smg->cf.ops.finished)
        smg->cf.ops.finished(smg, sgs, flag);
}

static void _gdl_destroy_func (gpointer data)
{
    struct curvecpr_messager_glib *mg = data;

    curvecpr_messager_glib_dealloc(mg);
    g_slice_free(struct curvecpr_messager_glib, mg);
}

static int _server_glib_connected (struct curvecpr_server_glib *sg, struct curvecpr_server_glib_session *sgs, void *priv)
{
    struct curvecpr_server_messager_glib *smg = sg->cf.priv;

    struct curvecpr_messager_glib *mg;
    struct curvecpr_messager_glib_cf mg_cf = {
        .ops = {
            .send = _messager_glib_send,
            .recv = _messager_glib_recv,
            .finished = _messager_glib_finished
        },

        .pending_maximum = smg->cf.pending_maximum,
        .sendmarkq_maximum = smg->cf.sendmarkq_maximum,
        .recvmarkq_maximum = smg->cf.recvmarkq_maximum,

        .priv = sgs
    };

    mg = g_slice_new(struct curvecpr_messager_glib);
    curvecpr_messager_glib_new(mg, &mg_cf, 0);

    g_datalist_id_set_data(&sgs->privs, _server_quark(), sg);
    g_datalist_id_set_data_full(&sgs->privs, _messager_quark(), mg, _gdl_destroy_func);

    if (smg->cf.ops.connected) {
        if (smg->cf.ops.connected(smg, sgs, priv)) {
            g_datalist_id_remove_data(&sgs->privs, _server_quark());
            g_datalist_id_remove_data(&sgs->privs, _messager_quark());

            return 1;
        }
    }

    return 0;
}

static void _server_glib_disconnected (struct curvecpr_server_glib *sg, struct curvecpr_server_glib_session *sgs)
{
    struct curvecpr_server_messager_glib *smg = sg->cf.priv;

    if (smg->cf.ops.disconnected)
        smg->cf.ops.disconnected(smg, sgs);

    g_datalist_id_remove_data(&sgs->privs, _server_quark());
    g_datalist_id_remove_data(&sgs->privs, _messager_quark());
}

static int _server_glib_send (struct curvecpr_server_glib *sg, struct curvecpr_server_glib_session *sgs, void *priv, const unsigned char *buf, size_t num)
{
    struct curvecpr_server_messager_glib *smg = sg->cf.priv;

    /* priv will probably only be set when the connection is being established
       (i.e., for the response to a "hello" packet). */
    if (priv && smg->cf.ops.put_session_priv)
        smg->cf.ops.put_session_priv(smg, sgs, priv);

    /* We have a fully processed message encapsulated in an encrypted packet
       ready to be sent on the wire. */
    return smg->cf.ops.send(smg, sgs, buf, num);
}

static int _server_glib_recv (struct curvecpr_server_glib *sg, struct curvecpr_server_glib_session *sgs, void *priv, const unsigned char *buf, size_t num)
{
    struct curvecpr_server_messager_glib *smg = sg->cf.priv;

    struct curvecpr_messager_glib *mg = g_datalist_id_get_data(&sgs->privs, _messager_quark());

    /* Update our privdata with the latest from the connection itself. */
    if (priv && smg->cf.ops.put_session_priv)
        smg->cf.ops.put_session_priv(smg, sgs, priv);

    /* We read a packet. Now it needs to be sent through the messager. */
    return curvecpr_messager_glib_recv(mg, buf, num);
}

static int _server_glib_next_nonce (struct curvecpr_server_glib *sg, unsigned char *destination, size_t num)
{
    struct curvecpr_server_messager_glib *smg = sg->cf.priv;

    return smg->cf.ops.next_nonce(smg, destination, num);
}

void curvecpr_server_messager_glib_new (struct curvecpr_server_messager_glib *smg, struct curvecpr_server_messager_glib_cf *cf)
{
    struct curvecpr_server_glib_cf sg_cf = {
        .ops = {
            .connected = _server_glib_connected,
            .disconnected = _server_glib_disconnected,

            .send = _server_glib_send,
            .recv = _server_glib_recv,

            .next_nonce = _server_glib_next_nonce
        },
        .priv = smg
    };

    curvecpr_bytes_zero(smg, sizeof(struct curvecpr_server_messager_glib));

    if (cf)
        curvecpr_bytes_copy(&smg->cf, cf, sizeof(struct curvecpr_server_messager_glib_cf));

    /* Server configuration. */
    curvecpr_bytes_copy(sg_cf.my_extension, smg->cf.my_extension, 16);

    curvecpr_bytes_copy(sg_cf.my_global_pk, smg->cf.my_global_pk, 32);
    curvecpr_bytes_copy(sg_cf.my_global_sk, smg->cf.my_global_sk, 32);

    /* Initialize server. */
    curvecpr_server_glib_new(&smg->sg, &sg_cf);
}

void curvecpr_server_messager_glib_dealloc (struct curvecpr_server_messager_glib *smg)
{
    curvecpr_server_glib_dealloc(&smg->sg);
}

void curvecpr_server_messager_glib_refresh_temporal_keys (struct curvecpr_server_messager_glib *smg)
{
    curvecpr_server_glib_refresh_temporal_keys(&smg->sg);
}

int curvecpr_server_messager_glib_send_by_pk (struct curvecpr_server_messager_glib *smg, const unsigned char their_session_pk[32], const unsigned char *buf, size_t num)
{
    struct curvecpr_server_glib_session *sgs;

    if (curvecpr_server_messager_glib_get_session(smg, their_session_pk, &sgs))
        return -EINVAL;

    return curvecpr_server_messager_glib_send(smg, sgs, buf, num);
}

int curvecpr_server_messager_glib_send (struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs, const unsigned char *buf, size_t num)
{
    struct curvecpr_messager_glib *mg = g_datalist_id_get_data(&sgs->privs, _messager_quark());
    if (!mg)
        return -EINVAL;

    return curvecpr_messager_glib_send(mg, buf, num);
}

int curvecpr_server_messager_glib_recv (struct curvecpr_server_messager_glib *smg, void *priv, const unsigned char *buf, size_t num, struct curvecpr_server_glib_session **sgs_stored)
{
    return curvecpr_server_glib_recv(&smg->sg, priv, buf, num, sgs_stored);
}

int curvecpr_server_messager_glib_get_session (struct curvecpr_server_messager_glib *smg, const unsigned char their_session_pk[32], struct curvecpr_server_glib_session **sgs_stored)
{
    return curvecpr_server_glib_get_session(&smg->sg, their_session_pk, sgs_stored);
}

int curvecpr_server_messager_glib_dealloc_session (struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs)
{
    return curvecpr_server_glib_dealloc_session(&smg->sg, sgs);
}

unsigned char curvecpr_server_messager_glib_session_is_finished (struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs)
{
    struct curvecpr_messager_glib *mg = g_datalist_id_get_data(&sgs->privs, _messager_quark());
    if (!mg)
        return -EINVAL;

    return curvecpr_messager_glib_is_finished(mg);
}

int curvecpr_server_messager_glib_finish_session (struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs)
{
    struct curvecpr_messager_glib *mg = g_datalist_id_get_data(&sgs->privs, _messager_quark());
    if (!mg)
        return -EINVAL;

    return curvecpr_messager_glib_finish(mg);
}

int curvecpr_server_messager_glib_process_session_sendq (struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs)
{
    struct curvecpr_messager_glib *mg = g_datalist_id_get_data(&sgs->privs, _messager_quark());
    if (!mg)
        return -EINVAL;

    return curvecpr_messager_glib_process_sendq(mg);
}

long long curvecpr_server_messager_glib_next_session_timeout (struct curvecpr_server_messager_glib *smg, struct curvecpr_server_glib_session *sgs)
{
    struct curvecpr_messager_glib *mg = g_datalist_id_get_data(&sgs->privs, _messager_quark());
    if (!mg)
        return -EINVAL;

    return curvecpr_messager_glib_next_timeout(mg);
}
