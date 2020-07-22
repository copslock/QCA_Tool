/*
 * Copyright (c) 2019-2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include <nss_nlbase.h>
#include <nss_nlsock_api.h>
#include <nss_nldtls_api.h>

/*
 * nss_nldtls_sock_cb()
 *	Callback func for dtls netlink socket
 */
int nss_nldtls_sock_cb(struct nl_msg *msg, void *arg)
{
	pid_t pid = getpid();

	struct nss_nldtls_rule *rule = nss_nlsock_get_data(msg);

	if (!rule) {
		nss_nlsock_log_error("%d:failed to get NSS NL dtls header\n", pid);
		return NL_SKIP;
	}

	uint8_t cmd = nss_nlcmn_get_cmd(&rule->cm);

	switch (cmd) {
	case NSS_NLDTLS_CMD_TYPE_CREATE_TUN:
	case NSS_NLDTLS_CMD_TYPE_DESTROY_TUN:
	case NSS_NLDTLS_CMD_TYPE_UPDATE_CONFIG:
	case NSS_NLDTLS_CMD_TYPE_TX_PKTS:
		return NL_OK;

	default:
		nss_nlsock_log_error("%d:unsupported message cmd type(%d)\n", pid, cmd);
		return NL_SKIP;
	}
}

/*
 * nss_nldtls_sock_open()
 *	Opens the NSS dtls NL socket for usage
 */
int nss_nldtls_sock_open(struct nss_nldtls_ctx *ctx, void *user_ctx, nss_nldtls_event_t event_cb)
{
	pid_t pid = getpid();
	int error;

	if (!ctx) {
		nss_nlsock_log_error("%d: invalid parameters passed\n", pid);
		return -EINVAL;
	}

	memset(ctx, 0, sizeof(*ctx));

	nss_nlsock_set_family(&ctx->sock, NSS_NLDTLS_FAMILY);
	nss_nlsock_set_user_ctx(&ctx->sock, user_ctx);

	/*
	 * try opening the socket with Linux
	 */
	error = nss_nlsock_open(&ctx->sock, nss_nldtls_sock_cb);
	if (error) {
		nss_nlsock_log_error("%d:unable to open NSS dtls socket, error(%d)\n", pid, error);
		goto fail;
	}

	return 0;
fail:
	memset(ctx, 0, sizeof(*ctx));
	return error;
}

/*
 * nss_nldtls_sock_close()
 *	Close the NSS dtls NL socket
 */
void nss_nldtls_sock_close(struct nss_nldtls_ctx *ctx)
{
	nss_nlsock_close(&ctx->sock);
	memset(ctx, 0, sizeof(struct nss_nldtls_ctx));
}

/*
 * nss_nldtls_sock_send()
 *	Send the dtls message asynchronously through the socket
 */
int nss_nldtls_sock_send(struct nss_nldtls_ctx *ctx, struct nss_nldtls_rule *rule)
{
	pid_t pid = getpid();
	int error = 0;
	if (!rule) {
		nss_nlsock_log_error("%d:invalid NSS dtls rule\n", pid);
		return -EINVAL;
	}

	error = nss_nlsock_send(&ctx->sock, &rule->cm, rule);
	if (error) {
		nss_nlsock_log_error("%d:failed to send NSS dtls rule, error(%d)\n", pid, error);
	}

	return error;
}

/*
 * nss_nldtls_init_rule()
 *	Initialize the dtls rule
 */
void nss_nldtls_init_rule(struct nss_nldtls_ctx *ctx, struct nss_nldtls_rule *rule, void *data, nss_nldtls_resp_t cb,
											enum nss_nldtls_cmd_type type)
{
	int32_t family_id = ctx->sock.family_id;
	struct nss_nldtls_resp *resp;

	nss_nldtls_rule_init(rule, type);

	nss_nlcmn_set_cb_owner(&rule->cm, family_id);

	resp = nss_nlcmn_get_cb_data(&rule->cm, family_id);
	assert(resp);

	resp->data = data;
	resp->cb = cb;
}
