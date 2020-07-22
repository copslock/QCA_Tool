/*
 * Copyright (c) 2019-2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include <nss_nlbase.h>
#include <nss_nlsock_api.h>
#include <nss_nlcapwap_api.h>

/*
 * nss_nlcapwap_sock_cb()
 *	Callback func for capwap netlink socket
 */
int nss_nlcapwap_sock_cb(struct nl_msg *msg, void *arg)
{
	struct nss_nlcapwap_rule *rule;
	uint8_t cmd;
	pid_t pid;

	if (!msg || !arg) {
		nss_nlsock_log_error("Invalid msg or arg received\n");
		return NL_SKIP;
	}

	rule = nss_nlsock_get_data(msg);
	pid = getpid();
	if (!rule) {
		nss_nlsock_log_error("%d:failed to get NSS NL capwap header\n", pid);
		return NL_SKIP;
	}

	cmd = nss_nlcmn_get_cmd(&rule->cm);
	switch (cmd) {
	case NSS_NLCAPWAP_CMD_TYPE_CREATE_TUN:
	case NSS_NLCAPWAP_CMD_TYPE_DESTROY_TUN:
	case NSS_NLCAPWAP_CMD_TYPE_UPDATE_MTU:
	case NSS_NLCAPWAP_CMD_TYPE_META_HEADER:
	case NSS_NLCAPWAP_CMD_TYPE_TX_PACKETS:
	case NSS_NLCAPWAP_CMD_TYPE_IP_FLOW:
	case NSS_NLCAPWAP_CMD_TYPE_DTLS:
	case NSS_NLCAPWAP_CMD_TYPE_PERF:
		return NL_OK;
	default:
		nss_nlsock_log_error("%d:unsupported message cmd type(%d)\n", pid, cmd);
		return NL_SKIP;
	}
}

/*
 * nss_nlcapwap_sock_open()
 *	Opens the NSS capwap NL socket for usage
 */
int nss_nlcapwap_sock_open(struct nss_nlcapwap_ctx *ctx, void *user_ctx, nss_nlcapwap_event_t event_cb)
{
	pid_t pid = getpid();
	int error;

	if (!ctx) {
		nss_nlsock_log_error("%d: invalid ctx passed\n", pid);
		return -EINVAL;
	}

	memset(ctx, 0, sizeof(*ctx));

	nss_nlsock_set_family(&ctx->sock, NSS_NLCAPWAP_FAMILY);
	nss_nlsock_set_user_ctx(&ctx->sock, user_ctx);

	/*
	 * try opening the socket with Linux
	 */
	error = nss_nlsock_open(&ctx->sock, nss_nlcapwap_sock_cb);
	if (error) {
		nss_nlsock_log_error("%d:unable to open NSS capwap socket, error(%d)\n", pid, error);
		goto fail;
	}

	return 0;
fail:
	memset(ctx, 0, sizeof(*ctx));
	return error;
}

/*
 * nss_nlcapwap_sock_close()
 *	Close the NSS capwap NL socket
 */
void nss_nlcapwap_sock_close(struct nss_nlcapwap_ctx *ctx)
{
	if (!ctx) {
		nss_nlsock_log_error("ctx is NULL\n");
		return;
	}

	nss_nlsock_close(&ctx->sock);
	memset(ctx, 0, sizeof(struct nss_nlcapwap_ctx));
}

/*
 * nss_nlcapwap_sock_send()
 *	Send the capwap message asynchronously through the socket
 */
int nss_nlcapwap_sock_send(struct nss_nlcapwap_ctx *ctx, struct nss_nlcapwap_rule *rule)
{
	pid_t pid = getpid();
	int error = 0;
	if (!rule) {
		nss_nlsock_log_error("%d:invalid NSS capwap rule\n", pid);
		return -EINVAL;
	}

	error = nss_nlsock_send(&ctx->sock, &rule->cm, rule);
	if (error) {
		nss_nlsock_log_error("%d:failed to send NSS capwap rule, error(%d)\n",
				pid, error);
	}

	return error;
}

/*
 * nss_nlcapwap_init_rule()
 *	Initialize the capwap rule
 */
void nss_nlcapwap_init_rule(struct nss_nlcapwap_ctx *ctx, struct nss_nlcapwap_rule *rule,
		void *data, nss_nlcapwap_resp_t cb, enum nss_nlcapwap_cmd_type type)
{
	int32_t family_id = ctx->sock.family_id;
	struct nss_nlcapwap_resp *resp;

	nss_nlcapwap_rule_init(rule, type);

	nss_nlcmn_set_cb_owner(&rule->cm, family_id);

	resp = nss_nlcmn_get_cb_data(&rule->cm, family_id);
	assert(resp);

	resp->data = data;
	resp->cb = cb;
}
