/*
 * Copyright (c) 2019-2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef __NSS_NLDTLS_API_H__
#define __NSS_NLDTLS_API_H__

/*
 * @addtogroup libnss_nl
 * @{
 */

/*
 * @file nss_nldtls_api.h
 *	This file declares the NSS NL dtls API(s) for userspace. These
 *	API(s) are wrapper functions for dtls family specific operation.
 */

/*
 * @brief response callback function
 *
 * @param user_ctx[IN] user context, provided at socket open
 * @param rule[IN] dtls rule associated with the response
 * @param resp_ctx[IN] data that the user wants per callback
 */
typedef void (*nss_nldtls_resp_t)(void *user_ctx, struct nss_nldtls_rule *rule, void *resp_ctx);

/*
 * @brief event callback function
 *
 * @param user_ctx[IN] user context, provided at socket open
 * @param rule[IN] dtls rule associated with the event
 */
typedef void (*nss_nldtls_event_t)(void *user_ctx, struct nss_nldtls_rule *rule);

/*
 * @brief NSS NL dtls response
 */
struct nss_nldtls_resp {
	void *data;		/**< response context */
	nss_nldtls_resp_t cb;	/**< response callback */
};

/*
 * @brief NSS dtls context
 */
struct nss_nldtls_ctx {
	struct nss_nlsock_ctx sock;	/**< NSS socket context */
	nss_nldtls_event_t event;	/**< NSS event callback function */
};

/*
 * @brief Open NSS dtls NL socket
 *
 * @param ctx[IN] NSS NL socket context, allocated by the caller
 * @param user_ctx[IN] user context stored per socket
 * @param event_cb[IN] event callback handler
 *
 * @return status of the open call
 */
int nss_nldtls_sock_open(struct nss_nldtls_ctx *ctx, void *user_ctx, nss_nldtls_event_t event_cb);

/*
 * @brief Close NSS dtls NL socket
 *
 * @param ctx[IN] NSS NL context
 */
void nss_nldtls_sock_close(struct nss_nldtls_ctx *ctx);

/*
 * @brief send an dtls rule asynchronously to the NSS NETLINK
 *
 * @param ctx[IN] NSS dtls NL context
 * @param rule[IN] dtls rule to use
 *
 * @return status of send, where '0' is success and -ve means failure
 */
int nss_nldtls_sock_send(struct nss_nldtls_ctx *ctx, struct nss_nldtls_rule *rule);

/*
 * @brief initialize the create rule message
 *
 * @param ctx[IN] NSS dtls NL context
 * @param rule[IN] dtls rule
 * @param data[IN] data received from sender
 * @param cb[IN] response callback handler
 * @param type[IN] type of command
 */
void nss_nldtls_init_rule(struct nss_nldtls_ctx *ctx, struct nss_nldtls_rule *rule, void *data, nss_nldtls_resp_t cb,
											enum nss_nldtls_cmd_type type);

/**}@*/
#endif /* !__NSS_NLDTLS_API_H__*/
