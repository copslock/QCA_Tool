/*
 * Copyright (c) 2019 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef __NSS_NLGRE_REDIR_API_H__
#define __NSS_NLGRE_REDIR_API_H__

/*
 * @addtogroup libnss_nl
 * @{
 */

/*
 * @file nss_nlgre_redir_api.h
 * 	This file declares the NSS NL gre_redir API(s) for userspace. These
 * 	API(s) are wrapper functions for gre_redir family specific operation.
 */

/*
 * @brief response callback function
 *
 * @param user_ctx[IN] user context, provided at socket open
 * @param rule[IN] gre_redir rule associated with the response
 * @param resp_ctx[IN] data that the user wants per callback
 */
typedef void (*nss_nlgre_redir_resp_t)(void *user_ctx, struct nss_nlgre_redir_rule *rule, void *resp_ctx);

/*
 * @brief event callback function
 *
 * @param user_ctx[IN] user context, provided at socket open
 * @param rule[IN] gre_redir rule associated with the event
 */
typedef void (*nss_nlgre_redir_event_t)(void *user_ctx, struct nss_nlgre_redir_rule *rule);

/*
 * @brief NSS NL gre_redir response
 */
struct nss_nlgre_redir_resp {
	void *data;			/**< response context */
	nss_nlgre_redir_resp_t cb;	/**< response callback */
};

/*
 * @brief NSS gre_redir context
 */
struct nss_nlgre_redir_ctx {
	struct nss_nlsock_ctx sock;	/**< NSS socket context */
	nss_nlgre_redir_event_t event;	/**< NSS event callback function */
};

/*
 * @brief Open NSS gre_redir NL socket
 *
 * @param ctx[IN] NSS NL socket context, allocated by the caller
 * @param user_ctx[IN] user context stored per socket
 * @param event_cb[IN] event callback handler
 *
 * @return status of the open call
 */
int nss_nlgre_redir_sock_open(struct nss_nlgre_redir_ctx *ctx, void *user_ctx, nss_nlgre_redir_event_t event_cb);

/*
 * @brief Close NSS gre_redir NL socket
 *
 * @param ctx[IN] NSS NL context
 */
void nss_nlgre_redir_sock_close(struct nss_nlgre_redir_ctx *ctx);

/*
 * @brief send an gre_redir rule asynchronously to the NSS NETLINK
 *
 * @param ctx[IN] NSS gre_redir NL context
 * @param rule[IN] gre_redir rule to use
 *
 * @return status of send, where '0' is success and -ve means failure
 */
int nss_nlgre_redir_sock_send(struct nss_nlgre_redir_ctx *ctx, struct nss_nlgre_redir_rule *rule);

/*
 * @brief initialize the create rule message
 *
 * @param ctx[IN] NSS gre_redir NL context
 * @param rule[IN] gre_redir rule
 * @param data[IN] data received from sender
 * @param cb[IN] response callback handler
 * @param type[IN] type of command
 */
void nss_nlgre_redir_init_rule(struct nss_nlgre_redir_ctx *ctx, struct nss_nlgre_redir_rule *rule, void *data, nss_nlgre_redir_resp_t cb,
											enum nss_nlgre_redir_cmd_type type);

/**}@*/
#endif /* !__NSS_NLGRE_REDIR_API_H__*/
