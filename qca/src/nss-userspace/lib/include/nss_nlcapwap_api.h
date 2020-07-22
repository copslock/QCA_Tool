/*
 * Copyright (c) 2019-2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef __NSS_NLCAPWAP_API_H__
#define __NSS_NLCAPWAP_API_H__

/*
 * @addtogroup libnss_nl
 * @{
 */

/*
 * @file nss_nlcapwap_api.h
 *	This file declares the NSS NL capwap API(s) for userspace. These
 *	API(s) are wrapper functions for capwap family specific operation.
 */

/*
 * @brief response callback function
 *
 * @param user_ctx[IN] user context, provided at socket open
 * @param rule[IN] capwap rule associated with the response
 * @param resp_ctx[IN] data that the user wants per callback
 */
typedef void (*nss_nlcapwap_resp_t)(void *user_ctx, struct nss_nlcapwap_rule *rule, void *resp_ctx);

/*
 * @brief event callback function
 *
 * @param user_ctx[IN] user context, provided at socket open
 * @param rule[IN] capwap rule associated with the event
 */
typedef void (*nss_nlcapwap_event_t)(void *user_ctx, struct nss_nlcapwap_rule *rule);

/*
 * @brief NSS NL capwap response
 */
struct nss_nlcapwap_resp {
	void *data;			/**< response context */
	nss_nlcapwap_resp_t cb;	/**< response callback */
};

/*
 * @brief NSS capwap context
 */
struct nss_nlcapwap_ctx {
	struct nss_nlsock_ctx sock;	/**< NSS socket context */
	nss_nlcapwap_event_t event;	/**< NSS event callback function */
};

/*
 * @brief Open NSS capwap NL socket
 *
 * @param ctx[IN] NSS NL socket context, allocated by the caller
 * @param user_ctx[IN] user context stored per socket
 * @param event_cb[IN] event callback handler
 *
 * @return status of the open call
 */
int nss_nlcapwap_sock_open(struct nss_nlcapwap_ctx *ctx, void *user_ctx, nss_nlcapwap_event_t event_cb);

/*
 * @brief Close NSS capwap NL socket
 *
 * @param ctx[IN] NSS NL context
 */
void nss_nlcapwap_sock_close(struct nss_nlcapwap_ctx *ctx);

/*
 * @brief send an capwap rule asynchronously to the NSS NETLINK
 *
 * @param ctx[IN] NSS capwap NL context
 * @param rule[IN] capwap rule to use
 *
 * @return status of send, where '0' is success and -ve means failure
 */
int nss_nlcapwap_sock_send(struct nss_nlcapwap_ctx *ctx, struct nss_nlcapwap_rule *rule);

/*
 * @brief initialize the create rule message
 *
 * @param ctx[IN] NSS capwap NL context
 * @param rule[IN] capwap rule
 * @param data[IN] data received from sender
 * @param cb[IN] response callback handler
 * @param type[IN] type of command
 */
void nss_nlcapwap_init_rule(struct nss_nlcapwap_ctx *ctx, struct nss_nlcapwap_rule *rule, void *data, nss_nlcapwap_resp_t cb,
											enum nss_nlcapwap_cmd_type type);

/**}@*/
#endif /* !__NSS_NLCAPWAP_API_H__*/
