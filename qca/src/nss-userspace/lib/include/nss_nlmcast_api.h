/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef __NSS_NLMCAST_API_H__
#define __NSS_NLMCAST_API_H__

/**
 * @addtogroup libnss_nl
 * @{
 */

/**
 * @file nss_nlmcast_api.h
 *	This file declares the NSS NL mcast API(s) for userspace. These
 *	API(s) are wrapper functions for mcast specific operation.
 */

/**
 * @brief event callback function
 *
 * @param cmd[IN] cmd received in generic Netlink header
 * @param data[IN] data received in Netlink message
 */
typedef void (*nss_nlmcast_event_t)(int cmd, void *data);

/**
 * @brief NSS mcast context
 */
struct nss_nlmcast_ctx {
	struct nss_nlsock_ctx sock;     /**< NSS socket context */
	nss_nlmcast_event_t event;       /**< NSS event callback function */
};

/**
 * @brief listening to NSS NL event data
 *
 * @param ctx[IN] mcast context
 *
 * @return status of the listen
 */
int nss_nlmcast_sock_listen(struct nss_nlmcast_ctx *ctx);

/**
 * @brief subscribe for the multicast group
 *
 * @param ctx[IN] mcast context
 * @param grp_name[IN] NSS NL group name
 *
 * @return status of the subscription
 */
int nss_nlmcast_sock_join_grp(struct nss_nlmcast_ctx *ctx, char *grp_name);

/**
 * @brief unsubscribe for the multicast group
 *
 * @param ctx[IN] mcast context
 * @param grp_name[IN] NSS NL group name
 *
 * @return status of the operation
 */
int nss_nlmcast_sock_leave_grp(struct nss_nlmcast_ctx *ctx, char *grp_name);

/**
 * @brief open a socket for listening to NSS NL event data, when a event arrives
 *	it will be delivered using through the callback function
 *
 * @param ctx[IN] mcast context
 * @param cb[IN] callback function
 * @param family_name[IN] NSS NL family name
 *
 * @return status of the operation
 */
int nss_nlmcast_sock_open(struct nss_nlmcast_ctx *ctx, nss_nlmcast_event_t cb, const char *family_name);

/**
 * @brief close the socket
 *
 * @param ctx[IN] mcast context
 *
 */
void nss_nlmcast_sock_close(struct nss_nlmcast_ctx *ctx);
/**}@*/
#endif /* !__NSS_NLMCAST_API_H__*/
