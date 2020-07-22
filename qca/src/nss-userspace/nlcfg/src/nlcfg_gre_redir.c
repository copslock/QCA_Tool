/*
 * Copyright (c) 2019 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

/*
 * @file NLCFG gre_redir handler
 */
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <nss_def.h>
#include <nss_nlbase.h>
#include <nss_nl_if.h>
#include "nlcfg_hlos.h"
#include "nlcfg_param.h"
#include "nss_nlcmn_if.h"
#include "nlcfg_gre_redir.h"
#include "nss_nlgre_redir_if.h"

/*
 * Function prototypes
 */
static int nlcfg_gre_redir_create_tun(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_gre_redir_destroy_tun(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_gre_redir_map_vap(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_gre_redir_unmap_vap(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_gre_redir_set_next_hop(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_gre_redir_add_hash(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_gre_redir_del_hash(struct nlcfg_param *, struct nlcfg_param_in *);

/*
 * Create tunnel parameters
 */
struct nlcfg_param create_tun_params[NLCFG_GRE_REDIR_CREATE_TUN_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_CREATE_TUN_PARAM_IPTYPE, "iptype="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_CREATE_TUN_PARAM_SIP, "sip="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_CREATE_TUN_PARAM_DIP, "dip="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_CREATE_TUN_PARAM_SSIP, "ssip="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_CREATE_TUN_PARAM_SDIP, "sdip="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_CREATE_TUN_PARAM_LAG_ENABLE, "lag_enable="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_CREATE_TUN_PARAM_HASHMODE, "hash_mode="),
};

/*
 * Delete tunnel parameters
 */
struct nlcfg_param destroy_tun_params[NLCFG_GRE_REDIR_DESTROY_TUN_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_DESTROY_TUN_PARAM_NETDEV, "netdev="),
};

/*
 * Map parameters
 */
struct nlcfg_param map_params[NLCFG_GRE_REDIR_MAP_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_MAP_PARAM_VAP_NSS_IF, "vap_nss_if="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_MAP_PARAM_RID, "rid="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_MAP_PARAM_VID, "vid="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_MAP_PARAM_TUN_TYPE, "tun_type="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_MAP_PARAM_SA_PAT, "sa_pat="),
};

/*
 * Unmap parameters
 */
struct nlcfg_param unmap_params[NLCFG_GRE_REDIR_UNMAP_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_UNMAP_PARAM_VAP_NSS_IF, "vap_nss_if="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_UNMAP_PARAM_RID, "rid="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_UNMAP_PARAM_VID, "vid="),
};

/*
 * Set_next hop parameters
 */
struct nlcfg_param set_next_params[NLCFG_GRE_REDIR_SET_NEXT_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_SET_NEXT_PARAM_DEV_NAME, "dev_name="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_SET_NEXT_PARAM_NEXT_DEV_NAME, "next_dev_name="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_SET_NEXT_PARAM_MODE, "mode="),
};

/*
 * Add hash parameters
 */
struct nlcfg_param add_hash_params[NLCFG_GRE_REDIR_ADD_HASH_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_ADD_HASH_PARAM_SMAC, "smac="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_ADD_HASH_PARAM_DMAC, "dmac="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_ADD_HASH_PARAM_SLAVE, "slave="),
};

/*
 * Delete hash parameters
 */
struct nlcfg_param del_hash_params[NLCFG_GRE_REDIR_DEL_HASH_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_DEL_HASH_PARAM_SMAC, "smac="),
	NLCFG_PARAM_INIT(NLCFG_GRE_REDIR_DEL_HASH_PARAM_DMAC, "dmac="),
};

/*
 * Gre-redir parameters
 */
struct nlcfg_param nlcfg_gre_redir_params[NLCFG_GRE_REDIR_CMD_TYPE_MAX] = {
	NLCFG_PARAMLIST_INIT("cmd=create", create_tun_params, nlcfg_gre_redir_create_tun),
	NLCFG_PARAMLIST_INIT("cmd=destroy", destroy_tun_params, nlcfg_gre_redir_destroy_tun),
	NLCFG_PARAMLIST_INIT("cmd=map", map_params, nlcfg_gre_redir_map_vap),
	NLCFG_PARAMLIST_INIT("cmd=unmap", unmap_params, nlcfg_gre_redir_unmap_vap),
	NLCFG_PARAMLIST_INIT("cmd=set_next", set_next_params, nlcfg_gre_redir_set_next_hop),
	NLCFG_PARAMLIST_INIT("cmd=add_hash", add_hash_params, nlcfg_gre_redir_add_hash),
	NLCFG_PARAMLIST_INIT("cmd=del_hash", del_hash_params, nlcfg_gre_redir_del_hash),
};

static struct nss_nlgre_redir_ctx nss_ctx;

/*
 * nlcfg_gre_redir_verify_mac()
 * 	Used to verify the mac address
 */
static bool nlcfg_gre_redir_verify_mac(char *str_mac, uint8_t mac[])
{
	int ret;
	if (!mac || !str_mac) {
		nlcfg_log_error("verfiy_mac: NULL value passed\n");
		return false;
	}

	ret = sscanf(str_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2],
			&mac[3], &mac[4], &mac[5]);
	if (ret != 6)
		return false;

	return true;
}

/*
 * nlcfg_gre_redir_get_hash_mode()
 * 	Assigns the hash_mode based on the parameters received
 */
static int nlcfg_gre_redir_get_hash_mode(char *hash_mode, uint8_t *actual_hash_mode)
{
	if(!hash_mode) {
		nlcfg_log_error("get_hash_mode: NULL value passed\n");
		return -EINVAL;
	}

	if (!strncmp(hash_mode, NLCFG_GRE_REDIR_SRC_AND_DEST_MAC_MODE, strlen(NLCFG_GRE_REDIR_SRC_AND_DEST_MAC_MODE))) {
		*actual_hash_mode = NLCFG_GRE_REDIR_HASH_MODE_TYPE_SRC_AND_DEST;
		return 0;
	}

	if (!strncmp(hash_mode, NLCFG_GRE_REDIR_SRC_MAC_MODE, strlen(NLCFG_GRE_REDIR_SRC_MAC_MODE))) {
		*actual_hash_mode = NLCFG_GRE_REDIR_HASH_MODE_TYPE_SRC;
		return 0;
	}

	if (!strncmp(hash_mode, NLCFG_GRE_REDIR_DEST_MAC_MODE, strlen(NLCFG_GRE_REDIR_DEST_MAC_MODE))) {
		*actual_hash_mode = NLCFG_GRE_REDIR_HASH_MODE_TYPE_DEST;
		return 0;
	}

	return -EINVAL;
}

/*
 * nlcfg_gre_redir_create_tunnel()
 * 	Handles GRE_REDIR tunnel creation
 */
static int nlcfg_gre_redir_create_tun(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlgre_redir_rule nl_msg = {{0}};
	uint32_t size;
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

	/*
	 * Open the NSS GRE_REDIR NL socket
	 */
	error = nss_nlgre_redir_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 * Initialize the rule
	 */
	nss_nlgre_redir_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NLCFG_GRE_REDIR_CMD_TYPE_CREATE_TUN);

	/*
	 * Iterate through the args to extract the parameters
	 */
        error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto fail;
	}

	/*
	 * Extract the type of IP address used
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_GRE_REDIR_CREATE_TUN_PARAM_IPTYPE];
	error = nlcfg_param_get_int(sub_params->data, sizeof(uint32_t), &nl_msg.msg.create.iptype);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	size = (nl_msg.msg.create.iptype == NLCFG_GRE_REDIR_IPV4 ? sizeof(struct in_addr) : sizeof(struct in6_addr));

	/*
	 * Extract the source IP address
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_CREATE_TUN_PARAM_SIP];
	error = nlcfg_param_get_ipaddr_ntoh(sub_params->data, size, nl_msg.msg.create.sip);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the destination IP address
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_CREATE_TUN_PARAM_DIP];
	error = nlcfg_param_get_ipaddr_ntoh(sub_params->data, size, nl_msg.msg.create.dip);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the lag_enable
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_CREATE_TUN_PARAM_LAG_ENABLE];
	error = nlcfg_param_get_bool(sub_params->data, &nl_msg.msg.create.lag_enable);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Process only when operating in lag mode
	 */
	if (!nl_msg.msg.create.lag_enable) {
		goto process;
	}

	/*
	 * Extract the second tunnel source IP address
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_CREATE_TUN_PARAM_SSIP];
	error = nlcfg_param_get_ipaddr_ntoh(sub_params->data, size, nl_msg.msg.create.ssip);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the second tunnel destination IP address
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_CREATE_TUN_PARAM_SDIP];
	error = nlcfg_param_get_ipaddr_ntoh(sub_params->data, size, nl_msg.msg.create.sdip);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the hash_mode
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_CREATE_TUN_PARAM_HASHMODE];
	error = nlcfg_gre_redir_get_hash_mode(sub_params->data, &nl_msg.msg.create.hash_mode);
	if (!sub_params || error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

process:
	/*
	 * Send the gre_redir msg to kernel using netlink socket
	 */
	error = nss_nlgre_redir_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to create tunnel error:%d\n", error);
		goto fail;
	}

	nlcfg_log_info("Tunnel create message sent successfully\n");
fail:
	/*
	 * close the socket
	 */
	nss_nlgre_redir_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_gre_redir_destroy_tun()
 *	Handle GRE_REDIR tunnel delete
 */
static int nlcfg_gre_redir_destroy_tun(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlgre_redir_rule nl_msg = {{0}};
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

        /*
	 * open the NSS GRE_REDIR NL socket
	 */
	error = nss_nlgre_redir_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	nss_nlgre_redir_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NLCFG_GRE_REDIR_CMD_TYPE_DESTROY_TUN);

	/*
	 * Iterate through the parameters table to identify the
	 * matched arguments and populate the argument list.
	 */
	error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto fail;
	}

	/*
	 * Extract the netdev parameter
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_GRE_REDIR_DESTROY_TUN_PARAM_NETDEV];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.destroy.netdev), nl_msg.msg.destroy.netdev);
	if (error < 0) {
		nlcfg_log_error("Not a valid device type.");
		goto fail;
	}

	/*
	 * Send tunnel destroy message
	 */
	error = nss_nlgre_redir_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("%s: Failed to destroy tunnel error:%d\n", nl_msg.msg.destroy.netdev, error);
		goto fail;
	}

	nlcfg_log_info("%s: Destroy tunnel message sent successfully\n", nl_msg.msg.destroy.netdev);
fail:
	/*
	 * close the socket
	 */
	nss_nlgre_redir_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_gre_redir_map_vap
 * 	HANDLES gre_redir map
 */
static int nlcfg_gre_redir_map_vap(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlgre_redir_rule nl_msg = {{0}};
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

        /*
	 * open the NSS GRE_REDIR NL socket
	 */
	error = nss_nlgre_redir_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 * Initialize the rule
	 */
	nss_nlgre_redir_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NLCFG_GRE_REDIR_CMD_TYPE_MAP);

	/*
	 * Iterate through the args to extract the parameters
	 */
        error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto fail;
	}

	/*
	 * Extract the NSS interface
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_GRE_REDIR_MAP_PARAM_VAP_NSS_IF];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.map.vap_nss_if), nl_msg.msg.map.vap_nss_if);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the radio ID
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_MAP_PARAM_RID];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.map.rid), &nl_msg.msg.map.rid);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the VAP ID
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_MAP_PARAM_VID];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.map.vid), &nl_msg.msg.map.vid);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the tunnel type
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_MAP_PARAM_TUN_TYPE];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.map.tun_type), nl_msg.msg.map.tun_type);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the Security association parameter
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_MAP_PARAM_SA_PAT];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.map.ipsec_sa_pattern), &nl_msg.msg.map.ipsec_sa_pattern);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 *  Send the message through netlink socket
	 */
	error = nss_nlgre_redir_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("%s: Failed to map:%d\n", nl_msg.msg.map.vap_nss_if, error);
		goto fail;
	}

	nlcfg_log_info("%s: map message sent successfully\n", nl_msg.msg.map.vap_nss_if);
fail:
	/*
	 * Close the socket
	 */
	nss_nlgre_redir_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_gre_redir_unmap
 * 	HANDLES gre_redir map
 */
static int nlcfg_gre_redir_unmap_vap(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlgre_redir_rule nl_msg = {{0}};
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

        /*
	 * open the NSS GRE_REDIR NL socket
	 */
	error = nss_nlgre_redir_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 *  Initialize the rule
	 */
	nss_nlgre_redir_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NLCFG_GRE_REDIR_CMD_TYPE_UNMAP);

	/*
	 *  Iterate through the args to extract the parameters
	 */
        error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto fail;
	}

	/*
	 *  Extract the NSS interface
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_GRE_REDIR_UNMAP_PARAM_VAP_NSS_IF];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.unmap.vap_nss_if), nl_msg.msg.unmap.vap_nss_if);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 *  Extract the radio ID
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_UNMAP_PARAM_RID];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.unmap.rid), &nl_msg.msg.unmap.rid);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 *  Extract the VID
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_UNMAP_PARAM_VID];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.unmap.vid), &nl_msg.msg.unmap.vid);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Send the message through netlink socket
	 */
	error = nss_nlgre_redir_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("%s: Failed to unmap:%d\n", nl_msg.msg.unmap.vap_nss_if, error);
		goto fail;
	}

	nlcfg_log_info("%s: Unmap message sent successfully\n", nl_msg.msg.unmap.vap_nss_if);
fail:
	/*
	 * Close the socket
	 */
	nss_nlgre_redir_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_gre_redir_set_next_hop
 * 	Sets the next hop for vap_nss_if
 */
static int nlcfg_gre_redir_set_next_hop(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlgre_redir_rule nl_msg = {{0}};
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

        /*
	 * open the NSS GRE_REDIR NL socket
	 */
	error = nss_nlgre_redir_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 *  Initialize the rule
	 */
	nss_nlgre_redir_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NLCFG_GRE_REDIR_CMD_TYPE_SET_NEXT_HOP);

	/*
	 * Iterate through the args to extract the parameters
	 */
        error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto fail;
	}

	/*
	 *  Extract the device name
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_GRE_REDIR_SET_NEXT_PARAM_DEV_NAME];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.snext.dev_name), nl_msg.msg.snext.dev_name);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 *  Extract the tunnel device name
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_SET_NEXT_PARAM_NEXT_DEV_NAME];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.snext.next_dev_name), nl_msg.msg.snext.next_dev_name);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 *  Extract the mode
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_SET_NEXT_PARAM_MODE];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.snext.mode), nl_msg.msg.snext.mode);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 *  Send the message through netlink socket
	 */
	error = nss_nlgre_redir_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to set next hop:%d\n", error);
		goto fail;
	}

	nlcfg_log_info("Set_next message sent successfully\n");
fail:
	/*
	 * Close the socket
	 */
	nss_nlgre_redir_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_gre_redir_add_hash
 * 	Handles adding a hash value
 */
static int nlcfg_gre_redir_add_hash(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlgre_redir_rule nl_msg = {{0}};
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

        /*
	 * open the NSS GRE_REDIR NL socket
	 */
	error = nss_nlgre_redir_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 *  Initialize the rule
	 */
	nss_nlgre_redir_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NLCFG_GRE_REDIR_CMD_TYPE_ADD_HASH);

	/*
	 *  Iterate through the args to extract the parameters
	 */
        error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto fail;
	}

	/*
	 * Extract the source mac address
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_GRE_REDIR_ADD_HASH_PARAM_SMAC];
	error = nlcfg_gre_redir_verify_mac(sub_params->data, nl_msg.msg.hash_ops.smac);
	if (!sub_params->data || !error) {
		nlcfg_log_error("Not a valid source mac addr\n");
		error = -EINVAL;
		goto fail;
	}

	/*
	 * Extract the dest mac address
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_ADD_HASH_PARAM_DMAC];
	error = nlcfg_gre_redir_verify_mac(sub_params->data, nl_msg.msg.hash_ops.dmac);
	if (!sub_params->data || !error) {
		nlcfg_log_error("Not a valid destination mac addr\n");
		error = -EINVAL;
		goto fail;
	}

	/*
	 * Extract the slave number
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_ADD_HASH_PARAM_SLAVE];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.hash_ops.slave), &nl_msg.msg.hash_ops.slave);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Send the message through netlink socket
	 */
	error = nss_nlgre_redir_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to add hash:%d\n", error);
		goto fail;
	}

	nlcfg_log_info("Add hash message sent successfully\n");
fail:
	/*
	 * close the socket
	 */
	nss_nlgre_redir_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_gre_redir_del_hash
 * 	Handles gre_redir delete hash
 */
static int nlcfg_gre_redir_del_hash(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlgre_redir_rule nl_msg = {{0}};
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

        /*
	 * open the NSS GRE_REDIR NL socket
	 */
	error = nss_nlgre_redir_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 * Initialize the rule
	 */
	nss_nlgre_redir_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NLCFG_GRE_REDIR_CMD_TYPE_DEL_HASH);

	/*
	 * Iterate through the args to extract the parameters
	 */
        error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto fail;
	}

	/*
	 * Extract the source MAC
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_GRE_REDIR_DEL_HASH_PARAM_SMAC];
	error = nlcfg_gre_redir_verify_mac(sub_params->data, nl_msg.msg.hash_ops.smac);
	if (!sub_params->data || !error) {
		nlcfg_log_error("Not a valid source mac addr\n");
		error = -EINVAL;
		goto fail;
	}

	/*
	 * Extract the destination MAC
	 */
	sub_params = &param->sub_params[NLCFG_GRE_REDIR_DEL_HASH_PARAM_DMAC];
	error = nlcfg_gre_redir_verify_mac(sub_params->data, nl_msg.msg.hash_ops.dmac);
	if (!sub_params->data || !error) {
		nlcfg_log_error("Not a valid destination mac addr\n");
		error = -EINVAL;
		goto fail;
	}

	/*
	 * Send the message through netlink socket
	 */
	error = nss_nlgre_redir_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to delete hash\n");
		goto fail;
	}

	nlcfg_log_info("Delete hash message sent successfully\n");
fail:
	/*
	 * close the socket
	 */
	nss_nlgre_redir_sock_close(&nss_ctx);
	return error;
}

