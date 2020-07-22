/*
 * Copyright (c) 2019 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

/*
 * @file NLCFG ipv6 handler
 */

#include "nlcfg_hlos.h"
#include <nss_nlbase.h>

#include "nlcfg_param.h"
#include "nlcfg_ipv6.h"

static int nlcfg_ipv6_flow_add(struct nlcfg_param *param, struct nlcfg_param_in *match);
static int nlcfg_ipv6_flow_del(struct nlcfg_param *param, struct nlcfg_param_in *match);
static void nlcfg_ipv6_resp(void *user_ctx, struct nss_nlipv6_rule *rule, void *resp_ctx) __attribute__((unused));

/*
 * flow add parameters
 */
static struct nlcfg_param flow_add_params[NLCFG_IPV6_FLOW_ADD_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_IPV6_FLOW_ADD_SEL_SIP, "sel_sip="),
	NLCFG_PARAM_INIT(NLCFG_IPV6_FLOW_ADD_SEL_DIP, "sel_dip="),
	NLCFG_PARAM_INIT(NLCFG_IPV6_FLOW_ADD_SEL_PROTO, "sel_proto="),
	NLCFG_PARAM_INIT(NLCFG_IPV6_FLOW_ADD_SEL_SPORT, "sel_sport="),
	NLCFG_PARAM_INIT(NLCFG_IPV6_FLOW_ADD_SEL_DPORT, "sel_dport="),
	NLCFG_PARAM_INIT(NLCFG_IPV6_FLOW_ADD_IFNAME_SRC, "ifname_in="),
	NLCFG_PARAM_INIT(NLCFG_IPV6_FLOW_ADD_IFNAME_DST, "ifname_out="),
        NLCFG_PARAM_INIT(NLCFG_IPV6_FLOW_ADD_IFTYPE_SRC, "iftype_in="),
	NLCFG_PARAM_INIT(NLCFG_IPV6_FLOW_ADD_IFTYPE_DST, "iftype_out="),
	NLCFG_PARAM_INIT(NLCFG_IPV6_FLOW_ADD_IS_ROUTED, "is_routed="),
};

/*
 * flow del parameters
 */
static struct nlcfg_param flow_del_params[NLCFG_IPV6_FLOW_DEL_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_IPV6_FLOW_DEL_SEL_SIP, "sel_sip="),
	NLCFG_PARAM_INIT(NLCFG_IPV6_FLOW_DEL_SEL_DIP, "sel_dip="),
	NLCFG_PARAM_INIT(NLCFG_IPV6_FLOW_DEL_SEL_PROTO, "sel_proto="),
	NLCFG_PARAM_INIT(NLCFG_IPV6_FLOW_DEL_SEL_SPORT, "sel_sport="),
	NLCFG_PARAM_INIT(NLCFG_IPV6_FLOW_DEL_SEL_DPORT, "sel_dport="),
};

/*
 * NOTE: whenever this table is updated, the 'enum nlcfg_ipv6_cmd' should also get updated
 */
struct nlcfg_param nlcfg_ipv6_params[NLCFG_IPV6_CMD_MAX] = {
	NLCFG_PARAMLIST_INIT("cmd=flow_add", flow_add_params, nlcfg_ipv6_flow_add),
	NLCFG_PARAMLIST_INIT("cmd=flow_del", flow_del_params, nlcfg_ipv6_flow_del),
};

static struct nss_nlipv6_ctx nss_ctx;

/*
 * nlcfg_param_ipaddr_ipv6_ntohl()
 * 	Convert the ipv6 address to host order
 */
void nlcfg_param_ipaddr_ipv6_ntohl(uint32_t *addr)
{
	uint32_t temp[4];

	memcpy(temp, addr, sizeof(temp));

	addr[0] = ntohl(temp[3]);
	addr[1] = ntohl(temp[2]);
	addr[2] = ntohl(temp[1]);
	addr[3] = ntohl(temp[0]);
}

/*
 * nlcfg_ipv6_get_sel()
 * 	get the IPv6 selector
 */
static int nlcfg_ipv6_get_sel(struct nlcfg_param *param, struct nss_ipv6_5tuple *sel)
{
	int error;
	char proto_name[NLCFG_PARAM_PROTO_LEN];

	if (!param || !sel) {
		nlcfg_log_warn("Param or selector is NULL \n");
		return -EINVAL;
	}

	/*
	 * extract source address
	 */
	error = nlcfg_param_get_ipaddr(param->data, sizeof(sel->flow_ip), &sel->flow_ip);
	if (error < 0) {
		goto fail;
	}

	/*
	 * extract destination address
	 */
	param++;
	error = nlcfg_param_get_ipaddr(param->data, sizeof(sel->return_ip), &sel->return_ip);
	if (error < 0) {
		goto fail;
	}

	/*
	 * IP-addess resolved from input string will be n/w byte order. Convert to host byte order.
	 */
	nlcfg_param_ipaddr_ipv6_ntohl(sel->flow_ip);
	nlcfg_param_ipaddr_ipv6_ntohl(sel->return_ip);

	/*
	 * extract protocol
	 */
	param++;
	error = nlcfg_param_get_str(param->data, NLCFG_PARAM_PROTO_LEN, proto_name);
	if (error < 0) {
		goto fail;
	}

	error = nlcfg_param_get_protocol(proto_name, &sel->protocol);
	if (error < 0) {
		goto fail;
	}

	/*
	 * extract source port
	 */
	param++;
	error = nlcfg_param_get_int(param->data, sizeof(sel->flow_ident), &sel->flow_ident);
	if (error < 0) {
		goto fail;
	}

	/*
	 * extract destination port
	 */
	param++;
	error = nlcfg_param_get_int(param->data, sizeof(sel->return_ident), &sel->return_ident);
	if (error < 0) {
		goto fail;
	}

	return 0;

fail:
	nlcfg_log_data_error(param);
	return error;
}

/*
 * nlcfg_ipv6_resp()
 * 	NLCFG log based on response from netlink
 */
static void nlcfg_ipv6_resp(void *user_ctx, struct nss_nlipv6_rule *rule, void *resp_ctx)
{
	if (!rule) {
		return;
	}

	uint8_t cmd = nss_nlcmn_get_cmd(&rule->cm);

	switch (cmd) {
	case NSS_IPV6_TX_CREATE_RULE_MSG:
		nlcfg_log_info("ack received for Ipv6 Tx create rule\n");
		break;

	case NSS_IPV6_TX_DESTROY_RULE_MSG:
		nlcfg_log_info("ack received for Ipv6 Tx destroy rule\n");
		break;

	case NSS_IPV6_RX_CONN_STATS_SYNC_MSG:
		nlcfg_log_info("ack received for Ipv6 stats sync rule\n");
		break;

	default:
		nlcfg_log_error("unsupported message cmd type(%d)\n", cmd);
	}
}

/*
 * nlcfg_ipv6_flow_add()
 * 	handle IPv6 flow add
 */
int nlcfg_ipv6_flow_add(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_ipv6_rule_create_msg *rule_create;
	struct nss_nlipv6_rule nl_msg = {{0}};
	int is_routed = false;
	int error;

	if (!param || !match) {
		nlcfg_log_warn("Param or match table is NULL \n");
		return -EINVAL;
	}

	/*
	 * open the NSS IPv6 NL socket
	 */
	error = nss_nlipv6_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_warn("Failed to open IPv6 socket; error(%d)\n", error);
		return error;
	}

	/*
	 * iterate through the param table to identify the matched arguments and
	 * populate the argument list
	 */
	error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto done;
	}

	nss_nlipv6_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NSS_IPV6_TX_CREATE_RULE_MSG);

	rule_create = &nl_msg.nim.msg.rule_create;
	nss_nlipv6_init_conn_rule(rule_create);

	/*
	 * extract selectors
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_IPV6_FLOW_ADD_SEL_SIP];
	error = nlcfg_ipv6_get_sel(sub_params, &rule_create->tuple);
	if (error) {
		goto done;
	}

	/*
	 * extract the source interface name
	 */
	sub_params = &param->sub_params[NLCFG_IPV6_FLOW_ADD_IFNAME_SRC];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.flow_ifname), nl_msg.flow_ifname);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * extract the destination interface name
	 */
	sub_params = &param->sub_params[NLCFG_IPV6_FLOW_ADD_IFNAME_DST];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.return_ifname), nl_msg.return_ifname);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * extarct the flow type
	 */
	sub_params = &param->sub_params[NLCFG_IPV6_FLOW_ADD_IS_ROUTED];
	error = nlcfg_param_get_int(sub_params->data, sizeof(uint32_t), &is_routed);
	if (error) {
		nlcfg_log_arg_error(sub_params);
		goto done;
	}

	if (is_routed) {
		nss_nlipv6_init_route_flow_rule(rule_create);
	} else {
		nss_nlipv6_init_bridge_flow_rule(rule_create);
	}

	/*
	 * extract the source interface type
	 */
	sub_params = &param->sub_params[NLCFG_IPV6_FLOW_ADD_IFTYPE_SRC];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.flow_iftype), &nl_msg.flow_iftype);
	if (error) {
		nlcfg_log_arg_error(sub_params);
		goto done;
	}

	/*
	 * extract the destination interface type
	 */
	sub_params = &param->sub_params[NLCFG_IPV6_FLOW_ADD_IFTYPE_DST];
	nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.return_iftype), &nl_msg.return_iftype);
	if (error) {
		nlcfg_log_arg_error(sub_params);
		goto done;
	}

	/*
	 * send message
	 */
	error = nss_nlipv6_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_warn("Unable to send message\n");
		goto done;
	}

	nlcfg_log_info("flow add message sent\n");
done:
	/*
	 * close the socket
	 */
	nss_nlipv6_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_ipv6_flow_del()
 * 	handle IPv6 flow delete
 */
int nlcfg_ipv6_flow_del(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlipv6_rule nl_msg = {{0}};
	int error;

	if (!param || !match) {
		nlcfg_log_warn("Param or match table is NULL \n");
		return -EINVAL;
	}

	/*
	 * open the NSS IPv6 NL socket
	 */
	error = nss_nlipv6_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_warn("Failed to open IPv6 socket; error(%d)\n", error);
		return error;
	}

	/*
	 * iterate through the param table to identify the matched arguments and
	 * populate the argument list
	 */
	error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto done;
	}

	nss_nlipv6_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NSS_IPV6_TX_DESTROY_RULE_MSG);

	/*
	 * extract selectors
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_IPV6_FLOW_DEL_SEL_SIP];
	error = nlcfg_ipv6_get_sel(sub_params, &nl_msg.nim.msg.rule_destroy.tuple);
	if (error) {
		goto done;
	}

	/*
	 * send message
	 */
	error = nss_nlipv6_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_warn("Unable to send message\n");
		goto done;
	}

	nlcfg_log_info("flow delete message sent\n");
done:
	/*
	 * close the socket
	 */
	nss_nlipv6_sock_close(&nss_ctx);
	return error;
}

