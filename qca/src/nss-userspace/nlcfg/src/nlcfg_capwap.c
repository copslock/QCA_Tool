/*
 * Copyright (c) 2019-2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

/*
 * @file NLCFG capwap handler
 */
#include <arpa/inet.h>
#include <nss_def.h>
#include <nss_nlbase.h>
#include <nss_nl_if.h>
#include <stdint.h>
#include "nlcfg_capwap.h"
#include "nlcfg_hlos.h"
#include "nlcfg_param.h"
#include "nss_dtls_cmn.h"
#include "nss_nlcapwap_if.h"
#include "nss_nlcmn_if.h"

/*
 * Function prototypes
 */
static int nlcfg_capwap_create_tun(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_capwap_destroy_tun(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_capwap_update_mtu(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_capwap_tx_packets(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_capwap_meta_header(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_capwap_dtls(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_capwap_perf(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_capwap_ip_flow(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_capwap_tx_keepalive(struct nlcfg_param *, struct nlcfg_param_in *);

/*
 * capwap_create_tun_params
 *	Create tunnel parameters
 */
struct nlcfg_param capwap_create_tun_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_IP_VERSION, "ip_version="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_SIP, "sip="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_DIP, "dip="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_SPORT, "sport="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_DPORT, "dport="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_PATH_MTU, "path_mtu="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_REASM_TIMEOUT, "reassembly_timeout="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_MAX_FRAGMENTS, "max_fragments="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_MAX_BUF_SZ, "max_buffer_size="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_STATS_TIMER, "stats_timer="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_RPS, "rps="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_VLAN_CONFIG, "vlan_config="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_PPPOE_CONFIG, "pppoe_config="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_CSUM_ENABLE, "csum_enable="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_UDP_TYPE, "which_udp="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_GMAC_IFNAME, "gmac_ifname="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_GMAC_IFMAC, "gmac_ifmac="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_INNER_TRUSTSEC_EN, "inner_trustsec_en="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_OUTER_TRUSTSEC_EN, "outer_trustsec_en="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_WIRELESS_QOS_EN, "wireless_qos_en="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_OUTER_SGT_VALUE, "outer_sgt_value="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_CREATE_TUN_PARAM_BSSID, "bssid="),
};

/*
 * capwap_destroy_tun_params
 *	Delete tunnel parameters
 */
struct nlcfg_param capwap_destroy_tun_params[NLCFG_CAPWAP_DESTROY_TUN_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DESTROY_TUN_PARAM_TUN_ID, "tun_id="),
};

/*
 * capwap_update_mtu_params
 *	Update mtu parameters
 */
struct nlcfg_param capwap_update_mtu_params[NLCFG_CAPWAP_UPDATE_MTU_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_UPDATE_MTU_PARAM_TUN_ID, "tun_id="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_UPDATE_MTU_PARAM_PATH_MTU, "path_mtu="),
};

/*
 * capwap_dtls_params
 *	Enable dtls parameters
 */
struct nlcfg_param capwap_dtls_params[NLCFG_CAPWAP_DTLS_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_ENABLE_DTLS, "enable_dtls="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_IP_VERSION, "ip_version="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_SIP, "sip="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_DIP, "dip="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_SPORT, "sport="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_DPORT, "dport="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_TUN_ID, "tun_id="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_FLAGS, "flags="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_ENCAP_ALGO, "encap_algo="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_ENCAP_CIPHER_KEY, "encap_cipher_key="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_ENCAP_CIPHER_KEY_LEN, "encap_cipher_key_len="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_ENCAP_AUTH_KEY, "encap_auth_key="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_ENCAP_AUTH_KEY_LEN, "encap_auth_key_len="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_ENCAP_NONCE, "encap_nonce="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_ENCAP_NONCE_LEN, "encap_nonce_len="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_ENCAP_VERS, "encap_vers="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_ENCAP_EPOCH, "encap_epoch="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_ENCAP_IP_TTL, "encap_ip_ttl="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_DECAP_ALGO, "decap_algo="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_DECAP_CIPHER_KEY, "decap_cipher_key="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_DECAP_CIPHER_KEY_LEN, "decap_cipher_key_len="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_DECAP_AUTH_KEY, "decap_auth_key="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_DECAP_AUTH_KEY_LEN, "decap_auth_key_len="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_DECAP_NONCE, "decap_nonce="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_DECAP_NONCE_LEN, "decap_nonce_len="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_DTLS_PARAM_WINDOW_SZ, "window_size="),
};

/*
 * capwap_performace_params
 *	Enable performance parameters
 */
struct nlcfg_param capwap_perf_params[NLCFG_CAPWAP_PERF_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_PERF_PARAM_PERF_EN, "perf_en="),
};

/*
 * capwap_tx_packets_params
 *	Send traffic parameters
 */
struct nlcfg_param capwap_tx_packets_params[NLCFG_CAPWAP_TX_PACKETS_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_TX_PACKETS_PARAM_PKT_SIZE, "pkt_size="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_TX_PACKETS_PARAM_NUM_OF_PACKETS, "num_of_packets="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_TX_PACKETS_PARAM_TUN_ID, "tun_id="),
};

/*
 * capwap_meta_header_params
 *	Create meta header parameters
 */
struct nlcfg_param capwap_meta_header_params[NLCFG_CAPWAP_META_HEADER_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_META_HEADER_PARAM_VERSION, "version="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_META_HEADER_PARAM_RID, "rid="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_META_HEADER_PARAM_TUN_ID, "tun_id="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_META_HEADER_PARAM_DSCP, "dscp="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_META_HEADER_PARAM_VLAN_PCP, "vlan_pcp="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_META_HEADER_PARAM_PKT_TYPE, "pkt_type="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_META_HEADER_PARAM_NWIRELESS, "nwireless="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_META_HEADER_PARAM_WIRELESS_QOS, "wireless_qos="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_META_HEADER_PARAM_OUTER_SGT, "outer_sgt="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_META_HEADER_PARAM_INNER_SGT, "inner_sgt="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_META_HEADER_PARAM_FLOW_ID, "flow_id="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_META_HEADER_PARAM_VAP_ID, "vap_id="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_META_HEADER_PARAM_WL_INFO, "wl_info="),
};

/*
 * capwap_ip_flow_params
 *	Create an IP flow parameters
 */
struct nlcfg_param capwap_ip_flow_params[NLCFG_CAPWAP_IP_FLOW_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_IP_FLOW_PARAM_MODE, "mode="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_IP_FLOW_PARAM_TUN_ID, "tun_id="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_IP_FLOW_PARAM_IP_VERSION, "ip_version="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_IP_FLOW_PARAM_L4_PROTO, "l4_proto="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_IP_FLOW_PARAM_SPORT, "sport="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_IP_FLOW_PARAM_DPORT, "dport="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_IP_FLOW_PARAM_SIP, "sip="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_IP_FLOW_PARAM_DIP, "dip="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_IP_FLOW_PARAM_FLOW_ID, "flow_id="),
};

/*
 * capwap_tx_keepalive_params
 *	Enable or disable keepalive for a capwap tunnel
 */
struct nlcfg_param capwap_tx_keepalive_params[NLCFG_CAPWAP_TX_KEEPALIVE_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_TX_KEEPALIVE_PARAM_TX_KEEPALIVE, "tx_keepalive="),
	NLCFG_PARAM_INIT(NLCFG_CAPWAP_TX_KEEPALIVE_PARAM_TUN_ID, "tun_id="),
};

/*
 * nlcfg_capwap_params
 *	Capwap parameters
 */
struct nlcfg_param nlcfg_capwap_params[NLCFG_CAPWAP_CMD_TYPE_MAX] = {
	NLCFG_PARAMLIST_INIT("cmd=create", capwap_create_tun_params, nlcfg_capwap_create_tun),
	NLCFG_PARAMLIST_INIT("cmd=destroy", capwap_destroy_tun_params, nlcfg_capwap_destroy_tun),
	NLCFG_PARAMLIST_INIT("cmd=update_mtu", capwap_update_mtu_params, nlcfg_capwap_update_mtu),
	NLCFG_PARAMLIST_INIT("cmd=dtls", capwap_dtls_params, nlcfg_capwap_dtls),
	NLCFG_PARAMLIST_INIT("cmd=performance", capwap_perf_params, nlcfg_capwap_perf),
	NLCFG_PARAMLIST_INIT("cmd=tx_packets", capwap_tx_packets_params, nlcfg_capwap_tx_packets),
	NLCFG_PARAMLIST_INIT("cmd=meta_header", capwap_meta_header_params, nlcfg_capwap_meta_header),
	NLCFG_PARAMLIST_INIT("cmd=ip_flow", capwap_ip_flow_params, nlcfg_capwap_ip_flow),
	NLCFG_PARAMLIST_INIT("cmd=keepalive", capwap_tx_keepalive_params, nlcfg_capwap_tx_keepalive),
};

static struct nss_nlcapwap_ctx nss_ctx;

/*
 * nlcfg_capwap_create_tun()
 *	Handles CAPWAP tunnel creation
 */
static int nlcfg_capwap_create_tun(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlcapwap_rule nl_msg = {{0}};
	uint8_t proto;
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

	/*
	 * Open the NSS CAPWAP NL socket
	 */
	error = nss_nlcapwap_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 * Initialize the rule
	 */
	nss_nlcapwap_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NSS_NLCAPWAP_CMD_TYPE_CREATE_TUN);

	/*
	 * Iterate through the args to extract the parameters
	 */
        error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto done;
	}

	/*
	 * Extract the type of IP address used
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_IP_VERSION];
	error = nlcfg_param_get_int(sub_params->data, sizeof(uint32_t), &nl_msg.msg.create.rule.l3_proto);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	proto = nl_msg.msg.create.rule.l3_proto;

	/*
	 * If ip version is 4
	 */
	if (proto == NLCFG_CAPWAP_IPV4) {
		/*
		 * Extract the source IP address
		 */
		sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_SIP];
		error = nlcfg_param_get_ipaddr_ntoh(sub_params->data, sizeof(struct in_addr),
				&nl_msg.msg.create.rule.encap.src_ip.ip.ipv4);
		if (error < 0) {
			nlcfg_log_data_error(sub_params);
			goto done;
		}

		/*
		 * Extract the destination IP address
		 */
		sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_DIP];
		error = nlcfg_param_get_ipaddr_ntoh(sub_params->data, sizeof(struct in_addr),
				&nl_msg.msg.create.rule.encap.dest_ip.ip.ipv4);
		if (error < 0) {
			nlcfg_log_data_error(sub_params);
			goto done;
		}
	} else {
		/*
		 * Extract the source IP address
		 */
		sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_SIP];
		error = nlcfg_param_get_ipaddr_ntoh(sub_params->data, sizeof(struct in6_addr),
				nl_msg.msg.create.rule.encap.src_ip.ip.ipv6);
		if (error < 0) {
			nlcfg_log_data_error(sub_params);
			goto done;
		}

		/*
		 * Extract the destination IP address
		 */
		sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_DIP];
		error = nlcfg_param_get_ipaddr_ntoh(sub_params->data, sizeof(struct in6_addr),
				nl_msg.msg.create.rule.encap.dest_ip.ip.ipv6);
		if (error < 0) {
			nlcfg_log_data_error(sub_params);
			goto done;
		}
	}

	/*
	 * Extract the source port number
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_SPORT];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.rule.encap.src_port),
			&nl_msg.msg.create.rule.encap.src_port);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the destination port number
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_DPORT];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.rule.encap.dest_port),
			&nl_msg.msg.create.rule.encap.dest_port);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the path mtu
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_PATH_MTU];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.rule.encap.path_mtu),
			&nl_msg.msg.create.rule.encap.path_mtu);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract inner trustsec parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_INNER_TRUSTSEC_EN];
	error = nlcfg_param_get_bool(sub_params->data, &nl_msg.msg.create.inner_trustsec_en);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract outer trustsec parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_OUTER_TRUSTSEC_EN];
	error = nlcfg_param_get_bool(sub_params->data, &nl_msg.msg.create.outer_trustsec_en);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract wireless qos parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_WIRELESS_QOS_EN];
	error = nlcfg_param_get_bool(sub_params->data, &nl_msg.msg.create.wireless_qos_en);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract reassembly timeout parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_REASM_TIMEOUT];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.rule.decap.reassembly_timeout),
			&nl_msg.msg.create.rule.decap.reassembly_timeout);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract max fragments parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_MAX_FRAGMENTS];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.rule.decap.max_fragments),
			&nl_msg.msg.create.rule.decap.max_fragments);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract max buffer size parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_MAX_BUF_SZ];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.rule.decap.max_buffer_size),
			&nl_msg.msg.create.rule.decap.max_buffer_size);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract stats timer parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_STATS_TIMER];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.rule.stats_timer),
			&nl_msg.msg.create.rule.stats_timer);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract rps parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_RPS];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.rule.rps),
			&nl_msg.msg.create.rule.rps);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract vlan configuration parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_VLAN_CONFIG];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.vlan_config),
			&nl_msg.msg.create.vlan_config);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract pppoe configuration parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_PPPOE_CONFIG];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.pppoe_config),
			&nl_msg.msg.create.pppoe_config);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract udplite header checksum configuration parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_CSUM_ENABLE];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.csum_enable),
			&nl_msg.msg.create.csum_enable);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the L4 proto type parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_UDP_TYPE];
	error = nlcfg_param_get_protocol(sub_params->data, &nl_msg.msg.create.rule.which_udp);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the gmac interface name parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_GMAC_IFNAME];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.create.gmac_ifname),
			nl_msg.msg.create.gmac_ifname);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the mac address of egress interface
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_GMAC_IFMAC];
	error = nlcfg_param_verify_mac(sub_params->data, nl_msg.msg.create.gmac_ifmac);
	if (!sub_params->data || !error) {
		nlcfg_log_data_error(sub_params);
		error = -EINVAL;
		goto done;
	}

	/*
	 * Extract the bssid
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_BSSID];
	error = nlcfg_param_verify_mac(sub_params->data, nl_msg.msg.create.rule.bssid);
	if (!sub_params->data || !error) {
		nlcfg_log_data_error(sub_params);
		error = -EINVAL;
		goto done;
	}

	/*
	 * Extract outer sgt parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_CREATE_TUN_PARAM_OUTER_SGT_VALUE];
	error = nlcfg_param_get_hex(sub_params->data, sizeof(nl_msg.msg.create.rule.outer_sgt_value),
			(uint8_t *)&nl_msg.msg.create.rule.outer_sgt_value);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Send the capwap msg to kernel using netlink socket
	 */
	error = nss_nlcapwap_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to create tunnel error:%d\n", error);
		goto done;
	}

	nlcfg_log_info("Tunnel create message sent successfully\n");
done:
	/*
	 * Close the socket
	 */
	nss_nlcapwap_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_capwap_destroy_tun()
 *	Handle CAPWAP tunnel delete
 */
static int nlcfg_capwap_destroy_tun(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlcapwap_rule nl_msg = {{0}};
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

	/*
	 * open the NSS CAPWAP NL socket
	 */
	error = nss_nlcapwap_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	nss_nlcapwap_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NSS_NLCAPWAP_CMD_TYPE_DESTROY_TUN);

	/*
	 * Iterate through the parameters table to identify the
	 * matched arguments and populate the argument list.
	 */
	error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto done;
	}

	/*
	 * Extract tunnel id parameter
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_CAPWAP_DESTROY_TUN_PARAM_TUN_ID];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.destroy.tun_id),
			&nl_msg.msg.destroy.tun_id);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Send tunnel destroy message
	 */
	error = nss_nlcapwap_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to destroy tunnel error:%d\n", error);
		goto done;
	}

	nlcfg_log_info("Destroy tunnel message sent successfully\n");
done:
	/*
	 * close the socket
	 */
	nss_nlcapwap_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_capwap_update_mtu()
 *	HANDLES capwap path mtu updation
 */
static int nlcfg_capwap_update_mtu(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlcapwap_rule nl_msg = {{0}};
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

        /*
	 * open the NSS CAPWAP NL socket
	 */
	error = nss_nlcapwap_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 * Initialize the rule
	 */
	nss_nlcapwap_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NSS_NLCAPWAP_CMD_TYPE_UPDATE_MTU);

	/*
	 * Iterate through the args to extract the parameters
	 */
        error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto done;
	}

	/*
	 * Extract tunnel id parameter
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_CAPWAP_UPDATE_MTU_PARAM_TUN_ID];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.update_mtu.tun_id),
			&nl_msg.msg.update_mtu.tun_id);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract path mtu parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_UPDATE_MTU_PARAM_PATH_MTU];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.update_mtu.mtu.path_mtu),
			&nl_msg.msg.update_mtu.mtu.path_mtu);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 *  Send the message through netlink socket
	 */
	error = nss_nlcapwap_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("%d: Failed to update mtu: %d\n", nl_msg.msg.update_mtu.mtu.path_mtu, error);
		goto done;
	}

	nlcfg_log_info("%d: update mtu message sent successfully\n", nl_msg.msg.update_mtu.mtu.path_mtu);
done:
	/*
	 * Close the socket
	 */
	nss_nlcapwap_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_capwap_perf()
 *	HANDLES capwap enable performance command
 */
static int nlcfg_capwap_perf(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlcapwap_rule nl_msg = {{0}};
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

        /*
	 * open the NSS CAPWAP NL socket
	 */
	error = nss_nlcapwap_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 *  Initialize the rule
	 */
	nss_nlcapwap_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NSS_NLCAPWAP_CMD_TYPE_PERF);

	/*
	 *  Iterate through the args to extract the parameters
	 */
        error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto done;
	}

	/*
	 * Extract performance parameter
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_CAPWAP_PERF_PARAM_PERF_EN];
	error = nlcfg_param_get_bool(sub_params->data, &nl_msg.msg.perf.perf_en);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Send the message through netlink socket
	 */
	error = nss_nlcapwap_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to enable performance for capwap tunnel:%d\n", error);
		goto done;
	}

	nlcfg_log_info("Enable performance message sent successfully\n");
done:
	/*
	 * Close the socket
	 */
	nss_nlcapwap_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_capwap_dtls()
 *	HANDLES enabling of dtls for capwap tunnel
 */
static int nlcfg_capwap_dtls(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlcapwap_rule nl_msg = {{0}};
	char key[NLCFG_CAPWAP_DTLS_KEY_SZ];
	uint32_t size;
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

        /*
	 * open the NSS CAPWAP NL socket
	 */
	error = nss_nlcapwap_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 *  Initialize the rule
	 */
	nss_nlcapwap_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NSS_NLCAPWAP_CMD_TYPE_DTLS);

	/*
	 *  Iterate through the args to extract the parameters
	 */
        error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto done;
	}

	/*
	 * Extract the dtls tun id parameter
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_TUN_ID];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.dtls.tun_id),
			&nl_msg.msg.dtls.tun_id);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract dtls enable parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_ENABLE_DTLS];
	error = nlcfg_param_get_bool(sub_params->data, &nl_msg.msg.dtls.enable_dtls);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	if (!nl_msg.msg.dtls.enable_dtls) {
		goto process;
	}

	/*
	 * Extract the type of IP address used
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_IP_VERSION];
	error = nlcfg_param_get_int(sub_params->data, sizeof(uint32_t), &nl_msg.msg.dtls.ip_version);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	size = (nl_msg.msg.dtls.ip_version == NLCFG_CAPWAP_IPV4 ? sizeof(struct in_addr) :
			sizeof(struct in6_addr));

	/*
	 * Extract the source IP address
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_SIP];
	error = nlcfg_param_get_ipaddr_ntoh(sub_params->data, size, nl_msg.msg.dtls.encap.sip);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the destination IP address
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_DIP];
	error = nlcfg_param_get_ipaddr_ntoh(sub_params->data, size, nl_msg.msg.dtls.encap.dip);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the source port number
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_SPORT];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.dtls.encap.sport),
			&nl_msg.msg.dtls.encap.sport);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the destination port number
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_DPORT];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.dtls.encap.dport),
			&nl_msg.msg.dtls.encap.dport);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the dtls flag parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_FLAGS];
	error = nlcfg_param_get_hex(sub_params->data, sizeof(nl_msg.msg.dtls.flags),
			(uint8_t *)&nl_msg.msg.dtls.flags);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract dtls encap algo parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_ENCAP_ALGO];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.dtls.encap.crypto.algo),
			&nl_msg.msg.dtls.encap.crypto.algo);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the cipher key data parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_ENCAP_CIPHER_KEY];
	error = nlcfg_param_get_str(sub_params->data,
			sizeof(nl_msg.msg.dtls.encap.crypto.cipher_key.data), key);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	nl_msg.msg.dtls.encap.crypto.cipher_key.data = (uint8_t *)key;

	/*
	 * Extract dtls encap cipher key data length parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_ENCAP_CIPHER_KEY_LEN];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.dtls.encap.crypto.cipher_key.len),
			&nl_msg.msg.dtls.encap.crypto.cipher_key.len);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the authentication key data parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_ENCAP_AUTH_KEY];
	error = nlcfg_param_get_str(sub_params->data,
			sizeof(nl_msg.msg.dtls.encap.crypto.auth_key.data), key);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	nl_msg.msg.dtls.encap.crypto.auth_key.data = (uint8_t *)key;

	/*
	 * Extract dtls encap authentication key data length parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_ENCAP_AUTH_KEY_LEN];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.dtls.encap.crypto.auth_key.len),
			&nl_msg.msg.dtls.encap.crypto.auth_key.len);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the nonce key data parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_ENCAP_NONCE];
	error = nlcfg_param_get_str(sub_params->data,
			sizeof(nl_msg.msg.dtls.encap.crypto.nonce.data), key);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	nl_msg.msg.dtls.encap.crypto.nonce.data = (uint8_t *)key;

	/*
	 * Extract dtls encap nonce key data length parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_ENCAP_NONCE_LEN];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.dtls.encap.crypto.nonce.len),
			&nl_msg.msg.dtls.encap.crypto.nonce.len);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract dtls encap version parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_ENCAP_VERS];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.dtls.encap.ver),
			&nl_msg.msg.dtls.encap.ver);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract dtls encap epoch parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_ENCAP_EPOCH];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.dtls.encap.epoch),
			&nl_msg.msg.dtls.encap.epoch);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract dtls encap ip ttl parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_ENCAP_IP_TTL];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.dtls.encap.ip_ttl),
			&nl_msg.msg.dtls.encap.ip_ttl);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract dtls decap algo parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_DECAP_ALGO];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.dtls.decap.crypto.algo),
			&nl_msg.msg.dtls.decap.crypto.algo);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the cipher key data parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_DECAP_CIPHER_KEY];
	error = nlcfg_param_get_str(sub_params->data,
			sizeof(nl_msg.msg.dtls.decap.crypto.cipher_key.data), key);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	nl_msg.msg.dtls.decap.crypto.cipher_key.data = (uint8_t *)key;

	/*
	 * Extract dtls decap cipher key data length parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_DECAP_CIPHER_KEY_LEN];
	error = nlcfg_param_get_int(sub_params->data,
			sizeof(nl_msg.msg.dtls.decap.crypto.cipher_key.len),
			&nl_msg.msg.dtls.decap.crypto.cipher_key.len);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the authentication key data parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_DECAP_AUTH_KEY];
	error = nlcfg_param_get_str(sub_params->data,
			sizeof(nl_msg.msg.dtls.decap.crypto.auth_key), key);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	nl_msg.msg.dtls.decap.crypto.auth_key.data = (uint8_t *)key;

	/*
	 * Extract dtls decap authentication key data length parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_DECAP_AUTH_KEY_LEN];
	error = nlcfg_param_get_int(sub_params->data,
			sizeof(nl_msg.msg.dtls.decap.crypto.auth_key.len),
			&nl_msg.msg.dtls.decap.crypto.auth_key.len);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the nonce key data parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_DECAP_NONCE];
	error = nlcfg_param_get_str(sub_params->data,
			sizeof(nl_msg.msg.dtls.decap.crypto.nonce.data), key);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	nl_msg.msg.dtls.decap.crypto.nonce.data = (uint8_t *)key;

	/*
	 * Extract dtls decap nonce key data length parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_DECAP_NONCE_LEN];
	error = nlcfg_param_get_int(sub_params->data,
			sizeof(nl_msg.msg.dtls.decap.crypto.nonce.len),
			&nl_msg.msg.dtls.decap.crypto.nonce.len);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract dtls window size parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_DTLS_PARAM_WINDOW_SZ];
	error = nlcfg_param_get_int(sub_params->data,
			sizeof(nl_msg.msg.dtls.decap.window_size),
			&nl_msg.msg.dtls.decap.window_size);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

process:
	/*
	 * Send the message through netlink socket
	 */
	error = nss_nlcapwap_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to send capwap+dtls enable/disable dtls for capwap tunnel:%d\n", error);
		goto done;
	}

	nlcfg_log_info("Capwap+dtls enable/disable message sent successfully\n");
done:
	/*
	 * Close the socket
	 */
	nss_nlcapwap_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_capwap_tx_packets()
 *	Sends the traffic from one encap AP to decap AP
 */
static int nlcfg_capwap_tx_packets(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlcapwap_rule nl_msg = {{0}};
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

	/*
	 * open the NSS CAPWAP NL socket
	 */
	error = nss_nlcapwap_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 *  Initialize the rule
	 */
	nss_nlcapwap_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NSS_NLCAPWAP_CMD_TYPE_TX_PACKETS);

	/*
	 * Iterate through the args to extract the parameters
	 */
        error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto done;
	}

	/*
	 * Extract the packet size
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_CAPWAP_TX_PACKETS_PARAM_PKT_SIZE];
	error = nlcfg_param_get_int(sub_params->data, sizeof(uint32_t), &nl_msg.msg.tx_packets.pkt_size);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the tun_id
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_TX_PACKETS_PARAM_TUN_ID];
	error = nlcfg_param_get_int(sub_params->data, sizeof(uint16_t), &nl_msg.msg.tx_packets.tun_id);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the number of packets to send
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_TX_PACKETS_PARAM_NUM_OF_PACKETS];
	error = nlcfg_param_get_int(sub_params->data, sizeof(uint32_t), &nl_msg.msg.tx_packets.num_of_packets);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Send the message through netlink socket
	 */
	error = nss_nlcapwap_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to send the traffic:%d\n", error);
		goto done;
	}

	nlcfg_log_info("Traffic generation command sent successfully\n");
done:
	/*
	 * Close the socket
	 */
	nss_nlcapwap_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_capwap_meta_header()
 *	Handles creation of meta header
 */
static int nlcfg_capwap_meta_header(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlcapwap_rule nl_msg = {{0}};
	struct nlcfg_capwap_meta_header meta_header = {0};
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

        /*
	 * open the NSS CAPWAP NL socket
	 */
	error = nss_nlcapwap_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 *  Initialize the rule
	 */
	nss_nlcapwap_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NSS_NLCAPWAP_CMD_TYPE_META_HEADER);

	/*
	 *  Iterate through the args to extract the parameters
	 */
        error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto done;
	}

	/*
	 * Extract the number of wireless info sections parameter
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_CAPWAP_META_HEADER_PARAM_NWIRELESS];
	error = nlcfg_param_get_int(sub_params->data, sizeof(meta_header.nwireless),
			&meta_header.nwireless);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the dscp parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_META_HEADER_PARAM_DSCP];
	error = nlcfg_param_get_int(sub_params->data, sizeof(meta_header.dscp),
			&meta_header.dscp);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the vlan pcp parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_META_HEADER_PARAM_VLAN_PCP];
	error = nlcfg_param_get_int(sub_params->data, sizeof(meta_header.vlan_pcp),
			&meta_header.vlan_pcp);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the tunnel ID parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_META_HEADER_PARAM_TUN_ID];
	error = nlcfg_param_get_int(sub_params->data, sizeof(meta_header.tun_id),
			&meta_header.tun_id);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	nl_msg.msg.meta_header.tun_id = meta_header.tun_id;

	/*
	 * Extract the rid parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_META_HEADER_PARAM_RID];
	error = nlcfg_param_get_int(sub_params->data, sizeof(meta_header.rid),
			&meta_header.rid);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the wireless qos parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_META_HEADER_PARAM_WIRELESS_QOS];
	error = nlcfg_param_get_hex(sub_params->data, sizeof(meta_header.wireless_qos),
			(uint8_t *)&meta_header.wireless_qos);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the flow id parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_META_HEADER_PARAM_FLOW_ID];
	error = nlcfg_param_get_int(sub_params->data, sizeof(meta_header.flow_id),
			&meta_header.flow_id);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the vap id parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_META_HEADER_PARAM_VAP_ID];
	error = nlcfg_param_get_hex(sub_params->data, sizeof(meta_header.vap_id),
			(uint8_t *)&meta_header.vap_id);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the capwap pkt type parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_META_HEADER_PARAM_PKT_TYPE];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.meta_header.type),
			&nl_msg.msg.meta_header.type);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	if (nl_msg.msg.meta_header.type == NLCFG_CAPWAP_PKT_TYPE_DATA) {
		meta_header.type = NLCFG_CAPWAP_PKT_TYPE_DATA | NLCFG_CAPWAP_PKT_TYPE_802_11;
	} else {
		meta_header.type = NLCFG_CAPWAP_PKT_TYPE_DATA | NLCFG_CAPWAP_PKT_TYPE_802_3;
	}

	if (nl_msg.msg.meta_header.type) {
		meta_header.type |= NLCFG_CAPWAP_PKT_TYPE_WIRELESS_INFO;
	}

	/*
	 * Extract the capwap version parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_META_HEADER_PARAM_VERSION];
	error = nlcfg_param_get_int(sub_params->data, sizeof(meta_header.version),
			&meta_header.version);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the outer sgt parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_META_HEADER_PARAM_OUTER_SGT];
	error = nlcfg_param_get_hex(sub_params->data, sizeof(meta_header.outer_sgt),
			(uint8_t *)&meta_header.outer_sgt);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the inner sgt parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_META_HEADER_PARAM_INNER_SGT];
	error = nlcfg_param_get_hex(sub_params->data, sizeof(meta_header.inner_sgt),
			(uint8_t *)&meta_header.inner_sgt);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the wireless info parameter
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_META_HEADER_PARAM_WL_INFO];
	error = nlcfg_param_get_hex(sub_params->data, sizeof(meta_header.wl_info), meta_header.wl_info);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Create a meta header blob
	 */
	memcpy(nl_msg.msg.meta_header.meta_header_blob, &meta_header, sizeof(meta_header));

	/*
	 * Send the message through netlink socket
	 */
	error = nss_nlcapwap_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to create meta header:%d\n", error);
		goto done;
	}

	nlcfg_log_info("Create meta header message sent successfully\n");
done:
	/*
	 * close the socket
	 */
	nss_nlcapwap_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_capwap_ip_flow
 *	Handles capwap flow add and delete
 */
static int nlcfg_capwap_ip_flow(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	char ip_flow_mode[NLCFG_CAPWAP_IP_FLOW_MODE_MAX];
	struct nss_nlcapwap_rule nl_msg = {{0}};
	uint32_t size;
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

        /*
	 * open the NSS CAPWAP NL socket
	 */
	error = nss_nlcapwap_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 * Initialize the rule
	 */
	nss_nlcapwap_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NSS_NLCAPWAP_CMD_TYPE_IP_FLOW);

	/*
	 * Iterate through the args to extract the parameters
	 */
        error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto done;
	}

	/*
	 * Extract the mode parameter
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_CAPWAP_IP_FLOW_PARAM_MODE];
	error = nlcfg_param_get_str(sub_params->data, NLCFG_CAPWAP_IP_FLOW_MODE_MAX, ip_flow_mode);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Add or delete ip flow
	 */
	if (!strncmp(ip_flow_mode, NLCFG_CAPWAP_IP_FLOW_MODE_ADD,
				strlen(NLCFG_CAPWAP_IP_FLOW_MODE_ADD))) {
		nl_msg.msg.ip_flow.ip_flow_mode = NSS_NLCAPWAP_IP_FLOW_MODE_ADD;
	} else if (!strncmp(ip_flow_mode, NLCFG_CAPWAP_IP_FLOW_MODE_DEL,
				strlen(NLCFG_CAPWAP_IP_FLOW_MODE_DEL))) {
		nl_msg.msg.ip_flow.ip_flow_mode = NSS_NLCAPWAP_IP_FLOW_MODE_DEL;
	} else {
		nlcfg_log_error("Invalid value for mode: [add or del]\n");
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the tunnel id
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_IP_FLOW_PARAM_TUN_ID];
	error = nlcfg_param_get_int(sub_params->data, sizeof(uint32_t), &nl_msg.msg.ip_flow.tun_id);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the type of IP address used
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_IP_FLOW_PARAM_IP_VERSION];
	error = nlcfg_param_get_int(sub_params->data, sizeof(uint32_t), &nl_msg.msg.ip_flow.flow.ip_version);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	size = (nl_msg.msg.ip_flow.flow.ip_version == NLCFG_CAPWAP_IPV4 ? sizeof(struct in_addr) :
			sizeof(struct in6_addr));

	/*
	 * Extract the source IP address
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_IP_FLOW_PARAM_SIP];
	error = nlcfg_param_get_ipaddr_ntoh(sub_params->data, size, nl_msg.msg.ip_flow.flow.src_ip);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the destination IP address
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_IP_FLOW_PARAM_DIP];
	error = nlcfg_param_get_ipaddr_ntoh(sub_params->data, size, nl_msg.msg.ip_flow.flow.dst_ip);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the source port number
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_IP_FLOW_PARAM_SPORT];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.ip_flow.flow.src_port),
			&nl_msg.msg.ip_flow.flow.src_port);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the destination port number
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_IP_FLOW_PARAM_DPORT];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.ip_flow.flow.dst_port),
			&nl_msg.msg.ip_flow.flow.dst_port);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the flow id
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_IP_FLOW_PARAM_FLOW_ID];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.ip_flow.flow.flow_id),
			&nl_msg.msg.ip_flow.flow.flow_id);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the L4 proto name
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_IP_FLOW_PARAM_L4_PROTO];
	error = nlcfg_param_get_protocol(sub_params->data, (uint8_t *)&nl_msg.msg.ip_flow.flow.protocol);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Send the message through netlink socket
	 */
	error = nss_nlcapwap_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to send the ip flow msg.\n");
		goto done;
	}

	nlcfg_log_info("IP flow message sent successfully\n");
done:
	/*
	 * close the socket
	 */
	nss_nlcapwap_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_capwap_tx_keepalive()
 *	Enables or disables the keepalive status for a tunnel
 */
static int nlcfg_capwap_tx_keepalive(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlcapwap_rule nl_msg = {{0}};
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

	/*
	 * open the NSS CAPWAP NL socket
	 */
	error = nss_nlcapwap_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 *  Initialize the rule
	 */
	nss_nlcapwap_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NSS_NLCAPWAP_CMD_TYPE_KEEPALIVE);

	/*
	 * Iterate through the args to extract the parameters
	 */
        error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto done;
	}

	/*
	 * Extract the keepalive flag value
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_CAPWAP_TX_KEEPALIVE_PARAM_TX_KEEPALIVE];
	error = nlcfg_param_get_bool(sub_params->data, &nl_msg.msg.kalive.tx_keepalive);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Extract the tun_id
	 */
	sub_params = &param->sub_params[NLCFG_CAPWAP_TX_KEEPALIVE_PARAM_TUN_ID];
	error = nlcfg_param_get_int(sub_params->data, sizeof(uint16_t), &nl_msg.msg.kalive.tun_id);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto done;
	}

	/*
	 * Send the message through netlink socket
	 */
	error = nss_nlcapwap_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to update the keepalive status for tunnel:%d\n", nl_msg.msg.kalive.tun_id);
		goto done;
	}

	nlcfg_log_info("Keepalive enable/disable command sent successfully\n");
done:
	/*
	 * Close the socket
	 */
	nss_nlcapwap_sock_close(&nss_ctx);
	return error;
}
