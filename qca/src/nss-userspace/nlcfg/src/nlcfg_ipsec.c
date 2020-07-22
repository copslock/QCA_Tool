/*
 * Copyright (c) 2019 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

/*
 * @file NLCFG ipsec handler
 */

#include <stdint.h>
#include <nss_def.h>
#include <nss_nl_if.h>
#include <arpa/inet.h>
#include <nss_nlbase.h>
#include "nlcfg_hlos.h"
#include "nss_nlcmn_if.h"
#include "nlcfg_param.h"
#include "nlcfg_ipsec.h"
#include "nss_ipsecmgr.h"
#include "nss_nlipsec_if.h"
#include "nlcfg_hlos.h"
#include "nlcfg_param.h"
#include "nlcfg_ipv4.h"
#include "nlcfg_ipv6.h"

static int nlcfg_ipsec_tunnel_add(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_ipsec_tunnel_del(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_ipsec_sa_add(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_ipsec_sa_del(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_ipsec_flow_add(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_ipsec_flow_del(struct nlcfg_param *, struct nlcfg_param_in *);
static void nlcfg_ipsec_resp(void *user_ctx, struct nss_nlipsec_rule *nl_rule, void *resp_ctx) __attribute__((unused));

/*
 * Tunnel del param
 */
static struct nlcfg_param tun_del_params[NLCFG_IPSEC_TUN_DEL_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_IPSEC_TUN_DEL_IFNAME_TUN, "tundev="),
};

/*
 * SA add parameters
 */
static struct nlcfg_param sa_add_params[NLCFG_IPSEC_SA_ADD_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_TUN_IFNAME, "tundev="),

	/*
	 * Flow tuple parameters
	 */
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_TUPLE_IP_VER, "ip_ver="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_TUPLE_SIP, "sip="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_TUPLE_DIP, "dip="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_TUPLE_SPI_IDX, "spi_idx=0x"),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_TUPLE_SPORT, "sport="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_TUPLE_DPORT, "dport="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_TUPLE_NEXT_HDR, "next_hdr="),

	/*
	 * Common SA parameters
	 */
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_ALGO, "algo="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_CIPHER_KEY, "cipher_key="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_AUTH_KEY, "auth_key="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_NONCE, "nonce="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_CIPHER_KEYLEN, "cipher_keylen="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_AUTH_KEYLEN, "auth_keylen="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_NONCE_SIZE, "nonce_size="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_CIDX, "cidx="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_BLK_LEN, "blk_len="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_IV_LEN, "iv_len="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_ICV_LEN, "icv_len="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_SKIP_TRAILER, "skip_trailer="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_ENABLE_ESN, "enable_esn="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_ENABLE_NATT, "enable_natt="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_TRANSPORT_MODE, "transport_mode="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_HAS_KEYS, "has_keys="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_SA_TYPE, "sa_type="),

	/*
	 * Encapsulation SA parameters
	 */
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_TTL_HOP_LIMIT, "ttl_hop_limit="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_DSCP, "dscp="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_DF, "df="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_COPY_DSCP, "copy_dscp="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_COPY_DF, "copy_df="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_TX_DEFAULT, "tx_default="),

	/*
	 * Decapsulation SA parameters
	 */
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_REPLAY_THRESH, "replay_thres="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_ADD_DATA_REPLAY_WINDOW, "replay_win=")
};

/*
 * SA delete parameters
 */
static struct nlcfg_param sa_del_params[NLCFG_IPSEC_SA_DEL_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_DEL_TUN_IFNAME, "tundev="),

	/*
	 * SA tuple parameters
	 */
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_DEL_TUPLE_IP_VER, "ip_ver="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_DEL_TUPLE_SIP, "sip="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_DEL_TUPLE_DIP, "dip="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_DEL_TUPLE_SPI_IDX, "spi_idx=0x"),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_DEL_TUPLE_SPORT, "sport="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_DEL_TUPLE_DPORT, "dport="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_SA_DEL_TUPLE_NEXT_HDR, "next_hdr="),
};

/*
 * Flow add parameters
 */
static struct nlcfg_param flow_add_params[NLCFG_IPSEC_FLOW_ADD_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_ADD_TUN_IFNAME, "tundev="),

	/*
	 * Flow tuple parameters
	 */
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_ADD_TUPLE_IP_VER, "in_ip_ver="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_ADD_TUPLE_SIP, "in_sip="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_ADD_TUPLE_DIP, "in_dip="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_ADD_TUPLE_SPI_IDX, "in_spi_idx=0x"),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_ADD_TUPLE_SPORT, "in_sport="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_ADD_TUPLE_DPORT, "in_dport="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_ADD_TUPLE_NEXT_HDR, "in_next_hdr="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_ADD_TUPLE_USER_PATTERN, "in_user_def="),

	/*
	 * SA parameters
	 */
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_ADD_SA_IP_VER, "ip_ver="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_ADD_SA_SIP, "sip="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_ADD_SA_DIP, "dip="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_ADD_SA_SPI_IDX, "spi_idx=0x"),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_ADD_SA_SPORT, "sport="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_ADD_SA_DPORT, "dport="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_ADD_SA_NEXT_HDR, "next_hdr="),
};

/*
 * Flow delete parameters
 */
static struct nlcfg_param flow_del_params[NLCFG_IPSEC_FLOW_DEL_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_DEL_TUN_IFNAME, "tundev="),

	/*
	 * Flow tuple parameters
	 */
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_DEL_TUPLE_IP_VER, "in_ip_ver="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_DEL_TUPLE_SIP, "in_sip="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_DEL_TUPLE_DIP, "in_dip="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_DEL_TUPLE_SPI_IDX, "in_spi_idx=0x"),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_DEL_TUPLE_SPORT, "in_sport="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_DEL_TUPLE_DPORT, "in_dport="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_DEL_TUPLE_NEXT_HDR, "in_next_hdr="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_DEL_TUPLE_USER_PATTERN, "in_user_def="),

	/*
	 * SA parameters
	 */
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_DEL_SA_IP_VER, "ip_ver="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_DEL_SA_SIP, "sip="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_DEL_SA_DIP, "dip="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_DEL_SA_SPI_IDX, "spi_idx=0x"),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_DEL_SA_SPORT, "sport="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_DEL_SA_DPORT, "dport="),
	NLCFG_PARAM_INIT(NLCFG_IPSEC_FLOW_DEL_SA_NEXT_HDR, "next_hdr="),
};

/*
 * NOTE: whenever this table is updated it should
 * reflect the size NLCFG_IPSEC_CMD_MAX
 */
struct nlcfg_param nlcfg_ipsec_params[NLCFG_IPSEC_CMD_MAX] = {
	NLCFG_PARAMLIST_INIT("cmd=tun_add", NULL, nlcfg_ipsec_tunnel_add),
	NLCFG_PARAMLIST_INIT("cmd=tun_del", tun_del_params, nlcfg_ipsec_tunnel_del),
	NLCFG_PARAMLIST_INIT("cmd=sa_add", sa_add_params, nlcfg_ipsec_sa_add),
	NLCFG_PARAMLIST_INIT("cmd=sa_del", sa_del_params, nlcfg_ipsec_sa_del),
	NLCFG_PARAMLIST_INIT("cmd=flow_add", flow_add_params, nlcfg_ipsec_flow_add),
	NLCFG_PARAMLIST_INIT("cmd=flow_del", flow_del_params, nlcfg_ipsec_flow_del),
};

static struct nss_nlipsec_ctx nss_ctx;

/* TODO: Add support for synchronous blocking of sender till the response is received */

/*
 * nlcfg_ipsec_resp()
 * 	Handle ipsec response from kernel
 */
static void nlcfg_ipsec_resp(void *user_ctx, struct nss_nlipsec_rule *nl_rule, void *resp_ctx)
{
	if (!nl_rule) {
		nlcfg_log_error("Invalid nlcfg IPsec response\n");
		return;
	}

	uint8_t cmd = nss_nlcmn_get_cmd(&nl_rule->cm);

	switch (cmd) {
	case NSS_NLIPSEC_CMD_ADD_TUNNEL:
		nlcfg_log_info("Received ACK for add tunnel\n");
		break;
	case NSS_NLIPSEC_CMD_DEL_TUNNEL:
		nlcfg_log_info("Received ACK for delete tunnel\n");
		break;
	case NSS_NLIPSEC_CMD_ADD_SA:
		nlcfg_log_info(" Received ACK for add sa\n");
		break;
	case NSS_NLIPSEC_CMD_DEL_SA:
		nlcfg_log_info(" Received ACK for delete sa\n");
		break;
	case NSS_NLIPSEC_CMD_ADD_FLOW:
		nlcfg_log_info(" Received ACK for add flow\n");
		break;
	case NSS_NLIPSEC_CMD_DEL_FLOW:
		nlcfg_log_info(" Received ACK for delete flow\n");
		break;
	default:
		nlcfg_log_error("unsupported cmd type(%d)\n", cmd);
	}
}

/*
 * nlcfg_ipsec_get_sa_tuple()
 * 	Extract the SA tuple parameters provided by user and fill the rule message.
 */
static int nlcfg_ipsec_get_sa_tuple(struct nlcfg_param *sub_param, struct nss_ipsecmgr_sa_tuple *tuple)
{
	int ip_hdr_size;
	uint32_t spi_idx;
	int error;

	memset(tuple, 0, sizeof(*tuple));

	/*
	 * Get IP version
	 */
	error = nlcfg_param_get_int(sub_param->data, sizeof(tuple->ip_version), &tuple->ip_version);
	if (error) {
		nlcfg_log_data_error(sub_param);
		return error;
	}

	sub_param++;

	ip_hdr_size = 4;
	if (tuple->ip_version == NLCFG_IPV6_HDR_VERSION)
		ip_hdr_size = 16;

	/*
	 * Source IP address
	 */
	error = nlcfg_param_get_ipaddr_ntoh(sub_param->data, ip_hdr_size, tuple->src_ip);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	sub_param++;

	/*
	 * Destination IP address
	 */
	error = nlcfg_param_get_ipaddr_ntoh(sub_param->data, ip_hdr_size, tuple->dest_ip);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	sub_param++;

	/*
	 * SPI index
	 */
	error = nlcfg_param_get_hex(sub_param->data, sizeof(tuple->spi_index), (uint8_t *)&spi_idx);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	tuple->spi_index = ntohl(spi_idx);

	sub_param++;

	/*
	 * Source port
	 */
	error = nlcfg_param_get_int(sub_param->data, sizeof(tuple->sport), &tuple->sport);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	sub_param++;

	/*
	 * Destination port
	 */
	error = nlcfg_param_get_int(sub_param->data, sizeof(tuple->dport), &tuple->dport);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	sub_param++;

	/*
	 * Protocol next header
	 */
	error = nlcfg_param_get_int(sub_param->data, sizeof(tuple->proto_next_hdr), &tuple->proto_next_hdr);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	nlcfg_log_info("Flow outer: src:0x%x dst:0x%x spi_idx:0x%x\n", tuple->src_ip[0], tuple->dest_ip[0],
			tuple->spi_index);
	nlcfg_log_info("Flow outer: sport:%d dport:%d next_hdr:%d\n", tuple->sport, tuple->dport,
			tuple->proto_next_hdr);
	return 0;
}

/*
 * nlcfg_ipsec_get_flow_tuple()
 * 	Extract the flow tuple parameters provided by user and fill the rule message.
 */
static int nlcfg_ipsec_get_flow_tuple(struct nlcfg_param *sub_param, struct nss_nlipsec_rule *nl_rule)
{
	struct nss_ipsecmgr_flow_tuple *tuple;
	int ip_hdr_size;
	uint32_t spi_idx;
	int error;

	/*
	 * Flow tuple
	 */
	tuple = &nl_rule->rule.flow.tuple;
	memset(tuple, 0, sizeof(*tuple));

	/*
	 * Get IP version
	 */
	error = nlcfg_param_get_int(sub_param->data, sizeof(tuple->ip_version), &tuple->ip_version);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	sub_param++;

	ip_hdr_size = 4;
	if (tuple->ip_version == NLCFG_IPV6_HDR_VERSION)
		ip_hdr_size = 16;

	/*
	 * Source IP address
	 */
	error = nlcfg_param_get_ipaddr_ntoh(sub_param->data, ip_hdr_size, tuple->src_ip);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	sub_param++;

	/*
	 * Destination IP address
	 */
	error = nlcfg_param_get_ipaddr_ntoh(sub_param->data, ip_hdr_size, tuple->dest_ip);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	sub_param++;

	/*
	 * SPI index
	 */
	error = nlcfg_param_get_hex(sub_param->data, sizeof(tuple->spi_index),(uint8_t *)&spi_idx);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	tuple->spi_index = ntohl(spi_idx);

	sub_param++;

	/*
	 * Source port
	 */
	error = nlcfg_param_get_int(sub_param->data, sizeof(tuple->sport), &tuple->sport);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	sub_param++;

	/*
	 * Destination port
	 */
	error = nlcfg_param_get_int(sub_param->data, sizeof(tuple->dport), &tuple->dport);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	sub_param++;

	/*
	 * Protocol next header
	 */
	error = nlcfg_param_get_int(sub_param->data, sizeof(tuple->proto_next_hdr), &tuple->proto_next_hdr);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	sub_param++;

	/*
	 * User defined
	 */
	error = nlcfg_param_get_int(sub_param->data, sizeof(tuple->use_pattern), &tuple->use_pattern);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	nlcfg_log_info("Flow inner: src:0x%x dst:0x%x sport:%d dport:%d nexthdr:%d usr_def:%d\n",
			tuple->src_ip[0], tuple->dest_ip[0], tuple->sport,
			tuple->dport, tuple->proto_next_hdr,
			tuple->use_pattern);
	return 0;
}

/*
 * nlcfg_ipsec_get_crypto_keys()
 * 	Extract the cryptographic keys provided by user.
 */
static int nlcfg_ipsec_get_crypto_keys(struct nlcfg_param *param, struct nss_nlipsec_rule *nl_rule)
{
	struct nss_ipsecmgr_sa_data *sa = &nl_rule->rule.sa.data;
	struct nss_ipsecmgr_crypto_keys *keys;
	struct nlcfg_param *sub_param;
	int error;

	/*
	 * Cryptographic algorithm
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_ALGO];
	error = nlcfg_param_get_int(sub_param->data, sizeof(sa->cmn.algo), &sa->cmn.algo);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	/*
	 * Keys
	 * ----
	 * The steps to copy a key from userspace are as follows:
	 * 1. Extract the cipher key length.
	 * 2. Allocate memory to copy the key.
	 * 3. Copy the key provided by the user to the message structure.
	 */
	keys = &sa->cmn.keys;

	/*
	 * Cipher key size
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_CIPHER_KEYLEN];
	error = nlcfg_param_get_int(sub_param->data, sizeof(keys->cipher_keylen), &keys->cipher_keylen);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	/*
	 * Authentication key size
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_AUTH_KEYLEN];
	error = nlcfg_param_get_int(sub_param->data, sizeof(keys->auth_keylen), &keys->auth_keylen);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	/*
	 * NONCE size
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_NONCE_SIZE];
	error = nlcfg_param_get_int(sub_param->data, sizeof(keys->nonce_size), &keys->nonce_size);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	/*
	 * Cipher key
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_CIPHER_KEY];
	error = nlcfg_param_get_hex(sub_param->data, keys->cipher_keylen, nl_rule->rule.sa.cipher_key);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	/*
	 * Authentication key
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_AUTH_KEY];
	error = nlcfg_param_get_hex(sub_param->data, keys->auth_keylen, nl_rule->rule.sa.auth_key);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	/*
	 * NONCE
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_NONCE];
	error = nlcfg_param_get_hex(sub_param->data, keys->nonce_size, nl_rule->rule.sa.nonce);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		return error;
	}

	nlcfg_log_info("Crypto key lengths: cipher:%d auth:%d nonce:%d\n", keys->cipher_keylen, keys->auth_keylen,
			keys->nonce_size);

	return 0;

}

/*
 * nlcfg_ipsec_tunnel_add()
 * 	Handle IPsec tunnel add
 */
static int nlcfg_ipsec_tunnel_add(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlipsec_rule nl_msg = {{0}};
	int error;

	if (!match || !param) {
		nlcfg_log_error("Param or match is null\n");
		return -EINVAL;
	}

        /*
	 * Open the NSS IPsec NL socket
	 */
	error = nss_nlipsec_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_warn("Failed to open IPsec socket; error(%d)\n", error);
		return error;
	}

	nss_nlipsec_init_cmd(&nss_ctx, &nl_msg, NULL, NULL, NSS_NLIPSEC_CMD_ADD_TUNNEL);

	error = nss_nlipsec_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to add tunnel error:%d\n", error);
		goto done;
	}

	nlcfg_log_info("Successfully added tunnel\n");
done:
	/*
	 * close the socket
	 */
	nss_nlipsec_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_ipsec_tunnel_del()
 * 	Handle IPsec tunnel delete
 */
static int nlcfg_ipsec_tunnel_del(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlipsec_rule nl_msg = {{0}};
	struct nlcfg_param *sub_param;
	int error;

	if (!match || !param) {
		nlcfg_log_error("Param or match is null\n");
		return -EINVAL;
	}

        /*
	 * Open the NSS IPsec NL socket
	 */
	error = nss_nlipsec_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_warn("Failed to open IPsec socket; error(%d)\n", error);
		return error;
	}

	nss_nlipsec_init_cmd(&nss_ctx, &nl_msg, NULL, NULL, NSS_NLIPSEC_CMD_DEL_TUNNEL);

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
	 * Extract interface name
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_TUN_DEL_IFNAME_TUN];
	error = nlcfg_param_get_str(sub_param->data, sizeof(nl_msg.ifname), nl_msg.ifname);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		goto done;
	}

	/*
	 * Send tunnel delete message
	 */
	error = nss_nlipsec_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("%s: Failed to deleted tunnel error:%d\n", nl_msg.ifname, error);
		goto done;
	}

	nlcfg_log_info("Successfully deleted tunnel(%s)\n", nl_msg.ifname);
done:
	/*
	 * close the socket
	 */
	nss_nlipsec_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_ipsec_sa_add()
 * 	Add a Security Assocition
 */
static int nlcfg_ipsec_sa_add(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlipsec_rule nl_msg = {{0}};
	struct nlcfg_param *sub_param;
	struct nss_ipsecmgr_sa_data *sa;
	int error;

	if (!match || !param) {
		nlcfg_log_error("Param or match is null\n");
		return -EINVAL;
	}

        /*
	 * Open the NSS IPsec NL socket
	 */
	error = nss_nlipsec_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_warn("Failed to open IPsec socket; error(%d)\n", error);
		return error;;
	}

	nss_nlipsec_init_cmd(&nss_ctx, &nl_msg, NULL, NULL, NSS_NLIPSEC_CMD_ADD_SA);

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
	 * Extract interface name
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_TUN_IFNAME];
	error = nlcfg_param_get_str(sub_param->data, sizeof(nl_msg.ifname), nl_msg.ifname);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		goto done;
	}

	/*
	 * Extract SA tuple
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_TUPLE_IP_VER];
	error = nlcfg_ipsec_get_sa_tuple(sub_param, &nl_msg.rule.sa.tuple);
	if (error) {
		nlcfg_log_error("%s: Failed to extract outer flow data\n", nl_msg.ifname);
		goto done;
	}

	/*
	 * Extract SA data
	 */
	sa = &nl_msg.rule.sa.data;
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_HAS_KEYS];
	error = nlcfg_param_get_int(sub_param->data, sizeof(sa->cmn.crypto_has_keys), &sa->cmn.crypto_has_keys);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		goto done;
	}

	/*
	 * If the keys are already configured then extract the crypto session index,
	 * else extract all the keys provided by the user.
	 */
	if (!sa->cmn.crypto_has_keys) {
		sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_CIDX];
		error = nlcfg_param_get_int(sub_param->data, sizeof(sa->cmn.index.session), &sa->cmn.index.session);
		if (error) {
			nlcfg_log_arg_error(sub_param);
			goto done;
		}

		sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_BLK_LEN];
		error = nlcfg_param_get_int(sub_param->data, sizeof(sa->cmn.index.blk_len), &sa->cmn.index.blk_len);
		if (error) {
			nlcfg_log_arg_error(sub_param);
			goto done;
		}

		sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_IV_LEN];
		error = nlcfg_param_get_int(sub_param->data, sizeof(sa->cmn.index.iv_len), &sa->cmn.index.iv_len);
		if (error) {
			nlcfg_log_arg_error(sub_param);
			goto done;
		}

	} else {
		error = nlcfg_ipsec_get_crypto_keys(param, &nl_msg);
		if (error) {
			nlcfg_log_error("Failed to extract keys");
			goto done;
		}
	}

	/*
	 * ICV Length
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_ICV_LEN];
	error = nlcfg_param_get_int(sub_param->data, sizeof(sa->cmn.icv_len), &sa->cmn.icv_len);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		goto done;
	}

	/*
	 * Skip trailer
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_SKIP_TRAILER];
	error = nlcfg_param_get_int(sub_param->data, sizeof(sa->cmn.skip_trailer), &sa->cmn.skip_trailer);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		goto done;
	}

	/*
	 * Enable ESN
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_ENABLE_ESN];
	error = nlcfg_param_get_int(sub_param->data, sizeof(sa->cmn.enable_esn), &sa->cmn.enable_esn);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		goto done;
	}

	/*
	 * Enable NATT
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_ENABLE_NATT];
	error = nlcfg_param_get_int(sub_param->data, sizeof(sa->cmn.enable_natt), &sa->cmn.enable_natt);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		goto done;
	}

	/*
	 * Enable IPsec in transport mode
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_TRANSPORT_MODE];
	error = nlcfg_param_get_int(sub_param->data, sizeof(sa->cmn.transport_mode), &sa->cmn.transport_mode);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		goto done;
	}

	/*
	 * SA type
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_SA_TYPE];
	error = nlcfg_param_get_int(sub_param->data, sizeof(sa->type), &sa->type);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		goto done;
	}

	if (sa->type == NSS_IPSECMGR_SA_TYPE_ENCAP) {

		/*
		 * TTL or hop limit
		 */
		sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_TTL_HOP_LIMIT];
		error = nlcfg_param_get_int(sub_param->data, sizeof(sa->encap.ttl_hop_limit), &sa->encap.ttl_hop_limit);
		if (error) {
			nlcfg_log_arg_error(sub_param);
			goto done;
		}

		/*
		 * DSCP
		 */
		sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_DSCP];
		error = nlcfg_param_get_int(sub_param->data, sizeof(sa->encap.dscp), &sa->encap.dscp);
		if (error) {
			nlcfg_log_arg_error(sub_param);
			goto done;
		}

		/*
		 * DF
		 */
		sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_DF];
		error = nlcfg_param_get_int(sub_param->data, sizeof(sa->encap.df), &sa->encap.df);
		if (error) {
			nlcfg_log_arg_error(sub_param);
			goto done;
		}

		/*
		 * Copy DSCP
		 */
		sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_COPY_DSCP];
		error = nlcfg_param_get_int(sub_param->data, sizeof(sa->encap.copy_dscp), &sa->encap.copy_dscp);
		if (error) {
			nlcfg_log_arg_error(sub_param);
			goto done;
		}

		/*
		 * Copy DF
		 */
		sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_COPY_DF];
		error = nlcfg_param_get_int(sub_param->data, sizeof(sa->encap.copy_df), &sa->encap.copy_df);
		if (error) {
			nlcfg_log_arg_error(sub_param);
			goto done;
		}

		/*
		 * Default SA
		 */
		sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_TX_DEFAULT];
		error = nlcfg_param_get_int(sub_param->data, sizeof(sa->encap.tx_default), &sa->encap.tx_default);
		if (error) {
			nlcfg_log_arg_error(sub_param);
			goto done;
		}

	} else if (sa->type == NSS_IPSECMGR_SA_TYPE_DECAP) {

		/*
		 * Anti-replay hash fail threshold
		 */
		sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_REPLAY_THRESH];
		error = nlcfg_param_get_int(sub_param->data, sizeof(sa->decap.replay_fail_thresh),
					&sa->decap.replay_fail_thresh);
		if (error) {
			nlcfg_log_arg_error(sub_param);
			goto done;
		}

		/*
		 * Anti-replay window size
		 */
		sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_DATA_REPLAY_WINDOW];
		error = nlcfg_param_get_int(sub_param->data, sizeof(sa->decap.replay_win), &sa->decap.replay_win);
		if (error) {
			nlcfg_log_arg_error(sub_param);
			goto done;
		}

	}

	/*
	 * Send SA add message
	 */
	error = nss_nlipsec_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("%s: Failed to add SA error:%d\n", nl_msg.ifname, error);
		goto done;
	}

	nlcfg_log_info("%s: Successfully added SA\n", nl_msg.ifname);
done:
	/*
	 * close the socket
	 */
	nss_nlipsec_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_ipsec_sa_del()
 * 	Delete a Security Assocition
 */
static int nlcfg_ipsec_sa_del(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlipsec_rule nl_msg = {{0}};
	struct nlcfg_param *sub_param;
	int error;

	if (!match || !param) {
		nlcfg_log_error("Param or match is null\n");
		return -EINVAL;
	}

        /*
	 * Open the NSS IPsec NL socket
	 */
	error = nss_nlipsec_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_warn("Failed to open IPsec socket; error(%d)\n", error);
		return error;;
	}

	nss_nlipsec_init_cmd(&nss_ctx, &nl_msg, NULL, NULL, NSS_NLIPSEC_CMD_DEL_SA);

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
	 * Extract interface name
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_ADD_TUN_IFNAME];
	error = nlcfg_param_get_str(sub_param->data, sizeof(nl_msg.ifname), nl_msg.ifname);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		goto done;
	}

	/*
	 * Extract SA tuple
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_SA_DEL_TUPLE_IP_VER];
	error = nlcfg_ipsec_get_sa_tuple(sub_param, &nl_msg.rule.sa.tuple);
	if (error) {
		nlcfg_log_error("%s: Failed to extract outer flow data\n", nl_msg.ifname);
		goto done;
	}

	/*
	 * Send delete SA message
	 */
	error = nss_nlipsec_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("%s: Failed to delete SA error:%d\n", nl_msg.ifname, error);
		goto done;
	}

	nlcfg_log_info("%s: Successfully deleted SA\n", nl_msg.ifname);
done:
	/*
	 * close the socket
	 */
	nss_nlipsec_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_ipsec_flow_add()
 * 	Add a flow.
 */
static int nlcfg_ipsec_flow_add(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlipsec_rule nl_msg = {{0}};
	struct nlcfg_param *sub_param;
	int error;

	if (!match || !param) {
		nlcfg_log_error("Param or match is null\n");
		return -EINVAL;
	}

        /*
	 * Open the NSS IPsec NL socket
	 */
	error = nss_nlipsec_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_warn("Failed to open IPsec socket; error(%d)\n", error);
		return error;
	}

	nss_nlipsec_init_cmd(&nss_ctx, &nl_msg, NULL, NULL, NSS_NLIPSEC_CMD_ADD_FLOW);

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
	 * Extract interface name
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_FLOW_ADD_TUN_IFNAME];
	error = nlcfg_param_get_str(sub_param->data, sizeof(nl_msg.ifname), nl_msg.ifname);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		goto done;
	}

	/*
	 * Extract flow SA
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_FLOW_ADD_SA_IP_VER];
	error = nlcfg_ipsec_get_sa_tuple(sub_param, &nl_msg.rule.flow.sa);
	if (error) {
		nlcfg_log_error("%s: Failed to get outer flow data\n", nl_msg.ifname);
		goto done;
	}

	/*
	 * Extract  flow tuple
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_FLOW_ADD_TUPLE_IP_VER];
	error = nlcfg_ipsec_get_flow_tuple(sub_param, &nl_msg);
	if (error) {
		nlcfg_log_error("%s: Failed to get inner flow data\n", nl_msg.ifname);
		goto done;
	}

	/*
	 * Send add flow message
	 */
	error = nss_nlipsec_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("%s: Failed to add flow error:%d\n", nl_msg.ifname, error);
		goto done;
	}

	nlcfg_log_info("%s: Successfully added flow\n", nl_msg.ifname);
done:
	/*
	 * close the socket
	 */
	nss_nlipsec_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_ipsec_flow_del()
 * 	Delete a flow.
 */
static int nlcfg_ipsec_flow_del(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nlipsec_rule nl_msg = {{0}};
	struct nlcfg_param *sub_param;
	int error;

	if (!match || !param) {
		nlcfg_log_error("Param or match is null\n");
		return -EINVAL;
	}

        /*
	 * Open the NSS IPsec NL socket
	 */
	error = nss_nlipsec_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_warn("Failed to open IPsec socket; error(%d)\n", error);
		return error;
	}

	nss_nlipsec_init_cmd(&nss_ctx, &nl_msg, NULL, NULL, NSS_NLIPSEC_CMD_DEL_FLOW);

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
	 * Extract interface name
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_FLOW_DEL_TUN_IFNAME];
	error = nlcfg_param_get_str(sub_param->data, sizeof(nl_msg.ifname), nl_msg.ifname);
	if (error) {
		nlcfg_log_arg_error(sub_param);
		goto done;
	}

	/*
	 * Extract flow SA
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_FLOW_DEL_SA_IP_VER];
	error = nlcfg_ipsec_get_sa_tuple(sub_param, &nl_msg.rule.flow.sa);
	if (error) {
		nlcfg_log_error("%s: Failed to get outer flow data\n", nl_msg.ifname);
		goto done;
	}

	/*
	 * Extract flow tuple
	 */
	sub_param = &param->sub_params[NLCFG_IPSEC_FLOW_DEL_TUPLE_IP_VER];
	error = nlcfg_ipsec_get_flow_tuple(sub_param, &nl_msg);
	if (error) {
		nlcfg_log_error("%s: Failed to get inner flow data\n", nl_msg.ifname);
		goto done;
	}

	/*
	 * Send delete flow message
	 */
	error = nss_nlipsec_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("%s: Failed to delete flow error:%d\n", nl_msg.ifname, error);
		goto done;
	}

	nlcfg_log_info("%s: Successfully deleted flow\n", nl_msg.ifname);
done:
	/*
	 * close the socket
	 */
	nss_nlipsec_sock_close(&nss_ctx);
	return error;
}
