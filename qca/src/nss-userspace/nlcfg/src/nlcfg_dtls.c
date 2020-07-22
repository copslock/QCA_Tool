/*
 * Copyright (c) 2019-2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

/*
 * @file NLCFG dtls handler
 */
/*
 * TODO: Remove interdependencies among the header files.
 */
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <nss_def.h>
#include <nss_nlbase.h>
#include <nss_nl_if.h>
#include <nss_nldtls_api.h>
#include "nlcfg_dtls.h"
#include "nlcfg_hlos.h"
#include "nlcfg_param.h"
#include "nss_nlcmn_if.h"
#include "nss_nldtls_if.h"

/*
 * Function prototypes
 */
static int nlcfg_dtls_create_tun(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_dtls_destroy_tun(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_dtls_update_config(struct nlcfg_param *, struct nlcfg_param_in *);
static int nlcfg_dtls_tx_pkts(struct nlcfg_param *, struct nlcfg_param_in *);

/*
 * Create tunnel parameters
 */
struct nlcfg_param dtls_create_tun_params[NLCFG_DTLS_CREATE_TUN_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_IP_VERSION, "ip_version="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_SIP, "sip="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_DIP, "dip="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_SPORT, "sport="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_DPORT, "dport="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_GMAC_IFNAME, "gmac_ifname="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_GMAC_IFMAC, "gmac_ifmac="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_FLAGS, "flags="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_ALGO, "encap_algo="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_CIPHER_KEY, "encap_cipher_key="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_CIPHER_KEY_LEN, "encap_cipher_key_len="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_AUTH_KEY, "encap_auth_key="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_AUTH_KEY_LEN, "encap_auth_key_len="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_NONCE, "encap_nonce="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_NONCE_LEN, "encap_nonce_len="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_VERS, "encap_vers="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_EPOCH, "encap_epoch="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_IP_TTL, "encap_ip_ttl="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_DSCP, "dscp="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_DSCP_COPY, "dscp_copy="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_DF, "df="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_ALGO, "decap_algo="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_CIPHER_KEY, "decap_cipher_key="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_CIPHER_KEY_LEN, "decap_cipher_key_len="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_AUTH_KEY, "decap_auth_key="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_AUTH_KEY_LEN, "decap_auth_key_len="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_NONCE, "decap_nonce="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_NONCE_LEN, "decap_nonce_len="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_WINDOW_SZ, "window_sz="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_FROM_MTU, "from_mtu="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_CREATE_TUN_PARAM_TO_MTU, "to_mtu="),
};

/*
 * Delete tunnel parameters
 */
struct nlcfg_param dtls_destroy_tun_params[NLCFG_DTLS_DESTROY_TUN_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_DTLS_DESTROY_TUN_PARAM_DEV_NAME, "dev_name="),
};

/*
 * Update config parameters
 */
struct nlcfg_param update_config_params[NLCFG_DTLS_UPDATE_CONFIG_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_DTLS_UPDATE_CONFIG_PARAM_DEV_NAME, "dev_name="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_UPDATE_CONFIG_PARAM_ALGO, "algo="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_UPDATE_CONFIG_PARAM_CIPHER_KEY, "cipher_key="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_UPDATE_CONFIG_PARAM_CIPHER_KEY_LEN, "cipher_key_len="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_UPDATE_CONFIG_PARAM_AUTH_KEY, "auth_key="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_UPDATE_CONFIG_PARAM_AUTH_KEY_LEN, "auth_key_len="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_UPDATE_CONFIG_PARAM_NONCE, "nonce="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_UPDATE_CONFIG_PARAM_NONCE_LEN, "nonce_len="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_UPDATE_CONFIG_PARAM_DIR, "dir="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_UPDATE_CONFIG_PARAM_EPOCH, "epoch="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_UPDATE_CONFIG_PARAM_WINDOW_SZ, "window_sz="),
};

/*
 * Tx packets parameters
 */
struct nlcfg_param dtls_tx_pkts_params[NLCFG_DTLS_TX_PKTS_PARAM_MAX] = {
	NLCFG_PARAM_INIT(NLCFG_DTLS_TX_PKTS_PARAM_LOG_EN, "log_en="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_TX_PKTS_PARAM_DEV_NAME, "dev_name="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_TX_PKTS_PARAM_PKT_SZ, "pkt_sz="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_TX_PKTS_PARAM_IP_VERSION, "ip_version="),
	NLCFG_PARAM_INIT(NLCFG_DTLS_TX_PKTS_PARAM_NUM_PKTS, "num_pkts="),
};

/*
 * Dtls parameters
 */
struct nlcfg_param nlcfg_dtls_params[NLCFG_DTLS_CMD_TYPE_MAX] = {
	NLCFG_PARAMLIST_INIT("cmd=create", dtls_create_tun_params, nlcfg_dtls_create_tun),
	NLCFG_PARAMLIST_INIT("cmd=destroy", dtls_destroy_tun_params, nlcfg_dtls_destroy_tun),
	NLCFG_PARAMLIST_INIT("cmd=update_config", update_config_params, nlcfg_dtls_update_config),
	NLCFG_PARAMLIST_INIT("cmd=tx_pkts", dtls_tx_pkts_params, nlcfg_dtls_tx_pkts),
};

static struct nss_nldtls_ctx nss_ctx;

/*
 * nlcfg_dtls_create_tun()
 *	Handles DTLS tunnel creation
 */
static int nlcfg_dtls_create_tun(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nldtls_rule nl_msg = {{0}};
	char key[NLCFG_DTLS_KEY_SZ];
	uint32_t size;
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

	/*
	 * Open the NSS DTLS NL socket
	 */
	error = nss_nldtls_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 * Initialize the rule
	 */
	nss_nldtls_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NLCFG_DTLS_CMD_TYPE_CREATE_TUN);

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
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_IP_VERSION];
	error = nlcfg_param_get_int(sub_params->data, sizeof(uint32_t), &nl_msg.msg.create.ip_version);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	size = (nl_msg.msg.create.ip_version == NLCFG_DTLS_IPV4 ? sizeof(struct in_addr) :
			sizeof(struct in6_addr));

	/*
	 * Extract the source IP address
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_SIP];
	error = nlcfg_param_get_ipaddr_ntoh(sub_params->data, size, nl_msg.msg.create.encap.sip);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the destination IP address
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_DIP];
	error = nlcfg_param_get_ipaddr_ntoh(sub_params->data, size, nl_msg.msg.create.encap.dip);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the source port number
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_SPORT];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.encap.sport),
			&nl_msg.msg.create.encap.sport);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the destination port number
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_DPORT];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.encap.dport),
			&nl_msg.msg.create.encap.dport);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the gmac interface name parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_GMAC_IFNAME];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.create.gmac_ifname),
			nl_msg.msg.create.gmac_ifname);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the mac address of egress interface
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_GMAC_IFMAC];
	error = nlcfg_param_verify_mac(sub_params->data, nl_msg.msg.create.gmac_ifmac);
	if (!sub_params->data || !error) {
		nlcfg_log_data_error(sub_params);
		error = -EINVAL;
		goto fail;
	}

	/*
	 * Extract the dtls flag parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_FLAGS];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.flags),
			&nl_msg.msg.create.flags);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract dtls encap algo parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_ALGO];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.encap.crypto.algo),
			&nl_msg.msg.create.encap.crypto.algo);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the cipher key data parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_CIPHER_KEY];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.create.encap.crypto.cipher_key.data),
			key);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	nl_msg.msg.create.encap.crypto.cipher_key.data = (uint8_t *)key;
	/*
	 * Extract dtls encap cipher key data length parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_CIPHER_KEY_LEN];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.encap.crypto.cipher_key.len),
			&nl_msg.msg.create.encap.crypto.cipher_key.len);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the authentication key data parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_AUTH_KEY];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.create.encap.crypto.auth_key.data),
			key);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	nl_msg.msg.create.encap.crypto.auth_key.data = (uint8_t *)key;

	/*
	 * Extract dtls encap authentication key data length parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_AUTH_KEY_LEN];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.encap.crypto.auth_key.len),
			&nl_msg.msg.create.encap.crypto.auth_key.len);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the nonce key data parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_NONCE];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.create.encap.crypto.nonce.data),
			key);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	nl_msg.msg.create.encap.crypto.nonce.data = (uint8_t *)key;

	/*
	 * Extract dtls encap nonce key data length parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_NONCE_LEN];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.encap.crypto.nonce.len),
			&nl_msg.msg.create.encap.crypto.nonce.len);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract dtls encap version parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_VERS];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.encap.ver),
			&nl_msg.msg.create.encap.ver);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract dtls encap epoch parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_EPOCH];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.encap.epoch),
			&nl_msg.msg.create.encap.epoch);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract dtls encap ip_ttl parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_IP_TTL];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.encap.ip_ttl),
			&nl_msg.msg.create.encap.ip_ttl);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract dtls decap algo parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_ALGO];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.decap.crypto.algo),
			&nl_msg.msg.create.decap.crypto.algo);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the cipher key data parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_CIPHER_KEY];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.create.decap.crypto.cipher_key.data),
			key);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	nl_msg.msg.create.decap.crypto.cipher_key.data = (uint8_t *)key;

	/*
	 * Extract dtls decap cipher key data length parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_CIPHER_KEY_LEN];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.decap.crypto.cipher_key.len),
			&nl_msg.msg.create.decap.crypto.cipher_key.len);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the authentication key data parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_AUTH_KEY];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.create.decap.crypto.auth_key.data),
			key);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	nl_msg.msg.create.decap.crypto.auth_key.data = (uint8_t *)key;

	/*
	 * Extract dtls decap authentication key data length parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_AUTH_KEY_LEN];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.decap.crypto.auth_key.len),
			&nl_msg.msg.create.decap.crypto.auth_key.len);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the nonce key data parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_NONCE];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.create.decap.crypto.nonce.data),
			key);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	nl_msg.msg.create.decap.crypto.nonce.data = (uint8_t *)key;

	/*
	 * Extract dtls decap nonce key data length parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_NONCE_LEN];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.decap.crypto.nonce.len),
			&nl_msg.msg.create.decap.crypto.nonce.len);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract dtls window size parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_WINDOW_SZ];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.decap.window_size),
			&nl_msg.msg.create.decap.window_size);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract from mtu parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_FROM_MTU];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.from_mtu),
			&nl_msg.msg.create.from_mtu);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract to mtu parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_CREATE_TUN_PARAM_TO_MTU];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.create.to_mtu),
			&nl_msg.msg.create.to_mtu);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Send the dtls msg to kernel using netlink socket
	 */
	error = nss_nldtls_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to create tunnel error:%d\n", error);
		goto fail;
	}

	nlcfg_log_info("Tunnel create message sent successfully\n");
fail:
	/*
	 * Close the socket
	 */
	nss_nldtls_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_dtls_destroy_tun()
 *	Handle DTLS tunnel delete
 */
static int nlcfg_dtls_destroy_tun(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nldtls_rule nl_msg = {{0}};
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

        /*
	 * open the NSS DTLS NL socket
	 */
	error = nss_nldtls_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	nss_nldtls_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NLCFG_DTLS_CMD_TYPE_DESTROY_TUN);

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
	 * Extract the dev_name parameter
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_DTLS_DESTROY_TUN_PARAM_DEV_NAME];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.destroy.dev_name),
			nl_msg.msg.destroy.dev_name);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Send tunnel destroy message
	 */
	error = nss_nldtls_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to send destroy tunnel command:%d\n", error);
		goto fail;
	}

	nlcfg_log_info("Destroy tunnel message sent successfully\n");
fail:
	/*
	 * close the socket
	 */
	nss_nldtls_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_dtls_update_config
 *	HANDLES dtls path mtu updation
 */
static int nlcfg_dtls_update_config(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nldtls_rule nl_msg = {{0}};
	char key[NLCFG_DTLS_KEY_SZ];
	char dir[NLCFG_DTLS_DIR_SZ];
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

        /*
	 * open the NSS DTLS NL socket
	 */
	error = nss_nldtls_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 * Initialize the rule
	 */
	nss_nldtls_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NLCFG_DTLS_CMD_TYPE_UPDATE_CONFIG);

	/*
	 * Iterate through the args to extract the parameters
	 */
        error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto fail;
	}

	/*
	 * Extract dtls encap algo parameter
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_DTLS_UPDATE_CONFIG_PARAM_ALGO];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.update_config.config_update.crypto.algo),
			&nl_msg.msg.update_config.config_update.crypto.algo);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the cipher key data parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_UPDATE_CONFIG_PARAM_CIPHER_KEY];
	error = nlcfg_param_get_str(sub_params->data,
			sizeof(nl_msg.msg.update_config.config_update.crypto.cipher_key.data),
			key);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	nl_msg.msg.update_config.config_update.crypto.cipher_key.data = (uint8_t *)key;

	/*
	 * Extract the dev_name parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_UPDATE_CONFIG_PARAM_DEV_NAME];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.update_config.dev_name),
			nl_msg.msg.update_config.dev_name);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract dtls encap cipher key data length parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_UPDATE_CONFIG_PARAM_CIPHER_KEY_LEN];
	error = nlcfg_param_get_int(sub_params->data,
			sizeof(nl_msg.msg.update_config.config_update.crypto.cipher_key.len),
			&nl_msg.msg.update_config.config_update.crypto.cipher_key.len);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the authentication key data parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_UPDATE_CONFIG_PARAM_AUTH_KEY];
	error = nlcfg_param_get_str(sub_params->data,
			sizeof(nl_msg.msg.update_config.config_update.crypto.auth_key.data),
			key);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	nl_msg.msg.update_config.config_update.crypto.auth_key.data = (uint8_t *)key;

	/*
	 * Extract dtls encap authentication key data length parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_UPDATE_CONFIG_PARAM_AUTH_KEY_LEN];
	error = nlcfg_param_get_int(sub_params->data,
			sizeof(nl_msg.msg.update_config.config_update.crypto.auth_key.len),
			&nl_msg.msg.update_config.config_update.crypto.auth_key.len);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the nonce key data parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_UPDATE_CONFIG_PARAM_NONCE];
	error = nlcfg_param_get_str(sub_params->data,
			sizeof(nl_msg.msg.update_config.config_update.crypto.nonce.data),
			key);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	nl_msg.msg.update_config.config_update.crypto.nonce.data = (uint8_t *)key;

	/*
	 * Extract the direction parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_UPDATE_CONFIG_PARAM_DIR];
	error = nlcfg_param_get_str(sub_params->data, NLCFG_DTLS_DIR_SZ,
			dir);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	if (!strncmp(dir, NLCFG_DTLS_DIR_ENCAP, strlen(NLCFG_DTLS_DIR_ENCAP))) {
		nl_msg.msg.update_config.dir = NSS_NLDTLS_ENCAP_SIDE;
	} else if (!strncmp(dir, NLCFG_DTLS_DIR_DECAP, strlen(NLCFG_DTLS_DIR_DECAP))) {
		nl_msg.msg.update_config.dir = NSS_NLDTLS_DECAP_SIDE;
	} else {
		nlcfg_log_error("Invalid dir value: [can be encap or decap]\n");
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract dtls encap nonce key data length parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_UPDATE_CONFIG_PARAM_NONCE_LEN];
	error = nlcfg_param_get_int(sub_params->data,
			sizeof(nl_msg.msg.update_config.config_update.crypto.nonce.len),
			&nl_msg.msg.update_config.config_update.crypto.nonce.len);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract dtls encap epoch parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_UPDATE_CONFIG_PARAM_EPOCH];
	error = nlcfg_param_get_int(sub_params->data,
			sizeof(nl_msg.msg.update_config.config_update.epoch),
			&nl_msg.msg.update_config.config_update.epoch);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract dtls window size parameter
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_UPDATE_CONFIG_PARAM_WINDOW_SZ];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.update_config.window_sz),
			&nl_msg.msg.update_config.window_sz);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 *  Send the message through netlink socket
	 */
	error = nss_nldtls_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to update configuration: %d\n", error);
		goto fail;
	}

	nlcfg_log_info("Update configuration message sent successfully\n");
fail:
	/*
	 * Close the socket
	 */
	nss_nldtls_sock_close(&nss_ctx);
	return error;
}

/*
 * nlcfg_dtls_tx_pkts
 *	Sends the traffic from one encap AP to decap AP
 */
static int nlcfg_dtls_tx_pkts(struct nlcfg_param *param, struct nlcfg_param_in *match)
{
	struct nss_nldtls_rule nl_msg = {{0}};
	int error;

	if (!match || !param) {
		nlcfg_log_error("NULL argument passed\n");
		return -EINVAL;
	}

        /*
	 * open the NSS DTLS NL socket
	 */
	error = nss_nldtls_sock_open(&nss_ctx, NULL, NULL);
	if (error < 0) {
		nlcfg_log_error("Unable to open the socket\n");
		return -ENOMEM;
	}

	/*
	 *  Initialize the rule
	 */
	nss_nldtls_init_rule(&nss_ctx, &nl_msg, NULL, NULL, NLCFG_DTLS_CMD_TYPE_TX_PKTS);

	/*
	 * Iterate through the args to extract the parameters
	 */
        error = nlcfg_param_iter_tbl(param, match);
	if (error) {
		nlcfg_log_arg_error(param);
		goto fail;
	}

	/*
	 * Extract the log_enable parameter
	 */
	struct nlcfg_param *sub_params = &param->sub_params[NLCFG_DTLS_TX_PKTS_PARAM_LOG_EN];
	error = nlcfg_param_get_bool(sub_params->data, &nl_msg.msg.tx_pkts.log_en);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the tunnel id used for transmission
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_TX_PKTS_PARAM_DEV_NAME];
	error = nlcfg_param_get_str(sub_params->data, sizeof(nl_msg.msg.tx_pkts.dev_name),
			nl_msg.msg.tx_pkts.dev_name);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the number of packets to send
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_TX_PKTS_PARAM_NUM_PKTS];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.tx_pkts.num_pkts),
			&nl_msg.msg.tx_pkts.num_pkts);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the size of packet to send
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_TX_PKTS_PARAM_PKT_SZ];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.tx_pkts.pkt_sz),
			&nl_msg.msg.tx_pkts.pkt_sz);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Extract the version of ip
	 */
	sub_params = &param->sub_params[NLCFG_DTLS_TX_PKTS_PARAM_IP_VERSION];
	error = nlcfg_param_get_int(sub_params->data, sizeof(nl_msg.msg.tx_pkts.ip_version),
			&nl_msg.msg.tx_pkts.ip_version);
	if (error < 0) {
		nlcfg_log_data_error(sub_params);
		goto fail;
	}

	/*
	 * Send the message through netlink socket
	 */
	error = nss_nldtls_sock_send(&nss_ctx, &nl_msg);
	if (error < 0) {
		nlcfg_log_error("Failed to send the traffic:%d\n", error);
		goto fail;
	}

	nlcfg_log_info("Traffic generation command sent successfully\n");
fail:
	/*
	 * Close the socket
	 */
	nss_nldtls_sock_close(&nss_ctx);
	return error;
}
