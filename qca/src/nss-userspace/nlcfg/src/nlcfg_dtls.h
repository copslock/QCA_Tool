/*
 * Copyright (c) 2019-2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef __NLCFG_DTLS_H
#define __NLCFG_DTLS_H

#define NLCFG_DTLS_IPV4 4
#define NLCFG_DTLS_IPV6 6
#define NLCFG_DTLS_DIR_ENCAP "encap"
#define NLCFG_DTLS_DIR_DECAP "decap"
#define NLCFG_DTLS_KEY_SZ 32
#define NLCFG_DTLS_DIR_SZ 6

/*
 * NLCFG dtls command_type
 */
enum nlcfg_dtls_cmd_type {
	NLCFG_DTLS_CMD_TYPE_UNKNOWN,			/**< Unknown commmand type. */
	NLCFG_DTLS_CMD_TYPE_CREATE_TUN,			/**< Creates a tunnel. */
	NLCFG_DTLS_CMD_TYPE_DESTROY_TUN,		/**< Destroys the tunnel created. */
	NLCFG_DTLS_CMD_TYPE_UPDATE_CONFIG,		/**< Updates the mtu of the dtls tunnel. */
	NLCFG_DTLS_CMD_TYPE_TX_PKTS,			/**< Helps in configuring parameters for sending traffic. */
	NLCFG_DTLS_CMD_TYPE_MAX				/**< Max number of commands type. */
};

/*
 * NLCFG tun_create parameters
 */
enum nlcfg_dtls_create_tun_params {
	NLCFG_DTLS_CREATE_TUN_PARAM_IP_VERSION,			/**< IP version: 4 or 6. */
	NLCFG_DTLS_CREATE_TUN_PARAM_SIP,			/**< Source IP address. */
	NLCFG_DTLS_CREATE_TUN_PARAM_DIP,			/**< Destination IP address. */
	NLCFG_DTLS_CREATE_TUN_PARAM_SPORT,			/**< Second tunnel src IP. */
	NLCFG_DTLS_CREATE_TUN_PARAM_DPORT,			/**< Second tunnel dest IP. */
	NLCFG_DTLS_CREATE_TUN_PARAM_GMAC_IFNAME,		/**< WAN physical interface name to be used for tunnel. */
	NLCFG_DTLS_CREATE_TUN_PARAM_GMAC_IFMAC,			/**< WAN interface MAC address. */
	NLCFG_DTLS_CREATE_TUN_PARAM_FLAGS,			/**< DTLS flags. */
	NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_ALGO,			/**< DTLS encap end algorithm */
	NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_CIPHER_KEY,		/**< Cipher key data for encapsulation */
	NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_CIPHER_KEY_LEN,	/**< Cipher key length for encapsulation */
	NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_AUTH_KEY,		/**< Authentication key data for encapsulation */
	NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_AUTH_KEY_LEN,		/**< Authentication key length for encapsulation */
	NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_NONCE,		/**< Nonce data for encapsulation */
	NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_NONCE_LEN,		/**< Nonce data length for encapsulation */
	NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_VERS,			/**< DTLS encap side version */
	NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_EPOCH,		/**< Epochs for encap side */
	NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_IP_TTL,		/**< Time to live for IP */
	NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_DSCP,			/**< DSCP */
	NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_DSCP_COPY,		/**< Flag to check if dscp needs to be copied. */
	NLCFG_DTLS_CREATE_TUN_PARAM_ENCAP_DF,			/**< Flag to check fragmentation. */
	NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_ALGO,			/**< Dtls decap side algo */
	NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_CIPHER_KEY,		/**< Cipher key data for decapsulation */
	NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_CIPHER_KEY_LEN,	/**< Cipher key length for decapsulation */
	NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_AUTH_KEY,		/**< Authentication key data for decapsulation */
	NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_AUTH_KEY_LEN,		/**< Authentication key length for decapsulation */
	NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_NONCE,		/**< Nonce data for decapsulation */
	NLCFG_DTLS_CREATE_TUN_PARAM_DECAP_NONCE_LEN,		/**< Nonce data length for decapsulation */
	NLCFG_DTLS_CREATE_TUN_PARAM_WINDOW_SZ,			/**< Anti replay window size */
	NLCFG_DTLS_CREATE_TUN_PARAM_FROM_MTU,			/**< Mtu of incoming interface */
	NLCFG_DTLS_CREATE_TUN_PARAM_TO_MTU,			/**< Mtu of outgoing interface */
	NLCFG_DTLS_CREATE_TUN_PARAM_MAX				/**< Max number of params. */
};

/*
 * NLCFG tun_destroy parameters
 */
enum nlcfg_dtls_destroy_tun_params {
	NLCFG_DTLS_DESTROY_TUN_PARAM_DEV_NAME,	/**< Dtls tunnel netdev name. */
	NLCFG_DTLS_DESTROY_TUN_PARAM_MAX	/**< Max number of destroy param. */
};

/*
 * NLCFG update_config parameters
 */
enum nlcfg_dtls_update_config_params {
	NLCFG_DTLS_UPDATE_CONFIG_PARAM_DEV_NAME,	/**< Dtls tunnel dev name */
	NLCFG_DTLS_UPDATE_CONFIG_PARAM_ALGO,		/**< Dtls decap side algo */
	NLCFG_DTLS_UPDATE_CONFIG_PARAM_CIPHER_KEY,	/**< Cipher key data for decapsulation */
	NLCFG_DTLS_UPDATE_CONFIG_PARAM_CIPHER_KEY_LEN,	/**< Cipher key length for decapsulation */
	NLCFG_DTLS_UPDATE_CONFIG_PARAM_AUTH_KEY,	/**< Authentication key data for decapsulation */
	NLCFG_DTLS_UPDATE_CONFIG_PARAM_AUTH_KEY_LEN,	/**< Authentication key length for decapsulation */
	NLCFG_DTLS_UPDATE_CONFIG_PARAM_NONCE,		/**< Nonce data for decapsulation */
	NLCFG_DTLS_UPDATE_CONFIG_PARAM_NONCE_LEN,	/**< Nonce data length for decapsulation */
	NLCFG_DTLS_UPDATE_CONFIG_PARAM_WINDOW_SZ,	/**< Anti replay window size */
	NLCFG_DTLS_UPDATE_CONFIG_PARAM_EPOCH,		/**< Epochs for encap side */
	NLCFG_DTLS_UPDATE_CONFIG_PARAM_DIR,		/**< Encap or decap side */
	NLCFG_DTLS_UPDATE_CONFIG_PARAM_MAX		/**< Max number of update mtu params. */
};

/*
 * NLCFG tx_pkts parameters
 */
enum nlcfg_dtls_tx_pkts_params {
	NLCFG_DTLS_TX_PKTS_PARAM_LOG_EN,		/**< Enable or disable log. */
	NLCFG_DTLS_TX_PKTS_PARAM_DEV_NAME,		/**< Tunnel dev name used for transmission. */
	NLCFG_DTLS_TX_PKTS_PARAM_PKT_SZ,		/**< Packet size to be sent. */
	NLCFG_DTLS_TX_PKTS_PARAM_IP_VERSION,		/**< IP version [4 or 6]. */
	NLCFG_DTLS_TX_PKTS_PARAM_NUM_PKTS,		/**< Number of pkts to be sent. */
	NLCFG_DTLS_TX_PKTS_PARAM_MAX			/**< Max number of tx packets params. */
};

#endif /* __NLCFG_DTLS_H*/
