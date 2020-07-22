/*
 * Copyright (c) 2019-2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef __NLCFG_CAPWAP_H
#define __NLCFG_CAPWAP_H

#define NLCFG_CAPWAP_IPV4 4			/**< Ip version 4. */
#define NLCFG_CAPWAP_IPV6 6			/**< Ip version 6. */
#define NLCFG_CAPWAP_IP_FLOW_MODE_MAX 6		/**< Max value of ip flow mode. */
#define NLCFG_CAPWAP_WL_INFO_LEN 8		/**< Max length of wireless info. */
#define NLCFG_CAPWAP_IP_FLOW_MODE_ADD "add"	/**< Add ip flow rule. */
#define NLCFG_CAPWAP_IP_FLOW_MODE_DEL "del"	/**< Del ip flow rule. */
#define NLCFG_CAPWAP_DTLS_KEY_SZ 32		/**< Dtls key size. */
#define NLCFG_CAPWAP_PKT_TYPE_DATA		0x0002	/**< capwap pkt type. */
#define NLCFG_CAPWAP_PKT_TYPE_802_11		0x0010	/**< T=1, then set wbid=1 */
#define NLCFG_CAPWAP_PKT_TYPE_802_3		0x0020	/**< Data is in 802.3 format */
#define NLCFG_CAPWAP_PKT_TYPE_WIRELESS_INFO	0x0008	/**< W=1, wireless info present */

/*
 * nlcfg_capwap_cmd_type
 *	NLCFG capwap command_type
 */
enum nlcfg_capwap_cmd_type {
	NLCFG_CAPWAP_CMD_TYPE_UNKNOWN,		/**< Unknown commmand type. */
	NLCFG_CAPWAP_CMD_TYPE_CREATE_TUN,	/**< Creates a tunnel. */
	NLCFG_CAPWAP_CMD_TYPE_DESTROY_TUN,	/**< Destroys the tunnel created. */
	NLCFG_CAPWAP_CMD_TYPE_UPDATE_MTU,	/**< Updates the mtu of the capwap tunnel. */
	NLCFG_CAPWAP_CMD_TYPE_PERF,		/**< Enables or disables performance for capwap. */
	NLCFG_CAPWAP_CMD_TYPE_DTLS,		/**< Enables/creates or disables/destroys dtls tunnel for capwap tunnel. */
	NLCFG_CAPWAP_CMD_TYPE_TX_PACKETS,	/**< Helps in configuring parameters for sending traffic. */
	NLCFG_CAPWAP_CMD_TYPE_META_HEADER,	/**< Creates a meta header for capwap. */
	NLCFG_CAPWAP_CMD_TYPE_IP_FLOW,		/**< To add or delete an ip flow for capwap. */
	NLCFG_CAPWAP_CMD_TYPE_TX_KEEPALIVE,	/**< To enable or disable keepalive for capwap. */
	NLCFG_CAPWAP_CMD_TYPE_MAX		/**< Max number of commands type. */
};

/*
 * nlcfg_capwap_create_tun_params
 *	NLCFG tun_create parameters
 */
enum nlcfg_capwap_create_tun_params {
	NLCFG_CAPWAP_CREATE_TUN_PARAM_IP_VERSION,		/**< IPv4 or IPv6. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_SIP,			/**< Source IP address. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_DIP,			/**< Destination IP address. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_SPORT,			/**< Second tunnel src IP. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_DPORT,			/**< Second tunnel dest IP. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_REASM_TIMEOUT,		/**< Reassemblly timeout at decap side. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_MAX_FRAGMENTS,		/**< Max fragments expected. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_PATH_MTU,			/**< MTU for capwap tunnel. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_MAX_BUF_SZ,		/**< Max bufffer size for capwap pkt. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_STATS_TIMER,		/**< Interval timer in milliseconds. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_RPS,			/**< Host core you to run on. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_VLAN_CONFIG,		/**< VLAN is configured. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_PPPOE_CONFIG,		/**< PPPOE is configured. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_CSUM_ENABLE,		/**< UDPLITE header checksum is configured. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_UDP_TYPE,			/**< UDP or UDPLite. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_GMAC_IFNAME,		/**< WAN physical interface name to be used for tunnel. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_GMAC_IFMAC,		/**< WAN interface MAC address. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_INNER_TRUSTSEC_EN,	/**< Inner trustsec is enabled. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_OUTER_TRUSTSEC_EN,	/**< Outer trustsec is enabled. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_WIRELESS_QOS_EN,		/**< Qos is enabled. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_OUTER_SGT_VALUE,		/**< Outer security group tag value. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_BSSID,			/**< BSSID of the AP. */
	NLCFG_CAPWAP_CREATE_TUN_PARAM_MAX			/**< Max number of params. */
};

/*
 * nlcfg_capwap_destroy_tun_params
 *	NLCFG tun_destroy parameters
 */
enum nlcfg_capwap_destroy_tun_params {
	NLCFG_CAPWAP_DESTROY_TUN_PARAM_TUN_ID,		/**< Tunnel Id of the tunnel to be destroyed. */
	NLCFG_CAPWAP_DESTROY_TUN_PARAM_MAX		/**< Max number of destroy param. */
};

/*
 * nlcfg_capwap_update_mtu_params
 *	NLCFG update_mtu parameters
 */
enum nlcfg_capwap_update_mtu_params {
	NLCFG_CAPWAP_UPDATE_MTU_PARAM_PATH_MTU,		/**< MTU for capwap tunnel. */
	NLCFG_CAPWAP_UPDATE_MTU_PARAM_TUN_ID,		/**< Tunnel for which mtu is updated. */
	NLCFG_CAPWAP_UPDATE_MTU_PARAM_MAX		/**< Max number of update mtu params. */
};

/*
 * nlcfg_capwap_dtls_params
 *	NLCFG dtls parameters
 */
enum nlcfg_capwap_dtls_params {
	NLCFG_CAPWAP_DTLS_PARAM_ENABLE_DTLS,		/**< Enable dtls for capwap tunnel. */
	NLCFG_CAPWAP_DTLS_PARAM_IP_VERSION,		/**< IP version 4 or 6. */
	NLCFG_CAPWAP_DTLS_PARAM_SIP,			/**< Source ip of dtls tunnel. */
	NLCFG_CAPWAP_DTLS_PARAM_DIP,			/**< Destination ip of dtls tunnel. */
	NLCFG_CAPWAP_DTLS_PARAM_SPORT,			/**< Source port of dtls tunnel. */
	NLCFG_CAPWAP_DTLS_PARAM_DPORT,			/**< Destination port of dtls tunnel. */
	NLCFG_CAPWAP_DTLS_PARAM_FLAGS,			/**< Flags needed for dtls. */
	NLCFG_CAPWAP_DTLS_PARAM_TUN_ID,			/**< Tunnel id for which tunnel to be enabled. */
	NLCFG_CAPWAP_DTLS_PARAM_ENCAP_ALGO,		/**< Dtls encap algorithm. */
	NLCFG_CAPWAP_DTLS_PARAM_ENCAP_CIPHER_KEY,	/**< Cipher key data for encapsulation */
	NLCFG_CAPWAP_DTLS_PARAM_ENCAP_CIPHER_KEY_LEN,	/**< Cipher key length for encapsulation */
	NLCFG_CAPWAP_DTLS_PARAM_ENCAP_AUTH_KEY,		/**< Authentication key data for encapsulation */
	NLCFG_CAPWAP_DTLS_PARAM_ENCAP_AUTH_KEY_LEN,	/**< Authentication key length for encapsulation */
	NLCFG_CAPWAP_DTLS_PARAM_ENCAP_NONCE,		/**< Nonce data for encapsulation */
	NLCFG_CAPWAP_DTLS_PARAM_ENCAP_NONCE_LEN,	/**< Nonce data length for encapsulation */
	NLCFG_CAPWAP_DTLS_PARAM_ENCAP_VERS,		/**< DTLS encap side version */
	NLCFG_CAPWAP_DTLS_PARAM_ENCAP_EPOCH,		/**< Epochs for encap side */
	NLCFG_CAPWAP_DTLS_PARAM_ENCAP_IP_TTL,		/**< Time to live for IP */
	NLCFG_CAPWAP_DTLS_PARAM_DECAP_ALGO,		/**< Dtls decap side algo */
	NLCFG_CAPWAP_DTLS_PARAM_DECAP_CIPHER_KEY,	/**< Cipher key data for decapsulation */
	NLCFG_CAPWAP_DTLS_PARAM_DECAP_CIPHER_KEY_LEN,	/**< Cipher key length for decapsulation */
	NLCFG_CAPWAP_DTLS_PARAM_DECAP_AUTH_KEY,		/**< Authentication key data for decapsulation */
	NLCFG_CAPWAP_DTLS_PARAM_DECAP_AUTH_KEY_LEN,	/**< Authentication key length for decapsulation */
	NLCFG_CAPWAP_DTLS_PARAM_DECAP_NONCE,		/**< Nonce data for decapsulation */
	NLCFG_CAPWAP_DTLS_PARAM_DECAP_NONCE_LEN,	/**< Nonce data length for decapsulation */
	NLCFG_CAPWAP_DTLS_PARAM_WINDOW_SZ,		/**< Anti replay window size */
	NLCFG_CAPWAP_DTLS_PARAM_MAX			/**< Max number of dtls params. */
};

/*
 * nlcfg_capwap_performance_params
 *	NLCFG performance parameters
 */
enum nlcfg_capwap_performance_params {
	NLCFG_CAPWAP_PERF_PARAM_PERF_EN,	/**< Enable performance for capwap tunnel. */
	NLCFG_CAPWAP_PERF_PARAM_MAX		/**< Max number of performance params. */
};

/*
 * nlcfg_capwap_tx_packets_params
 *	NLCFG tx_packets parameters
 */
enum nlcfg_capwap_tx_packets_params {
	NLCFG_CAPWAP_TX_PACKETS_PARAM_PKT_SIZE,		/**< Length of packets you want to send. */
	NLCFG_CAPWAP_TX_PACKETS_PARAM_NUM_OF_PACKETS,	/**< Number of pkts to be sent. */
	NLCFG_CAPWAP_TX_PACKETS_PARAM_TUN_ID,		/**< Tunnel ID used for transmission. */
	NLCFG_CAPWAP_TX_PACKETS_PARAM_MAX		/**< Max number of tx packets params. */
};

/*
 * nlcfg_capwap_meta_header_params
 *	NLCFG create meta header parameters
 */
enum nlcfg_capwap_meta_header_params {
	NLCFG_CAPWAP_META_HEADER_PARAM_NWIRELESS,	/**< Number of wireless info sections. */
	NLCFG_CAPWAP_META_HEADER_PARAM_DSCP,		/**< DSCP value. */
	NLCFG_CAPWAP_META_HEADER_PARAM_VLAN_PCP,	/**< VLAN PCP is configured. */
	NLCFG_CAPWAP_META_HEADER_PARAM_TUN_ID,		/**< Tunnel Id. */
	NLCFG_CAPWAP_META_HEADER_PARAM_RID,		/**< Radio ID. */
	NLCFG_CAPWAP_META_HEADER_PARAM_WIRELESS_QOS,	/**< Wireless qos. */
	NLCFG_CAPWAP_META_HEADER_PARAM_FLOW_ID,		/**< Flow Id for the capwap ip flow. */
	NLCFG_CAPWAP_META_HEADER_PARAM_VAP_ID,		/**< Vap Id. */
	NLCFG_CAPWAP_META_HEADER_PARAM_PKT_TYPE,	/**< Capwap packet type. */
	NLCFG_CAPWAP_META_HEADER_PARAM_VERSION,		/**< Capwap version. */
	NLCFG_CAPWAP_META_HEADER_PARAM_OUTER_SGT,	/**< Inner security group tag value */
	NLCFG_CAPWAP_META_HEADER_PARAM_INNER_SGT,	/**< Inner security group tag value. */
	NLCFG_CAPWAP_META_HEADER_PARAM_WL_INFO,		/**< Wireless info. */
	NLCFG_CAPWAP_META_HEADER_PARAM_MAX,		/**< Max number of create meta header params. */
};

/*
 * nlcfg_capwap_ip_flow_params
 *	NLCFG IP flow parameters
 */
enum nlcfg_capwap_ip_flow_params {
	NLCFG_CAPWAP_IP_FLOW_PARAM_MODE,		/**< Add or del flow. */
	NLCFG_CAPWAP_IP_FLOW_PARAM_TUN_ID,		/**< Tunnel for which flow to be added. */
	NLCFG_CAPWAP_IP_FLOW_PARAM_IP_VERSION,		/**< IP version. */
	NLCFG_CAPWAP_IP_FLOW_PARAM_L4_PROTO,		/**< Layer 4 proto used(udp/udplite). */
	NLCFG_CAPWAP_IP_FLOW_PARAM_SPORT,		/**< Source port number. */
	NLCFG_CAPWAP_IP_FLOW_PARAM_DPORT,		/**< Destination port number. */
	NLCFG_CAPWAP_IP_FLOW_PARAM_SIP,			/**< Source IP address. */
	NLCFG_CAPWAP_IP_FLOW_PARAM_DIP,			/**< Destination IP address. */
	NLCFG_CAPWAP_IP_FLOW_PARAM_FLOW_ID,		/**< Flow Id associated with the rule. */
	NLCFG_CAPWAP_IP_FLOW_PARAM_MAX			/**< Max number of ip flow params. */
};

/*
 * nlcfg_capwap_tx_keepalive
 *	NLCFG set keepalive parameters
 */
enum nlcfg_capwap_tx_keepalive {
	NLCFG_CAPWAP_TX_KEEPALIVE_PARAM_TUN_ID,		/**< Tunnel for which keepalive to be activated. */
	NLCFG_CAPWAP_TX_KEEPALIVE_PARAM_TX_KEEPALIVE,		/**< Flag to check for dtls keepalive ON/OFF status. */
	NLCFG_CAPWAP_TX_KEEPALIVE_PARAM_MAX,			/**< Max number of keepalive params. */
};

/*
 * nlcfg_capwap_meta_header
 *	parameters to create meta header.
 */
struct nlcfg_capwap_meta_header {
	uint8_t version;	/**< CAPWAP version */
	uint8_t rid;		/**< Radio ID */
	uint16_t tun_id;	/**< Tunnel-ID */
	uint8_t dscp;		/**< DSCP value */
	uint8_t vlan_pcp;	/**< VLAN priority .P marking */
	uint16_t type;		/**< Type of CAPWAP packet & What was there in CAPWAP header */
	uint16_t nwireless;	/**< Number of wireless info sections in CAPWAP header */
	uint16_t wireless_qos;	/**< 802.11e qos info */
	uint16_t outer_sgt;	/**< Security Group Tag value in the TrustSec header */
	uint16_t inner_sgt;	/**< Security Group Tag value in the TrustSec header */
	uint32_t flow_id;	/**< Flow identification */
	uint16_t vap_id;	/**< VAP ID info */
	uint16_t magic;		/**< Magic for verification purpose. Use only for debugging */

	/*
	 * Put the wl_info at last so we don't have to do copy if 802.11 to 802.3 conversion did not happen.
	 */
	uint8_t wl_info[8];	/* Wireless info preserved from the original packet */
};

#endif /* __NLCFG_CAPWAP_H*/
