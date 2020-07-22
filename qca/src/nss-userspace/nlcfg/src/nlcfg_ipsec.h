/*
 * Copyright (c) 2019 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef __NLCFG_IPSEC_H
#define __NLCFG_IPSEC_H

#define NLCFG_IPSEC_DIR_LEN 10

/*
 * NLCFG ipsec commands
 */
enum nlcfg_ipsec_cmd {
	NLCFG_IPSEC_CMD_ADD_TUNNEL,			/* Tunnel add */
	NLCFG_IPSEC_CMD_DELETE_TUNNEL,			/* Tunnel delete */
	NLCFG_IPSEC_CMD_ADD_SA,				/* Security association add */
	NLCFG_IPSEC_CMD_DEL_SA,				/* Security association delete */
	NLCFG_IPSEC_CMD_ADD_FLOW,			/* Flow add */
	NLCFG_IPSEC_CMD_DEL_FLOW,			/* Flow delete */
	NLCFG_IPSEC_CMD_MAX
};

/*
 * NLCFG tunnel del paramters
 */
enum nlcfg_ipsec_tun_del {
	NLCFG_IPSEC_TUN_DEL_IFNAME_TUN,			/* tunnel interface name */
	NLCFG_IPSEC_TUN_DEL_MAX
};

/*
 * NLCFG SA add parameters
 */
enum nlcfg_ipsec_sa_add {
	/* Interface name */
	NLCFG_IPSEC_SA_ADD_TUN_IFNAME,			/* Tunnel interface name */

	/* SA tuple */
	NLCFG_IPSEC_SA_ADD_TUPLE_IP_VER,		/* IP protocol version v4/v6 */
	NLCFG_IPSEC_SA_ADD_TUPLE_SIP,			/* Source IP address */
	NLCFG_IPSEC_SA_ADD_TUPLE_DIP,			/* Destination IP address */
	NLCFG_IPSEC_SA_ADD_TUPLE_SPI_IDX,		/* SPI index */
	NLCFG_IPSEC_SA_ADD_TUPLE_SPORT,			/* Source port */
	NLCFG_IPSEC_SA_ADD_TUPLE_DPORT,			/* Destination port */
	NLCFG_IPSEC_SA_ADD_TUPLE_NEXT_HDR,		/* Transport layer protocol */

	/* Common SA parameters */
	NLCFG_IPSEC_SA_ADD_DATA_ALGO,			/* Crypto algorithm */
	NLCFG_IPSEC_SA_ADD_DATA_CIPHER_KEY,		/* Cipher key */
	NLCFG_IPSEC_SA_ADD_DATA_AUTH_KEY,		/* Authentication key */
	NLCFG_IPSEC_SA_ADD_DATA_NONCE,			/* Nonce */
	NLCFG_IPSEC_SA_ADD_DATA_CIPHER_KEYLEN,		/* Cipher key length */
	NLCFG_IPSEC_SA_ADD_DATA_AUTH_KEYLEN,		/* Authentication key length */
	NLCFG_IPSEC_SA_ADD_DATA_NONCE_SIZE,		/* Nonce size */
	NLCFG_IPSEC_SA_ADD_DATA_CIDX,			/* Crypto session index */
	NLCFG_IPSEC_SA_ADD_DATA_BLK_LEN,		/* Cipher block length */
	NLCFG_IPSEC_SA_ADD_DATA_IV_LEN,			/* Cipher iv length */
	NLCFG_IPSEC_SA_ADD_DATA_ICV_LEN,		/* ICV length */
	NLCFG_IPSEC_SA_ADD_DATA_SKIP_TRAILER,		/* Skip trailer */
	NLCFG_IPSEC_SA_ADD_DATA_ENABLE_ESN,		/* Enable ESN flag */
	NLCFG_IPSEC_SA_ADD_DATA_ENABLE_NATT,		/* Enable NATT flag */
	NLCFG_IPSEC_SA_ADD_DATA_TRANSPORT_MODE,		/* Enable IPsec in transport mode. */
	NLCFG_IPSEC_SA_ADD_DATA_HAS_KEYS,		/* Crypto keys flag */
	NLCFG_IPSEC_SA_ADD_DATA_SA_TYPE,		/* SA type, encap or decap */

	/* Encapsulation SA parameters */
	NLCFG_IPSEC_SA_ADD_DATA_TTL_HOP_LIMIT,		/* TTL or hop limit */
	NLCFG_IPSEC_SA_ADD_DATA_DSCP,			/* Dscp */
	NLCFG_IPSEC_SA_ADD_DATA_DF,			/* Don't fragment flag */
	NLCFG_IPSEC_SA_ADD_DATA_COPY_DSCP,		/* Copy dscp flag */
	NLCFG_IPSEC_SA_ADD_DATA_COPY_DF,		/* Copy df flag */
	NLCFG_IPSEC_SA_ADD_DATA_TX_DEFAULT,		/* Make this as default SA */

	/* Decapsulation SA parameters */
	NLCFG_IPSEC_SA_ADD_DATA_REPLAY_THRESH,		/* Replay hash fail threshold */
	NLCFG_IPSEC_SA_ADD_DATA_REPLAY_WINDOW,		/* Anti-replay window size */

	NLCFG_IPSEC_SA_ADD_MAX
};

/*
 * NLCFG SA delete paramters
 */
enum nlcfg_ipsec_sa_del {
	/* Interface name */
	NLCFG_IPSEC_SA_DEL_TUN_IFNAME,			/* Tunnel interface name */

	/* Outer flow */
	NLCFG_IPSEC_SA_DEL_TUPLE_IP_VER,		/* IP protocol version v4/v6 */
	NLCFG_IPSEC_SA_DEL_TUPLE_SIP,			/* Source IP address */
	NLCFG_IPSEC_SA_DEL_TUPLE_DIP,			/* Destination IP address */
	NLCFG_IPSEC_SA_DEL_TUPLE_SPI_IDX,		/* SPI index */
	NLCFG_IPSEC_SA_DEL_TUPLE_SPORT,			/* Source port */
	NLCFG_IPSEC_SA_DEL_TUPLE_DPORT,			/* Destination port */
	NLCFG_IPSEC_SA_DEL_TUPLE_NEXT_HDR,		/* Transport layer protocol */

	NLCFG_IPSEC_SA_DEL_MAX
};

/*
 * NLCFG flow add paramters
 */
enum nlcfg_ipsec_flow_add {
	/* Interface name */
	NLCFG_IPSEC_FLOW_ADD_TUN_IFNAME,		/* Tunnel interface name */

	/* Flow tuple */
	NLCFG_IPSEC_FLOW_ADD_TUPLE_IP_VER,		/* IP protocol version v4/v6 */
	NLCFG_IPSEC_FLOW_ADD_TUPLE_SIP,			/* Source IP address */
	NLCFG_IPSEC_FLOW_ADD_TUPLE_DIP,			/* Destination IP address */
	NLCFG_IPSEC_FLOW_ADD_TUPLE_SPI_IDX,		/* SPI index */
	NLCFG_IPSEC_FLOW_ADD_TUPLE_SPORT,		/* Source port */
	NLCFG_IPSEC_FLOW_ADD_TUPLE_DPORT,		/* Destination port */
	NLCFG_IPSEC_FLOW_ADD_TUPLE_NEXT_HDR,		/* Transport layer protocol */
	NLCFG_IPSEC_FLOW_ADD_TUPLE_USER_PATTERN,	/* User defined */

	/* SA tuple */
	NLCFG_IPSEC_FLOW_ADD_SA_IP_VER,			/* IP protocol version v4/v6 */
	NLCFG_IPSEC_FLOW_ADD_SA_SIP,			/* Source IP address */
	NLCFG_IPSEC_FLOW_ADD_SA_DIP,			/* Destination IP address */
	NLCFG_IPSEC_FLOW_ADD_SA_SPI_IDX,		/* SPI index */
	NLCFG_IPSEC_FLOW_ADD_SA_SPORT,			/* Source port */
	NLCFG_IPSEC_FLOW_ADD_SA_DPORT,			/* Destination port */
	NLCFG_IPSEC_FLOW_ADD_SA_NEXT_HDR,		/* Transport layer protocol */

	NLCFG_IPSEC_FLOW_ADD_MAX
};

/*
 * NLCFG flow delete paramters
 */
enum nlcfg_ipsec_flow_del {
	/* Interface name */
	NLCFG_IPSEC_FLOW_DEL_TUN_IFNAME,		/* Tunnel interface name */

	/* Flow tuple */
	NLCFG_IPSEC_FLOW_DEL_TUPLE_IP_VER,		/* IP protocol version v4/v6 */
	NLCFG_IPSEC_FLOW_DEL_TUPLE_SIP,			/* Source IP address */
	NLCFG_IPSEC_FLOW_DEL_TUPLE_DIP,			/* Destination IP address */
	NLCFG_IPSEC_FLOW_DEL_TUPLE_SPI_IDX,		/* SPI index */
	NLCFG_IPSEC_FLOW_DEL_TUPLE_SPORT,		/* Source port */
	NLCFG_IPSEC_FLOW_DEL_TUPLE_DPORT,		/* Destination port */
	NLCFG_IPSEC_FLOW_DEL_TUPLE_NEXT_HDR,		/* Transport layer protocol */
	NLCFG_IPSEC_FLOW_DEL_TUPLE_USER_PATTERN,	/* User defined */

	/* SA tuple */
	NLCFG_IPSEC_FLOW_DEL_SA_IP_VER,			/* IP protocol version v4/v6 */
	NLCFG_IPSEC_FLOW_DEL_SA_SIP,			/* Source IP address */
	NLCFG_IPSEC_FLOW_DEL_SA_DIP,			/* Destination IP address */
	NLCFG_IPSEC_FLOW_DEL_SA_SPI_IDX,		/* SPI index */
	NLCFG_IPSEC_FLOW_DEL_SA_SPORT,			/* Source port */
	NLCFG_IPSEC_FLOW_DEL_SA_DPORT,			/* Destination port */
	NLCFG_IPSEC_FLOW_DEL_SA_NEXT_HDR,		/* Transport layer protocol */

	NLCFG_IPSEC_FLOW_DEL_MAX
};

#endif /* __NLCFG_IPSEC_H*/
