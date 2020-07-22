/*
 * Copyright (c) 2019 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef __NLCFG_GRE_REDIR_H
#define __NLCFG_GRE_REDIR_H

#define NLCFG_GRE_REDIR_SRC_AND_DEST_MAC_MODE "src_and_dest_mac_mode"
#define NLCFG_GRE_REDIR_SRC_MAC_MODE "src_mac_mode"
#define NLCFG_GRE_REDIR_DEST_MAC_MODE "dest_mac_mode"
#define NLCFG_GRE_REDIR_IPV4 1
#define NLCFG_GRE_REDIR_IPV6 2

/*
 * NLCFG gre_redir command_type
 */
enum nlcfg_gre_redir_cmd_type {
	NLCFG_GRE_REDIR_CMD_TYPE_UNKNOWN,		/**< Unknown commmand type. */
	NLCFG_GRE_REDIR_CMD_TYPE_CREATE_TUN,		/**< Create a tunnel. */
	NLCFG_GRE_REDIR_CMD_TYPE_DESTROY_TUN,		/**< Destroy the tunnel created. */
	NLCFG_GRE_REDIR_CMD_TYPE_MAP,			/**< Map the nss interface and tunnel Id. */
	NLCFG_GRE_REDIR_CMD_TYPE_UNMAP,			/**< Unmap the nss interface and tunnel Id. */
	NLCFG_GRE_REDIR_CMD_TYPE_SET_NEXT_HOP,		/**< Used to set the next hop of ingress interface. */
	NLCFG_GRE_REDIR_CMD_TYPE_ADD_HASH, 		/**< Add a hash value. */
	NLCFG_GRE_REDIR_CMD_TYPE_DEL_HASH, 		/**< Del a hash value. */
	NLCFG_GRE_REDIR_CMD_TYPE_MAX			/**< Max number of commands type. */
};

/*
 * NLCFG gre_redir_tun_add parameters
 */
enum nlcfg_gre_redir_create_tun_param {
	NLCFG_GRE_REDIR_CREATE_TUN_PARAM_IPTYPE,	/**< Ip version. */
	NLCFG_GRE_REDIR_CREATE_TUN_PARAM_SIP,		/**< Source IP address. */
	NLCFG_GRE_REDIR_CREATE_TUN_PARAM_DIP,		/**< Destination IP address. */
	NLCFG_GRE_REDIR_CREATE_TUN_PARAM_SSIP,		/**< Second tunnel src IP. */
	NLCFG_GRE_REDIR_CREATE_TUN_PARAM_SDIP,		/**< Second tunnel dest IP. */
	NLCFG_GRE_REDIR_CREATE_TUN_PARAM_LAG_ENABLE,	/**< Indicates whether lag is enabled or not. */
	NLCFG_GRE_REDIR_CREATE_TUN_PARAM_HASHMODE,	/**< Helps in mapping the traffic based on
							  combination of src and dest mac. */
	NLCFG_GRE_REDIR_CREATE_TUN_PARAM_MAX		/**< Max number of params. */
};

/*
 * NLCFG GRE_REDIR_TUN_DEL parameters
 */
enum nlcfg_gre_redir_destroy_tun_param {
	NLCFG_GRE_REDIR_DESTROY_TUN_PARAM_NETDEV,	/**< Device name to be destroy. */
	NLCFG_GRE_REDIR_DESTROY_TUN_PARAM_MAX		/**< Max number of destroy param. */
};

/*
 * NLCFG map parameters
 */
enum nlcfg_gre_redir_map_param {
	NLCFG_GRE_REDIR_MAP_PARAM_VAP_NSS_IF,		/**< Vap nss interface name. */
	NLCFG_GRE_REDIR_MAP_PARAM_RID,			/**< Radio Id. */
	NLCFG_GRE_REDIR_MAP_PARAM_VID,			/**< Vap Id. */
	NLCFG_GRE_REDIR_MAP_PARAM_TUN_TYPE,		/**< Tunnel type. */
	NLCFG_GRE_REDIR_MAP_PARAM_SA_PAT,		/**< Ipsec security association parameters. */
	NLCFG_GRE_REDIR_MAP_PARAM_MAX			/**< Max number of map param. */
};

/*
 * NLCFG unmap parameters
 */
enum nlcfg_gre_redir_unmap_param {
	NLCFG_GRE_REDIR_UNMAP_PARAM_VAP_NSS_IF,		/**< Vap nss interface name. */
	NLCFG_GRE_REDIR_UNMAP_PARAM_RID,		/**< Radio Id. */
	NLCFG_GRE_REDIR_UNMAP_PARAM_VID,		/**< Vap Id. */
	NLCFG_GRE_REDIR_UNMAP_PARAM_MAX			/**< Max number of unmap params. */
};

/*
 * NLCFG set next hop parameters
 */
enum nlcfg_gre_redir_set_next_param {
	NLCFG_GRE_REDIR_SET_NEXT_PARAM_DEV_NAME,	/**< Dev whose next hop to be set. */
	NLCFG_GRE_REDIR_SET_NEXT_PARAM_NEXT_DEV_NAME,	/**< Dev to be set as next hop. */
	NLCFG_GRE_REDIR_SET_NEXT_PARAM_MODE,		/**< Sjack or wifi. */
	NLCFG_GRE_REDIR_SET_NEXT_PARAM_MAX		/**< Max number of set next params. */
};

/*
 * NLCFG add hash parameters
 */
enum nlcfg_gre_redir_add_hash {
	NLCFG_GRE_REDIR_ADD_HASH_PARAM_SMAC,		/**< MAC of source sta. */
	NLCFG_GRE_REDIR_ADD_HASH_PARAM_DMAC,		/**< MAC of destination sta. */
	NLCFG_GRE_REDIR_ADD_HASH_PARAM_SLAVE,		/**< Tunnel used to send traffic. */
	NLCFG_GRE_REDIR_ADD_HASH_PARAM_MAX		/**< Max number of add hash params. */
};

/*
 * NLCFG delete hash parameters
 */
enum nlcfg_gre_redir_del_hash {
	NLCFG_GRE_REDIR_DEL_HASH_PARAM_SMAC,		/**< Src mac of station. */
	NLCFG_GRE_REDIR_DEL_HASH_PARAM_DMAC,		/**< Dest mac of station. */
	NLCFG_GRE_REDIR_DEL_HASH_PARAM_MAX		/**< Max number of del hash params. */
};

/*
 * NLCFG gre_redir tunnel types.
 */
enum nlcfg_gre_redir_tunnel_type {
	NLCFG_GRE_REDIR_TUNNEL_TYPE_UNKNOWN,		/**< Reserved. */
	NLCFG_GRE_REDIR_TUNNEL_TYPE_TUN,		/**< Tunnel mode. */
	NLCFG_GRE_REDIR_TUNNEL_TYPE_DTUN,		/**< D-tunnel mode. */
	NLCFG_GRE_REDIR_TUNNEL_TYPE_SPLIT,		/**< Split mode. */
	NLCFG_GRE_REDIR_TUNNEL_TYPE_MAX			/**< Maximum tunnel type. */
};

/*
 * NLCFG gre_redir hash_mode types.
 */
enum nlcfg_gre_redir_hash_mode_type {
	NLCFG_GRE_REDIR_HASH_MODE_TYPE_SRC_AND_DEST,	/**< Mapping based on src and dest mac. */
	NLCFG_GRE_REDIR_HASH_MODE_TYPE_SRC,		/**< Mapping based on src mac only. */
	NLCFG_GRE_REDIR_HASH_MODE_TYPE_DEST,		/**< Mapping based on dest mac only. */
	NLCFG_GRE_REDIR_HASH_MODE_TYPE_MAX		/**< Max value of hash_mode */
};
#endif /* __NLCFG_GRE_REDIR_H*/
