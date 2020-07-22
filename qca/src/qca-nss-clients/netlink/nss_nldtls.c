/*
 **************************************************************************
 * Copyright (c) 2015-2016,2018-2020 The Linux Foundation. All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

#include <crypto/internal/skcipher.h>
#include <linux/etherdevice.h>
#include <linux/icmp.h>
#include <linux/inet.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <net/genetlink.h>
#include <net/ip6_checksum.h>
#include <net/udp.h>
#include <nss_api_if.h>
#include <nss_dtls.h>
#include <nss_dtlsmgr.h>
#include <nss_dtls_cmn.h>
#include <nss_nlcmn_if.h>
#include <nss_nl_if.h>
#include "nss_nl.h"
#include "nss_nldtls.h"
#include "nss_nldtls_if.h"

/*
 * Initializing the global variables
 */
static struct nss_nldtls_gbl_ctx gbl_ctx = {
	.lock = __SPIN_LOCK_UNLOCKED(lock),
	.num_tun = ATOMIC_INIT(0),
	.dtls_list_head = LIST_HEAD_INIT(gbl_ctx.dtls_list_head),
	.log_en = false
};

/*
 * nss_nldtls_family_mcgrp
 *	Multicast group for sending message status & events
 */
static const struct genl_multicast_group nss_nldtls_family_mcgrp[] = {
	{.name = NSS_NLDTLS_MCAST_GRP},
};

/*
 * nss_nldtls_family
 *	Dtls family definition
 */
struct genl_family nss_nldtls_family = {
	.id = GENL_ID_GENERATE,				/* Auto generate ID */
	.name = NSS_NLDTLS_FAMILY,			/* family name string */
	.hdrsize = sizeof(struct nss_nldtls_rule),	/* NSS NETLINK dtls rule */
	.version = NSS_NL_VER,				/* Set it to NSS_NLDTLS version */
	.maxattr = NSS_NLDTLS_CMD_TYPE_MAX,		/* maximum commands supported */
	.netnsok = true,
	.pre_doit = NULL,
	.post_doit = NULL,
};

/*
 * nss_nldtls_find_dtls_tun_gbl_ctx()
 *	Returns the global context object of a tunnel
 */
static struct nss_nldtls_tun_ctx *nss_nldtls_find_dtls_tun_gbl_ctx(struct net_device *dev)
{
	struct nss_nldtls_tun_ctx *entry;

	spin_lock(&gbl_ctx.lock);
	list_for_each_entry(entry, &gbl_ctx.dtls_list_head, list) {
		if (!strncmp(entry->dev_name, dev->name, IFNAMSIZ)) {
			spin_unlock(&gbl_ctx.lock);
			return entry;
		}
	}

	spin_unlock(&gbl_ctx.lock);
	return NULL;
}

/*
 * nss_nldtls_data_cb()
 *	Data callback function for dtls
 */
static void __maybe_unused nss_nldtls_data_cb(void *app_data __maybe_unused, struct sk_buff *skb __maybe_unused)
{
	static bool first_pkt;
	unsigned long long duration;
	ktime_t delta;

	if (unlikely(!first_pkt)) {
		gbl_ctx.first_rx_pkt_time = ktime_get();
		first_pkt = true;
	}

	/*
	 * Remove meta header
	 */
	skb_pull(skb, sizeof(struct nss_dtlsmgr_metadata));
	gbl_ctx.last_rx_pkt_time = ktime_get();

	if (unlikely(gbl_ctx.log_en)) {
		struct net_device *dev;

		delta = ktime_sub(gbl_ctx.last_rx_pkt_time, gbl_ctx.first_rx_pkt_time);
		duration = (unsigned long long) ktime_to_ns(delta) >> 10;
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, skb->data, 32);
		dev = dev_get_by_index(&init_net, skb->skb_iif);
		if (dev) {
			nss_nl_error("In dev = %s, out_dev = %s\n", dev->name, skb->dev->name);
			dev_put(dev);
		}

		nss_nl_info("%p: DTLS RX (%s) pkt len = %d udp_csum = %s rx_time: %llu\n", skb,
				skb->dev->name, skb->len, udp_lib_checksum_complete(skb) ?
				"invalid" : "valid", duration);
	}

	dev_kfree_skb_any(skb);
}

/*
 * nss_nldtls_dev_rx_handler()
 *	Common rx handler for all dtls dev
 */
static rx_handler_result_t nss_nldtls_dev_rx_handler(struct sk_buff **pskb)
{
	static bool first_pkt;
	unsigned long long duration;
	struct sk_buff *skb = *pskb;
	ktime_t delta;

	if (unlikely(!first_pkt)) {
		gbl_ctx.first_rx_pkt_time = ktime_get();
		first_pkt = true;
	}

	gbl_ctx.last_rx_pkt_time = ktime_get();
	if (unlikely(gbl_ctx.log_en)) {
		struct net_device *dev;

		delta = ktime_sub(gbl_ctx.last_rx_pkt_time, gbl_ctx.first_rx_pkt_time);
		duration = (unsigned long long) ktime_to_ns(delta) >> 10;
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, skb->data, 64);
		dev = dev_get_by_index(&init_net, skb->skb_iif);
		if (dev) {
			nss_nl_info("%p: in_dev = %s, out_dev = %s\n", skb, dev->name, skb->dev->name);
			dev_put(dev);
		}

		nss_nl_info("%p: DTLS RX (%s) pkt len = %d udp_csum = %s rx_time: %llu\n", skb,
				skb->dev->name, skb->len, udp_lib_checksum_complete(skb) ?
				"invalid" : "valid", duration);
	}

	dev_kfree_skb_any(skb);
	return RX_HANDLER_CONSUMED;
}

/*
 * nss_nldtls_create_ipv4_rule()
 *	Create a nss entry to accelerate the given IPv4 connection
 */
static int nss_nldtls_create_ipv4_rule(struct nss_ipv4_create *unic, uint16_t rule_flags)
{
	struct nss_ipv4_rule_create_msg *nircm;
	struct nss_ctx_instance *nss_ctx;
	struct nss_ipv4_msg nim;
	nss_tx_status_t status;

	nss_ctx = nss_ipv4_get_mgr();
	if (!nss_ctx) {
		nss_nl_info("%p: Couldn't get IPv4 ctx\n", unic);
		return -1;
	}

	nss_nl_info("%p: IPv4 rule: src:%pI4h:%d dst:%pI4h:%d p:%d\n",
	      unic, &unic->src_ip, unic->src_port,
	      &unic->dest_ip, unic->dest_port, unic->protocol);

	memset(&nim, 0, sizeof (struct nss_ipv4_msg));
	nss_ipv4_msg_init(&nim, NSS_IPV4_RX_INTERFACE,
			  NSS_IPV4_TX_CREATE_RULE_MSG,
			  sizeof(struct nss_ipv4_rule_create_msg), NULL, NULL);

	nircm = &nim.msg.rule_create;
	nircm->valid_flags = 0;
	nircm->rule_flags = 0;

	/*
	 * Copy over the 5 tuple details.
	 */
	nircm->tuple.protocol = (uint8_t)unic->protocol;
	nircm->tuple.flow_ip = unic->src_ip;
	nircm->tuple.flow_ident = (uint32_t)unic->src_port;
	nircm->tuple.return_ip = unic->dest_ip;
	nircm->tuple.return_ident = (uint32_t)unic->dest_port;

	/*
	 * Copy over the connection rules and set the CONN_VALID flag
	 */
	nircm->conn_rule.flow_interface_num = unic->src_interface_num;
	nircm->conn_rule.flow_mtu = unic->from_mtu;
	nircm->conn_rule.flow_ip_xlate = unic->src_ip_xlate;
	nircm->conn_rule.flow_ident_xlate = (uint32_t)unic->src_port_xlate;
	memcpy(nircm->conn_rule.flow_mac, unic->src_mac, 6);
	nircm->conn_rule.return_interface_num = unic->dest_interface_num;
	nircm->conn_rule.return_mtu = unic->to_mtu;
	nircm->conn_rule.return_ip_xlate = unic->dest_ip_xlate;
	nircm->conn_rule.return_ident_xlate = (uint32_t)unic->dest_port_xlate;
	if ((nircm->tuple.return_ip != nircm->conn_rule.return_ip_xlate) ||
	    (nircm->tuple.return_ident != nircm->conn_rule.return_ident_xlate))
		memcpy(nircm->conn_rule.return_mac, unic->dest_mac_xlate, 6);
	else
		memcpy(nircm->conn_rule.return_mac, unic->dest_mac, 6);

	/*
	 * Copy over the DSCP rule parameters
	 */
	if (unic->flags & NSS_IPV4_CREATE_FLAG_DSCP_MARKING) {
		nircm->dscp_rule.flow_dscp = unic->flow_dscp;
		nircm->dscp_rule.return_dscp = unic->return_dscp;
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_DSCP_MARKING;
		nircm->valid_flags |= NSS_IPV4_RULE_CREATE_DSCP_MARKING_VALID;
	}

	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_CONN_VALID;

	/*
	 * Copy over the pppoe rules and set the PPPOE_VALID flag.
	 */
	nircm->pppoe_rule.flow_if_exist = unic->flow_pppoe_if_exist;
	nircm->pppoe_rule.flow_if_num = unic->flow_pppoe_if_num;
	nircm->pppoe_rule.return_if_exist = unic->return_pppoe_if_exist;
	nircm->pppoe_rule.return_if_num = unic->return_pppoe_if_num;
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_PPPOE_VALID;

	/*
	 * Copy over the vlan rules and set the VLAN_VALID flag
	 */
	nircm->vlan_primary_rule.ingress_vlan_tag = unic->in_vlan_tag[0];
	nircm->vlan_primary_rule.egress_vlan_tag = unic->out_vlan_tag[0];
	nircm->vlan_secondary_rule.ingress_vlan_tag = unic->in_vlan_tag[1];
	nircm->vlan_secondary_rule.egress_vlan_tag = unic->out_vlan_tag[1];
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_VLAN_VALID;

	/*
	 * Copy over the qos rules and set the QOS_VALID flag
	 */
	nircm->qos_rule.flow_qos_tag = unic->flow_qos_tag;
	nircm->qos_rule.return_qos_tag = unic->return_qos_tag;
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_QOS_VALID;

	if (unic->flags & NSS_IPV4_CREATE_FLAG_NO_SEQ_CHECK)
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_NO_SEQ_CHECK;

	if (unic->flags & NSS_IPV4_CREATE_FLAG_BRIDGE_FLOW)
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_BRIDGE_FLOW;

	if (unic->flags & NSS_IPV4_CREATE_FLAG_ROUTED)
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_ROUTED;

	/*
	 * Set the flag NSS_IPV4_RULE_CREATE_FLAG_ICMP_NO_CME_FLUSH so that
	 * rule is not flushed when NSS FW receives ICMP errors/packets.
	 */
	nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_ICMP_NO_CME_FLUSH;

	/*
	 * Add any other additional flags which caller has requested.
	 * For example: update MTU
	 */
	nircm->rule_flags |= rule_flags;

	status = nss_ipv4_tx(nss_ctx, &nim);
	if (status != NSS_TX_SUCCESS) {
		nss_nl_info("%p: Create IPv4 message failed %d\n", nss_ctx, status);
	}

	return 0;
}

/*
 * nss_nldtls_create_ipv6_rule()
 *	Create a nss entry to accelerate the given IPV6 connection
 */
static int nss_nldtls_create_ipv6_rule(struct nss_ipv6_create *unic, uint16_t rule_flags)
{
	struct nss_ipv6_rule_create_msg *nircm;
	struct nss_ctx_instance *nss_ctx;
	struct nss_ipv6_msg nim;
	nss_tx_status_t status;

	nss_ctx = nss_ipv6_get_mgr();
	if (!nss_ctx) {
		nss_nl_info("%p: Couldn't get IPv6 ctx\n", unic);
		return -1;
	}

	nss_nl_info("%p: Create IPv6 rule: %pI6:%d %pI6:%d p:%d\n",
	      unic, unic->src_ip, unic->src_port, unic->dest_ip,
	      unic->dest_port, unic->protocol);

	memset(&nim, 0, sizeof (struct nss_ipv6_msg));
	nss_ipv6_msg_init(&nim, NSS_IPV6_RX_INTERFACE,
			  NSS_IPV6_TX_CREATE_RULE_MSG,
			  sizeof(struct nss_ipv6_rule_create_msg), NULL, NULL);

	nircm = &nim.msg.rule_create;
	nircm->rule_flags = 0;
	nircm->valid_flags = 0;

	/*
	 * Copy over the 5 tuple information.
	 */
	nircm->tuple.protocol = (uint8_t)unic->protocol;
	memcpy(nircm->tuple.flow_ip, unic->src_ip, sizeof(nircm->tuple.flow_ip));
	memcpy(nircm->tuple.return_ip, unic->dest_ip, sizeof(nircm->tuple.return_ip));
	nircm->tuple.flow_ident = (uint32_t)unic->src_port;
	nircm->tuple.return_ident = (uint32_t)unic->dest_port;

	/*
	 * Copy over the connection rules and set CONN_VALID flag
	 */
	nircm->conn_rule.flow_interface_num = unic->src_interface_num;
	nircm->conn_rule.flow_mtu = unic->from_mtu;
	nircm->conn_rule.return_interface_num = unic->dest_interface_num;
	nircm->conn_rule.return_mtu = unic->to_mtu;
	memcpy(nircm->conn_rule.flow_mac, unic->src_mac, 6);
	memcpy(nircm->conn_rule.return_mac, unic->dest_mac, 6);
	nircm->valid_flags |= NSS_IPV6_RULE_CREATE_CONN_VALID;

	/*
	 * Copy over the DSCP rule parameters
	 */
	if (unic->flags & NSS_IPV6_CREATE_FLAG_DSCP_MARKING) {
		nircm->dscp_rule.flow_dscp = unic->flow_dscp;
		nircm->dscp_rule.return_dscp = unic->return_dscp;
		nircm->rule_flags |= NSS_IPV6_RULE_CREATE_FLAG_DSCP_MARKING;
		nircm->valid_flags |= NSS_IPV6_RULE_CREATE_DSCP_MARKING_VALID;
	}

	/*
	 * Copy over the pppoe rules and set PPPOE_VALID flag
	 */
	nircm->pppoe_rule.flow_if_exist = unic->flow_pppoe_if_exist;
	nircm->pppoe_rule.flow_if_num = unic->flow_pppoe_if_num;
	nircm->pppoe_rule.return_if_exist = unic->return_pppoe_if_exist;
	nircm->pppoe_rule.return_if_num = unic->return_pppoe_if_num;
	nircm->valid_flags |= NSS_IPV6_RULE_CREATE_PPPOE_VALID;

	/*
	 * Copy over the tcp rules and set TCP_VALID flag
	 */
	nircm->tcp_rule.flow_window_scale = unic->flow_window_scale;
	nircm->tcp_rule.flow_max_window = unic->flow_max_window;
	nircm->tcp_rule.flow_end = unic->flow_end;
	nircm->tcp_rule.flow_max_end = unic->flow_max_end;
	nircm->tcp_rule.return_window_scale = unic->return_window_scale;
	nircm->tcp_rule.return_max_window = unic->return_max_window;
	nircm->tcp_rule.return_end = unic->return_end;
	nircm->tcp_rule.return_max_end = unic->return_max_end;
	nircm->valid_flags |= NSS_IPV6_RULE_CREATE_TCP_VALID;

	/*
	 * Copy over the vlan rules and set the VLAN_VALID flag
	 */
	nircm->vlan_primary_rule.egress_vlan_tag = unic->out_vlan_tag[0];
	nircm->vlan_primary_rule.ingress_vlan_tag = unic->in_vlan_tag[0];
	nircm->vlan_secondary_rule.egress_vlan_tag = unic->out_vlan_tag[1];
	nircm->vlan_secondary_rule.ingress_vlan_tag = unic->in_vlan_tag[1];
	nircm->valid_flags |= NSS_IPV6_RULE_CREATE_VLAN_VALID;

	/*
	 * Copy over the qos rules and set the QOS_VALID flag
	 */
	nircm->qos_rule.flow_qos_tag = unic->flow_qos_tag;
	nircm->qos_rule.return_qos_tag = unic->return_qos_tag;
	nircm->valid_flags |= NSS_IPV6_RULE_CREATE_QOS_VALID;

	if (unic->flags & NSS_IPV6_CREATE_FLAG_NO_SEQ_CHECK)
		nircm->rule_flags |= NSS_IPV6_RULE_CREATE_FLAG_NO_SEQ_CHECK;

	if (unic->flags & NSS_IPV6_CREATE_FLAG_BRIDGE_FLOW)
		nircm->rule_flags |= NSS_IPV6_RULE_CREATE_FLAG_BRIDGE_FLOW;

	if (unic->flags & NSS_IPV6_CREATE_FLAG_ROUTED)
		nircm->rule_flags |= NSS_IPV6_RULE_CREATE_FLAG_ROUTED;

	/*
	 * Set the flag NSS_IPV4_RULE_CREATE_FLAG_ICMP_NO_CME_FLUSH so that
	 * rule is not flushed when NSS FW receives ICMP errors/packets.
	 */
	nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_ICMP_NO_CME_FLUSH;

	/*
	 * Add any other additional flags which caller has requested.
	 * For example: update MTU
	 */
	nircm->rule_flags |= rule_flags;

	status = nss_ipv6_tx(nss_ctx, &nim);
	if (status != NSS_TX_SUCCESS) {
		nss_nl_info("%p: Create IPv4 message failed %d\n", nss_ctx, status);
	}

	return 0;
}

/*
 * nss_nldtls_create_session()
 *	Create a DTLS session through dtlsmgr driver API.
 */
static struct net_device *nss_nldtls_create_session(struct nss_nldtls_rule *nl_rule, uint32_t flags)
{
	struct nss_nldtls_tun_ctx *dtls_tun_data;
	struct nss_dtlsmgr_config dcfg;
	struct nss_dtlsmgr_ctx *ctx;
	struct net_device *ndev;
	uint8_t algo;
	int err;

	if (atomic_read(&gbl_ctx.num_tun) >= NSS_NLDTLS_MAX_TUNNELS) {
		nss_nl_error("Max number of tunnels exhausted: 32\n");
		return NULL;
	}

	memset(&dcfg, 0, sizeof(struct nss_dtlsmgr_config));
	algo = nl_rule->msg.create.encap.crypto.algo;
	dcfg.flags = flags;
	if (algo == NSS_DTLSMGR_ALGO_AES_GCM)
		dcfg.flags |= NSS_DTLSMGR_CIPHER_MODE_GCM;

	dcfg.app_data = NULL;
	dcfg.notify = NULL;
	dcfg.data = NULL;

	/*
	 * Encap configuration
	 */
	memcpy((void *)&dcfg.encap, (void *)&nl_rule->msg.create.encap, sizeof(struct nss_dtlsmgr_encap_config));

	/*
	 * Decap configuration
	 */
	memcpy((void *)&dcfg.decap, (void *)&nl_rule->msg.create.decap, sizeof(struct nss_dtlsmgr_decap_config));
	dcfg.decap.nexthop_ifnum = NSS_N2H_INTERFACE;

	/*
	 * Create a dtls session
	 */
	ndev = nss_dtlsmgr_session_create(&dcfg);
	if (!ndev) {
		nss_nl_error("Failed to create DTLS session\n");
		return NULL;
	}

	ctx = netdev_priv(ndev);
	/*
	 * Register rx handler for dtls netdev
	 */
	rtnl_lock();
	err = netdev_rx_handler_register(ndev, nss_nldtls_dev_rx_handler, 0);
	if (err) {
		rtnl_unlock();
		nss_dtlsmgr_session_destroy(ndev);
		nss_nl_error("%p: Failed to register rx handler\n", ctx);
		return NULL;
	}

	rtnl_unlock();

	/*
	 * Prepare data for current tunnel
	 */
	dtls_tun_data = (struct nss_nldtls_tun_ctx *)kmalloc(sizeof(*dtls_tun_data), GFP_KERNEL);
	dtls_tun_data->nl_rule = nl_rule;
	memcpy(dtls_tun_data->dev_name, ndev->name, IFNAMSIZ);

	/*
	 * Adding tunnel to global list of tunnels
	 */
	spin_lock(&gbl_ctx.lock);
	list_add_tail(&dtls_tun_data->list, &gbl_ctx.dtls_list_head);
	spin_unlock(&gbl_ctx.lock);

	nss_nl_info("%p: Succesfully created dtls session.\n", ctx);
	return ndev;
}

/*
 * nss_nldtls_create_ipv4_rule_entry()
 *	Handler for adding ipv4 rule entry for dtls session
 */
static int nss_nldtls_create_ipv4_rule_entry(struct net_device *dtls_dev, struct nss_nldtls_rule *nl_rule)
{
	struct nss_ipv4_create ipv4;
	struct net_device *ndev;
	uint32_t if_num;

	/*
	 * Configure IPv4 rule
	 */
	memset(&ipv4, 0, sizeof(struct nss_ipv4_create));

	ipv4.from_mtu = nl_rule->msg.create.from_mtu;
	ipv4.to_mtu = nl_rule->msg.create.to_mtu;

	ndev = dev_get_by_name(&init_net, &nl_rule->msg.create.gmac_ifname[0]);
	if (ndev == NULL) {
		nss_nl_error("Can't find %s netdev\n", nl_rule->msg.create.gmac_ifname);
		return -EINVAL;
	}

	if_num = nss_cmn_get_interface_number_by_dev(ndev);
	ipv4.src_interface_num = if_num;
	ipv4.dest_interface_num = nss_dtlsmgr_get_interface(dtls_dev, NSS_DTLSMGR_INTERFACE_TYPE_OUTER);

	ipv4.src_port = nl_rule->msg.create.encap.dport;
	ipv4.src_port_xlate = nl_rule->msg.create.encap.dport;
	ipv4.src_ip = nl_rule->msg.create.encap.dip[0];
	ipv4.src_ip_xlate = nl_rule->msg.create.encap.dip[0];

	ipv4.dest_ip = nl_rule->msg.create.encap.sip[0];
	ipv4.dest_ip_xlate = nl_rule->msg.create.encap.sip[0];
	ipv4.dest_port = nl_rule->msg.create.encap.sport;
	ipv4.dest_port_xlate = nl_rule->msg.create.encap.sport;

	ipv4.protocol = IPPROTO_UDP;
	ipv4.in_vlan_tag[0] = NSS_NLDTLS_VLAN_INVALID;
	ipv4.out_vlan_tag[0] = NSS_NLDTLS_VLAN_INVALID;
	ipv4.in_vlan_tag[1] = NSS_NLDTLS_VLAN_INVALID;
	ipv4.out_vlan_tag[1] = NSS_NLDTLS_VLAN_INVALID;

	memcpy(&ipv4.src_mac[0], &nl_rule->msg.create.gmac_ifmac[0], sizeof(ipv4.src_mac));

	/*
	 * Create an ipv4 rule entry
	 */
	return nss_nldtls_create_ipv4_rule(&ipv4, 0);
}

/*
 * nss_nldtls_create_ipv6_rule_entry()
 *	Handler to add an ipv6 rule entry for dtls session
 */
static int nss_nldtls_create_ipv6_rule_entry(struct net_device *dtls_dev, struct nss_nldtls_rule *nl_rule)
{
	struct nss_ipv6_create ipv6;
	struct net_device *ndev;
	uint32_t if_num;

	/*
	 * Configure IPv6 rule
	 */
	memset(&ipv6, 0, sizeof(struct nss_ipv6_create));

	ipv6.from_mtu = nl_rule->msg.create.from_mtu;
	ipv6.to_mtu = nl_rule->msg.create.to_mtu;

	ndev = dev_get_by_name(&init_net, &nl_rule->msg.create.gmac_ifname[0]);
	if (ndev == NULL) {
		nss_nl_error("Can't find %s netdev\n", nl_rule->msg.create.gmac_ifname);
		return -EINVAL;
	}

	if_num = nss_cmn_get_interface_number_by_dev(ndev);
	ipv6.src_interface_num = if_num;
	ipv6.dest_interface_num = nss_dtlsmgr_get_interface(dtls_dev, NSS_DTLSMGR_INTERFACE_TYPE_OUTER);
	ipv6.src_port = nl_rule->msg.create.encap.dport;
	ipv6.dest_port = nl_rule->msg.create.encap.sport;

	/*
	 * Configure IPv6 rule
	 */
	memcpy(ipv6.src_ip, nl_rule->msg.create.encap.dip, sizeof(ipv6.src_ip));
	memcpy(ipv6.dest_ip, nl_rule->msg.create.encap.sip, sizeof(ipv6.dest_ip));
	ipv6.protocol = IPPROTO_UDP;

	ipv6.in_vlan_tag[0] = NSS_NLDTLS_VLAN_INVALID;
	ipv6.in_vlan_tag[1] = NSS_NLDTLS_VLAN_INVALID;
	ipv6.out_vlan_tag[1] = NSS_NLDTLS_VLAN_INVALID;
	ipv6.out_vlan_tag[0] = NSS_NLDTLS_VLAN_INVALID;

	memcpy(&ipv6.src_mac[0], &nl_rule->msg.create.gmac_ifmac[0], sizeof(ipv6.src_mac));

	/*
	 * Create an ipv6 rule entry
	 */
	return nss_nldtls_create_ipv6_rule(&ipv6, 0);
}

/*
 * nss_nldtls_destroy_tun()
 *	Common handler for tunnel destroy
 */
static int nss_nldtls_destroy_tun(struct net_device *dtls_ndev)
{
	struct nss_nldtls_tun_ctx *dtls_tun_data;

	dtls_tun_data = nss_nldtls_find_dtls_tun_gbl_ctx(dtls_ndev);
	if (!dtls_tun_data) {
		nss_nl_error("Unable to find context of the tunnel: %s\n", dtls_ndev->name);
		dev_put(dtls_ndev);
		return -EAGAIN;
	}

	/*
	 * Delete tunnel node from the list
	 */
	list_del_init(&dtls_tun_data->list);
	kfree(dtls_tun_data);
	dev_put(dtls_ndev);

	/*
	 * Destroy the dtls session
	 */
	if (nss_dtlsmgr_session_destroy(dtls_ndev)) {
		nss_nl_error("Unable to destroy the tunnel: %s\n", dtls_ndev->name);
		return -EAGAIN;
	}

	return 0;
}

/*
 * nss_nldtls_ops_create_tun()
 *	Handler for creating tunnel
 */
static int nss_nldtls_ops_create_tun(struct sk_buff *skb, struct genl_info *info)
{
	struct nss_nldtls_rule *nl_rule;
	struct net_device *dtls_dev;
	struct nss_nlcmn *nl_cm;
	int ret = 0;

	/*
	 * Extract the message payload
	 */
	nl_cm = nss_nl_get_msg(&nss_nldtls_family, info, NSS_NLDTLS_CMD_TYPE_CREATE_TUN);
	if (!nl_cm) {
		nss_nl_error("%p: Unable to extract create tunnel data\n", skb);
		return -EINVAL;
	}

	/*
	 * Message validation required before accepting the configuration
	 */
	nl_rule = container_of(nl_cm, struct nss_nldtls_rule, cm);

	/*
	 * Create tunnel based on ip version
	 */
	if (nl_rule->msg.create.ip_version == NSS_NLDTLS_IP_VERS_4) {
		dtls_dev = nss_nldtls_create_session(nl_rule, NSS_NLDTLS_IPV4_SESSION);
		if (!dtls_dev) {
			nss_nl_error("%p: Unable to create dtls session for v4\n", skb);
			return -EINVAL;
		}

		/*
		 * Create IPv4 rule entry
		 */
		ret = nss_nldtls_create_ipv4_rule_entry(dtls_dev, nl_rule);
		if (ret < 0) {
			nss_nldtls_destroy_tun(dtls_dev);
			nss_nl_error("%p Unable to add a rule entry for ipv4.\n", skb);
			return -EAGAIN;
		}

		atomic_inc(&gbl_ctx.num_tun);
		nss_nl_info("%p: Successfully created ipv4 dtls tunnel\n", skb);
	} else {
		dtls_dev = nss_nldtls_create_session(nl_rule, NSS_DTLSMGR_HDR_IPV6);
		if (!dtls_dev) {
			nss_nl_error("%p: Unable to create dtls session for v6\n", skb);
			return -EINVAL;
		}

		/*
		 * Create IPv6 rule entry
		 */
		ret = nss_nldtls_create_ipv6_rule_entry(dtls_dev, nl_rule);
		if (ret < 0) {
			nss_nldtls_destroy_tun(dtls_dev);
			nss_nl_error("%p: Unable to add a rule entry for ipv6.\n", skb);
			return -EAGAIN;
		}

		atomic_inc(&gbl_ctx.num_tun);
		nss_nl_info("%p: Successfully created ipv6 dtls tunnel\n", skb);
	}

	return 0;
}

/*
 * nss_nldtls_ops_destroy_tun()
 *	Handler to destroy tunnel
 */
static int nss_nldtls_ops_destroy_tun(struct sk_buff *skb, struct genl_info *info)
{
	struct nss_nldtls_rule *nl_rule;
	struct net_device *dtls_ndev;
	struct nss_nlcmn *nl_cm;
	int ret;

	/*
	 * Extract the message payload
	 */
	nl_cm = nss_nl_get_msg(&nss_nldtls_family, info, NSS_NLDTLS_CMD_TYPE_DESTROY_TUN);
	if (!nl_cm) {
		nss_nl_error("%p: Unable to extract destroy tunnel data\n", skb);
		return -EINVAL;
	}

	/*
	 * Message validation required before accepting the configuration
	 */
	nl_rule = container_of(nl_cm, struct nss_nldtls_rule, cm);

	dtls_ndev = dev_get_by_name(&init_net, nl_rule->msg.destroy.dev_name);
	if (!dtls_ndev) {
		nss_nl_error("%p: Unable to find dev: %s\n", skb, nl_rule->msg.destroy.dev_name);
		return -EINVAL;
	}

	/*
	 * Common dtls handler for tunnel destroy
	 */
	ret = nss_nldtls_destroy_tun(dtls_ndev);
	if (ret < 0) {
		nss_nl_error("%p: Unable to destroy tunnel: %s\n", skb, dtls_ndev->name);
		return -EAGAIN;
	}

	atomic_dec(&gbl_ctx.num_tun);
	nss_nl_info("%p: Successfully destroyed dtls session: %s\n", skb, nl_rule->msg.destroy.dev_name);
	return 0;
}

/*
 * nss_nldtls_ops_update_config()
 *	Handler for updating configuration command
 */
static int nss_nldtls_ops_update_config(struct sk_buff *skb, struct genl_info *info)
{
	struct nss_nldtls_tun_ctx *dtls_tun_data;
	struct nss_dtlsmgr_config_update dcfg;
	struct nss_nldtls_rule *nl_rule;
	struct net_device *dtls_ndev;
	struct nss_dtlsmgr_ctx *ctx;
	nss_dtlsmgr_status_t status;
	struct nss_nlcmn *nl_cm;

	/*
	 * extract the message payload
	 */
	nl_cm = nss_nl_get_msg(&nss_nldtls_family, info, NSS_NLDTLS_CMD_TYPE_UPDATE_CONFIG);
	if (!nl_cm) {
		nss_nl_error("%p: Unable to extract update_config data.\n", skb);
		return -EINVAL;
	}

	/*
	 * Message validation required before accepting the configuration
	 */
	nl_rule = container_of(nl_cm, struct nss_nldtls_rule, cm);

	dtls_ndev = dev_get_by_name(&init_net, nl_rule->msg.update_config.dev_name);
	if (!dtls_ndev) {
		nss_nl_error("%p: Unable to find dev: %s\n", skb, nl_rule->msg.update_config.dev_name);
		return -EINVAL;
	}

	ctx = netdev_priv(dtls_ndev);
	dtls_tun_data = nss_nldtls_find_dtls_tun_gbl_ctx(dtls_ndev);
	if (!dtls_tun_data) {
		nss_nl_error("%p: Unable to find context of the tunnel: %s\n", ctx, dtls_ndev->name);
		dev_put(dtls_ndev);
		return -EAGAIN;
	}

	/*
	 * Configure the dtls configuration
	 */
	dcfg.crypto.algo = nl_rule->msg.update_config.config_update.crypto.algo;
	dcfg.crypto.cipher_key.data = nl_rule->msg.update_config.config_update.crypto.cipher_key.data;
	dcfg.crypto.cipher_key.len = nl_rule->msg.update_config.config_update.crypto.cipher_key.len;
	dcfg.crypto.auth_key.data = nl_rule->msg.update_config.config_update.crypto.auth_key.data;
	dcfg.crypto.auth_key.len = nl_rule->msg.update_config.config_update.crypto.auth_key.len;
	dcfg.crypto.nonce.data = nl_rule->msg.update_config.config_update.crypto.nonce.data;
	dcfg.crypto.nonce.len = nl_rule->msg.update_config.config_update.crypto.nonce.len;
	dcfg.epoch = nl_rule->msg.update_config.config_update.epoch;
	dcfg.window_size = nl_rule->msg.update_config.config_update.window_size;
	if (!nl_rule->msg.update_config.dir) {
		status = nss_dtlsmgr_session_update_encap(dtls_ndev, &dcfg);
		if (status != NSS_DTLSMGR_OK) {
			nss_nl_error("%p: Unable to update encap configuration\n", ctx);
			dev_put(dtls_ndev);
			return -EINVAL;
		}

		nss_nl_info("%p: Successfully update the encap configuration\n", ctx);
	} else {
		status = nss_dtlsmgr_session_update_decap(dtls_ndev, &dcfg);
		if (status != NSS_DTLSMGR_OK) {
			nss_nl_error("%p: Unable to update decap configuration\n", ctx);
			dev_put(dtls_ndev);
			return -EINVAL;
		}

		nss_nl_info("%p: Successfully update the decap configuration\n", ctx);
	}

	/*
	 * Update the tun data configuration
	 */
	dtls_tun_data->nl_rule = nl_rule;
	return 0;
}

/*
 * nss_nldtls_construct_ipv4_udp_header()
 *	Creates an ipv4 + udp packet
 */
static struct sk_buff *nss_nldtls_construct_ipv4_udp_header(struct net_device *dev, struct nss_nldtls_rule *nl_rule)
{
	struct nss_nldtls_tun_ctx *tun_data;
	struct nss_nldtls_rule *dtls_rule;
	uint16_t hroom, troom;
	struct sk_buff *skb;
	struct udphdr *uh;
	struct iphdr *iph;

	/*
	 * Get the tun data
	 */
	tun_data = nss_nldtls_find_dtls_tun_gbl_ctx(dev);
	dtls_rule = tun_data->nl_rule;
	hroom = dev->needed_headroom;
	troom = dev->needed_tailroom;
	skb = dev_alloc_skb(nl_rule->msg.tx_pkts.pkt_sz + hroom + troom);
	if (!skb) {
		nss_nl_info("Failed to allocate skb\n");
		return NULL;
	}

	skb_reserve(skb, sizeof(struct udphdr) + sizeof(struct iphdr));
	skb_put(skb, nl_rule->msg.tx_pkts.pkt_sz);

	/*
	 * Fill the packet with dummy data
	 */
	memset(skb->data, NSS_NLDTLS_DUMMY_DATA, skb->len);

	/*
	 * Fill udp header fields
	 */
	skb_push(skb, sizeof(struct udphdr));
	uh = (struct udphdr *)skb->data;
	uh->source = htons(dtls_rule->msg.create.encap.sport);
	uh->dest = htons(dtls_rule->msg.create.encap.dport);
	uh->len = htons(skb->len);
	uh->check = 0;

	/*
	 * Fill IP header fields
	 */
	skb_push(skb, sizeof(struct iphdr));
	iph = (struct iphdr *)skb->data;
	iph->ihl = 5;
	iph->version = 4;
	iph->tot_len = (nl_rule->msg.tx_pkts.pkt_sz + sizeof(struct udphdr) + sizeof(struct iphdr));
	iph->ttl = dtls_rule->msg.create.encap.ip_ttl;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = dtls_rule->msg.create.encap.sip[0];
	iph->daddr = dtls_rule->msg.create.encap.dip[0];

	/*
	 * UDP checksum
	 */
	uh->check = udp_csum(skb);
	uh->check = csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len,
				      IPPROTO_UDP, uh->check);

	if (nl_rule->msg.tx_pkts.log_en) {
		nss_nl_info("%p: DTLS TX pkt len:%d udp_csum:0x%x\n", skb, skb->len, uh->check);
	}

	return skb;
}

/*
 * nss_nldtls_construct_ipv6_udp_header()
 *	Creates an ipv6 + udp packet
 */
static struct sk_buff *nss_nldtls_construct_ipv6_udp_header(struct net_device *dev, struct nss_nldtls_rule *nl_rule)
{
	struct nss_nldtls_tun_ctx *tun_data;
	struct nss_nldtls_rule *dtls_rule;
	uint16_t hroom, troom;
	struct sk_buff *skb;
	struct udphdr *uh;
	struct ipv6hdr *ip6h;

	/*
	 * Get the tun data
	 */
	tun_data = nss_nldtls_find_dtls_tun_gbl_ctx(dev);
	dtls_rule = tun_data->nl_rule;
	hroom = dev->needed_headroom;
	troom = dev->needed_tailroom;
	skb = dev_alloc_skb(nl_rule->msg.tx_pkts.pkt_sz + hroom + troom);
	if (!skb) {
		nss_nl_info("Failed to allocate skb\n");
		return NULL;
	}

	skb_reserve(skb, sizeof(struct udphdr) + sizeof(struct iphdr));
	skb_put(skb, nl_rule->msg.tx_pkts.pkt_sz);

	/*
	 * Fill the packet with dummy data
	 */
	memset(skb->data, NSS_NLDTLS_DUMMY_DATA, skb->len);

	/*
	 * Fill udp header fields
	 */
	skb_push(skb, sizeof(struct udphdr));
	uh = (struct udphdr *)skb->data;
	uh->source = htons(dtls_rule->msg.create.encap.sport);
	uh->dest = htons(dtls_rule->msg.create.encap.dport);
	uh->len = htons(skb->len);
	uh->check = 0;

	/*
	 * Fill IP header fields
	 */
	skb_push(skb, sizeof(struct ipv6hdr));
	ip6h = (struct ipv6hdr *)skb->data;
	ip6h->version = 6;
	ip6h->payload_len = htons(nl_rule->msg.tx_pkts.pkt_sz + sizeof(struct udphdr));
	ip6h->hop_limit = 64;
	ip6h->nexthdr = IPPROTO_UDP;
	ip6h->saddr.in6_u.u6_addr32[0] = htonl(dtls_rule->msg.create.encap.sip[0]);
	ip6h->saddr.in6_u.u6_addr32[1] = htonl(dtls_rule->msg.create.encap.sip[1]);
	ip6h->saddr.in6_u.u6_addr32[2] = htonl(dtls_rule->msg.create.encap.sip[2]);
	ip6h->saddr.in6_u.u6_addr32[3] = htonl(dtls_rule->msg.create.encap.sip[3]);

	ip6h->saddr.in6_u.u6_addr32[0] = htonl(dtls_rule->msg.create.encap.dip[0]);
	ip6h->saddr.in6_u.u6_addr32[1] = htonl(dtls_rule->msg.create.encap.dip[1]);
	ip6h->saddr.in6_u.u6_addr32[2] = htonl(dtls_rule->msg.create.encap.dip[2]);
	ip6h->saddr.in6_u.u6_addr32[3] = htonl(dtls_rule->msg.create.encap.dip[3]);

	skb_set_transport_header(skb, sizeof(struct ipv6hdr));
	/*
	 * UDP checksum
	 */
	udp6_set_csum(false, skb, &ip6h->saddr, &ip6h->daddr, nl_rule->msg.tx_pkts.pkt_sz + sizeof(struct udphdr));

	if (nl_rule->msg.tx_pkts.log_en) {
		nss_nl_info("%p: DTLS TX pkt len:%d udp_csum:0x%x\n", skb, skb->len, uh->check);
	}

	return skb;
}

/*
 * nss_nldtls_tx_ipv4_pkts_host_to_host()
 *	Handler for sending ipv4 traffic from one host to other
 */
static bool nss_nldtls_tx_ipv4_pkts_host_to_host(struct nss_nldtls_rule *nl_rule, struct net_device *dtls_dev)
{
	int i;
	for (i = 0; i < nl_rule->msg.tx_pkts.num_pkts; i++) {
		struct sk_buff *skb;

		skb = nss_nldtls_construct_ipv4_udp_header(dtls_dev, nl_rule);
		if (!skb) {
			nss_nl_error("%p: Unable to create ipv4 + udp packet\n", dtls_dev);
			return false;
		}

		dtls_dev->netdev_ops->ndo_start_xmit(skb, dtls_dev);
	}

	return true;
}

/*
 * nss_nldtls_tx_ipv6_pkts_host_to_host()
 *	Handler for sending ipv6 traffic from one host to other
 */
static bool nss_nldtls_tx_ipv6_pkts_host_to_host(struct nss_nldtls_rule *nl_rule, struct net_device *dtls_dev)
{
	int i;
	for (i = 0; i < nl_rule->msg.tx_pkts.num_pkts; i++) {
		struct sk_buff *skb;

		skb = nss_nldtls_construct_ipv6_udp_header(dtls_dev, nl_rule);
		if (!skb) {
			nss_nl_error("%p: Unable to create ipv4 + udp packet\n", dtls_dev);
			return false;
		}

		dtls_dev->netdev_ops->ndo_start_xmit(skb, dtls_dev);
	}

	return true;
}

/*
 * nss_nldtls_ops_tx_pkts()
 *	Handler for sending traffic
 */
static int nss_nldtls_ops_tx_pkts(struct sk_buff *skb, struct genl_info *info)
{
	struct nss_nldtls_tun_ctx *dtls_tun_data;
	struct nss_nldtls_rule *nl_rule;
	struct net_device *dtls_ndev;
	unsigned long long duration;
	struct nss_nlcmn *nl_cm;
	ktime_t delta;

	/*
	 * extract the message payload
	 */
	nl_cm = nss_nl_get_msg(&nss_nldtls_family, info, NSS_NLDTLS_CMD_TYPE_TX_PKTS);
	if (!nl_cm) {
		nss_nl_error("%p: Unable to extract tx_pkts data\n", skb);
		return -EINVAL;
	}

	/*
	 * Message validation required before accepting the configuration
	 */
	nl_rule = container_of(nl_cm, struct nss_nldtls_rule, cm);

	dtls_ndev = dev_get_by_name(&init_net, nl_rule->msg.tx_pkts.dev_name);
	if (!dtls_ndev) {
		nss_nl_error("%p: Unable to find dev: %s\n", skb, nl_rule->msg.tx_pkts.dev_name);
		return -EINVAL;
	}

	dtls_tun_data = nss_nldtls_find_dtls_tun_gbl_ctx(dtls_ndev);
	if (!dtls_tun_data) {
		nss_nl_error("%p: Unable to find context of the tunnel: %s\n", skb, dtls_ndev->name);
		dev_put(dtls_ndev);
		return -EAGAIN;
	}

	spin_lock(&gbl_ctx.lock);
	gbl_ctx.log_en = nl_rule->msg.tx_pkts.log_en;
	spin_unlock(&gbl_ctx.lock);

	/*
	 * Send traffic from host to host
	 */
	gbl_ctx.first_tx_pkt_time = ktime_get();
	if (nl_rule->msg.tx_pkts.ip_version == NSS_NLDTLS_IP_VERS_4) {
		if (!nss_nldtls_tx_ipv4_pkts_host_to_host(nl_rule, dtls_ndev)) {
			nss_nl_error("%p: Error in transmission\n", skb);
			return -EAGAIN;
		}
	} else {
		if (!nss_nldtls_tx_ipv6_pkts_host_to_host(nl_rule, dtls_ndev)) {
			nss_nl_error("%p: Error in transmission\n", skb);
			return -EAGAIN;
		}
	}

	gbl_ctx.last_tx_pkt_time = ktime_get();
	delta = ktime_sub(gbl_ctx.last_tx_pkt_time, gbl_ctx.first_tx_pkt_time);
	duration = (unsigned long long) ktime_to_ns(delta) >> 10;
	nss_nl_info("%p: Packets sent in %llu usecs", dtls_ndev, duration);
	nss_nl_info("%p: Traffic transmission successful\n", skb);
	return 0;
}

/*
 * nss_nldtls_cmd_ops
 *	Operation table called by the generic netlink layer based on the command
 */
struct genl_ops nss_nldtls_cmd_ops[] = {
	{.cmd = NSS_NLDTLS_CMD_TYPE_CREATE_TUN, .doit = nss_nldtls_ops_create_tun,},
	{.cmd = NSS_NLDTLS_CMD_TYPE_DESTROY_TUN, .doit = nss_nldtls_ops_destroy_tun,},
	{.cmd = NSS_NLDTLS_CMD_TYPE_UPDATE_CONFIG, .doit = nss_nldtls_ops_update_config,},
	{.cmd = NSS_NLDTLS_CMD_TYPE_TX_PKTS, .doit = nss_nldtls_ops_tx_pkts,},
};

/*
 * nss_nldtls_init()
 *	Init handler for dtls
 */
bool nss_nldtls_init(void)
{
	int err;

	nss_nl_info_always("Init NSS netlink dtls handler\n");

	/*
	 * register NETLINK ops with the family
	 */
	err = genl_register_family_with_ops_groups(&nss_nldtls_family, nss_nldtls_cmd_ops, nss_nldtls_family_mcgrp);
	if (err) {
		nss_nl_info_always("Error: %d unable to register gre_redir family\n", err);
		genl_unregister_family(&nss_nldtls_family);
		return false;
	}

	return true;
}

/*
 * nss_nldtls_exit()
 *	Exit handler for dtls
 */
bool nss_nldtls_exit(void)
{
	struct nss_nldtls_tun_ctx *entry, *tmp;
	struct net_device *dtls_ndev;
	int err;

	nss_nl_info_always("Exit NSS netlink dtls handler\n");

	/*
	 * Destroy all active tunnel before exiting
	 */
	list_for_each_entry_safe(entry, tmp, &gbl_ctx.dtls_list_head, list) {
		dtls_ndev = dev_get_by_name(&init_net, entry->dev_name);
		if (dtls_ndev) {
			nss_nldtls_destroy_tun(dtls_ndev);
		}
	}

	nss_nl_info_always("All active tunnels destroyed\n");

	/*
	 * unregister the ops family
	 */
	err = genl_unregister_family(&nss_nldtls_family);
	if (err) {
		nss_nl_info_always("Error: %d unable to unregister dtls NETLINK family\n", err);
		return false;
	}

	return true;
}
