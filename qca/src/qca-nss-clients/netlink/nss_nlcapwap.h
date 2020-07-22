/*
 **************************************************************************
 * Copyright (c) 2014-2015, 2018-2020 The Linux Foundation. All rights reserved.
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

/*
 * nss_nlcapwap.h
 *	NSS Netlink Capwap API definitions
 */
#ifndef __NSS_NLCAPWAP_H
#define __NSS_NLCAPWAP_H

#include "nss_nlcapwap_if.h"

#define NSS_NLCAPWAP_IP_VERS_4 4			/* IP version 4 */
#define NSS_NLCAPWAP_IP_VERS_6 6			/* IP version 6 */
#define NSS_NLCAPWAP_VLAN_TAG_INVALID 0xFFF		/* Invalid vlan tag */
#define NSS_NLCAPWAP_WAN_IFNUM 0			/* WAN interface number */
#define NSS_NLCAPWAP_DATA 0xcc				/* Dummy data */
#define NSS_NLCAPWAP_KALIVE_PAYLOAD_SZ 64		/* Capwap+Dtls keepalive packet size */
#define NSS_NLCAPWAP_KALIVE_TIMER_MSECS 1000		/* Capwap+Dtls keepalive timer */
#define NSS_NLCAPWAP_STATS_MAX 5			/* Maximum number of stats per tunnel */
#define NSS_NLCAPWAP_MAX_STR_LEN 96			/* Maximum length of stats string */
#define NSS_NLCAPWAP_MAX_HEADROOM 128	/* Maximum headroom needed */
#define NSS_NLCAPWAP_MAX_TAILROOM 192	/* Maximum tailroom needed */
#define NSS_NLCAPWAP_MAX_TUNNEL_LONGS BITS_TO_LONGS(NSS_CAPWAPMGR_MAX_TUNNELS)
/*
 * nss_nlcapwap_meta_header_type
 *	Capwap meta header type
 */
enum nss_nlcapwap_meta_header_type {
	NSS_NLCAPWAP_META_HEADER_TYPE_UNKNOWN = -1,	/* Unknown meta header type */
	NSS_NLCAPWAP_META_HEADER_TYPE_IPV4_DATA,	/* capwap meta header type ipv4 */
	NSS_NLCAPWAP_META_HEADER_TYPE_EAPOL,		/* capwap meta header type eapol */
	NSS_NLCAPWAP_META_HEADER_TYPE_MAX		/* Max meta header type */
};

/*
 * nss_nlcapwap_tunnel_stats
 *	Keeps track of the netlink capwap stats
 */
struct nss_nlcapwap_tunnel_stats {
	uint32_t ka_seq_fail;
	uint32_t tx_data_pkts;
	uint32_t rx_data_pkts;
	uint32_t tx_ka_pkts;
	uint32_t rx_ka_pkts;
};

/*
 * nss_nlcapwap_tunnel_keepalive
 *	Parameters needed for keepalive execution
 */
struct nss_nlcapwap_tunnel_keepalive {
	struct delayed_work work;
	uint32_t tx_seq;
	uint32_t rx_seq;
	uint16_t tun_id;
	atomic_t status;
};

/*
 * nss_nlcapwap_tunnel
 *	Stores the per tunnel data
 */
struct nss_nlcapwap_tunnel {
	struct nss_nlcapwap_tunnel_keepalive kalive;	/* Keepalive parameters */
	struct nss_nlcapwap_tunnel_stats stats;		/* Per tunnel netlink level stats */
	struct nss_nlcapwap_meta_header mh;		/* Stores meta header of tunnel */
};

/*
 * nss_nlcapwap_global_ctx
 *	Global context for capwap
 */
struct nss_nlcapwap_global_ctx {
	struct nss_nlcapwap_tunnel tun[NSS_CAPWAPMGR_MAX_TUNNELS];
					/* Keepalive params per tunnel */
	unsigned long tun_bitmap[NSS_NLCAPWAP_MAX_TUNNEL_LONGS];
					/* Bitmap to keep track of tunnel status */
	struct net_device *capwap_dev;	/* CAPWAP global device */
	struct dentry *dentry;		/* Debug entry to maintain netlink stats */
	atomic_t enable_perf;		/* Atomic variable to enable and disable perf */
	rwlock_t lock;			/* Lock variable for synchronization */
};

/*
 * nss_nlcapwap_app_hdr
 *	Custom header needed by sender and receiver
 */
struct nss_nlcapwap_app_hdr {
	uint32_t seq_num;		/* Seq number associated with packet */
	uint16_t tun_id;		/* Tunnel used for transmission */
	uint8_t res[2];			/* Reserved for padding */
};

/*
 * nss_nlcapwap_hdr
 *	capwap header used for dtls_keepalive packets
 */
struct nss_nlcapwap_hdr {
	uint8_t preamble;	/* 0=CAPWAP header, 1=CAPWAP DTLS header */

	/*
	 * 1-byte
	 */
	uint8_t rid1:3;
	/*
	 * rid1: 3 bits of a 5-bit field that contains the Radio ID number for
	 * this packet, whose value is between one (1) and 31. Given
	 * that MAC Addresses are not necessarily unique across physical
	 * radios in a WTP, the Radio Identifier (RID) field is used to
	 * indicate with which physical radio the message is associated.
	 */
	uint8_t hlen:5;
	/*
	 * hlen: A 5-bit field containing the length of the CAPWAP transport
	 * header in 4-byte words (similar to IP header length). This
	 * length includes the optional headers.
	 */

	/*
	 * 1-byte
	 */
	uint8_t T:1;		/* Type (1=802.11, 0=Other) */
	uint8_t wbid:5;
	/*
	 * wbid: A 5-bit field that is the wireless binding identifier. The
	 * identifier will indicate the type of wireless packet associated
	 * with the radio. The following values are defined:
	 * 0 - Reserved 1 - IEEE 802.11 2 - Reserved 3 - EPCGlobal [EPCGlobal]
	 */

	uint8_t rid2:2;		/* 2-bits of radio id -- look at rid1 */

	/*
	 * 1-byte
	 */
	uint8_t flags:3;	/* Not Used */
	uint8_t K:1;		/* 1=KeepAlive packet 0=Not keepalive packet */
	uint8_t M:1;		/* 1=MAC address is present, 0=not present */
	uint8_t W:1;		/* 1=wireless info present, 0=not present */
	uint8_t L:1;		/* 1=Last fragment, 0=Not the last fragment */
	uint8_t F:1;		/* 1=Fragmented, 0=Not fragmented */

	uint16_t frag_id;	/* Fragment ID */
	uint16_t frag_off;	/* 13-bit Offset of the fragment in 8 byte words */
				/* lower 3 bits are reserved & must be set to 0 */
} __attribute__((packed));

/*
 * nss_nlcapwap_init()
 *	To initialize the capwap module
 */
bool nss_nlcapwap_init(void);

/*
 * nss_nlcapwap_exit()
 *	To de-initialize the capwap module
 */
bool nss_nlcapwap_exit(void);

#if (CONFIG_NSS_NLCAPWAP == 1)
#define NSS_NLCAPWAP_INIT nss_nlcapwap_init
#define NSS_NLCAPWAP_EXIT nss_nlcapwap_exit
#else
#define NSS_NLCAPWAP_INIT 0
#define NSS_NLCAPWAP_EXIT 0
#endif /* !CONFIG_NSS_NLCAPWAP */

#endif /* __NSS_NLCAPWAP_H */
