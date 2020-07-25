#ifndef __PACKET_HANDLE_H__
#define __PACKET_HANDLE_H__

#include <asm/uaccess.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/notifier.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <linux/rtnetlink.h>
#include <linux/stat.h>
#include <net/dst.h>
#include <net/pkt_sched.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netpoll.h>
#include <linux/rcupdate.h>
#include <linux/delay.h>
#include <net/iw_handler.h>
#include <asm/current.h>
#include <linux/audit.h>
#include <linux/dmaengine.h>
#include <linux/err.h>
#include <linux/ctype.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/inetdevice.h>
#include <linux/time.h>
#include <linux/stddef.h>
#include <asm/memory.h>
/* #define DEBUG_PRINT 1 */
struct sta_data{
	uint64_t key;
	char sta_name[30];
	char sta_mac[6];
	uint32_t sta_count;
	uint32_t sta_rx_packets;
	uint32_t sta_tx_packets;
	uint32_t eth_rx_packets;
	uint32_t eth_tx_packets;
	struct net_device *dev;
	struct sta_data *next;
};
typedef struct sta_data sta_info;

#define PACK_HANDLE_MAC_SIZE    6
#define PACK_HANDLE_SUCCESS     0
#define PACK_HANDLE_FAILED      -1
#define ETH_HEADER_SIZE		14
#define ETH_IF_NAME	"eth1"
#define STA_IF_NAME	"sta"
#define PACK_HANDLED	1
#define PACK_RET_TO_LNX_STACK	0
#define THROTTLE_TIMEOUT        30

struct sta_data *create_new_stanode(struct net_device *dev);

void insert_stanode_into_list(sta_info *sta_node);

int8_t delete_stanode_from_list(char *staMac);

int8_t find_staMac_from_list(uint32_t key, sta_info **sta_data);

int32_t sendto_packet_handling_flow(struct sk_buff *skb);

int32_t set_destination_node(struct net_device *dev);

ssize_t write_stats(struct file *filp,const char *buf,size_t count,loff_t *offp);

#endif /* __PACKET_HANDLE_H__ */
