#include <linux/etherdevice.h>
#include "packet-handle.h"


struct timespec throttle_expire;
static struct net_device *eth_dev;

static uint32_t eth_tx_dropped;
static uint32_t sta_tx_dropped;
static uint32_t sta_bcast_mcast_frwded;

typedef void (*pkt_fwd_set_stat)(struct net_device *dev, int indx);
typedef uint32_t (*pkt_fwd_get_stat)(struct net_device *dev, int indx);

static struct __wif_net_device_stat{
	pkt_fwd_set_stat set;
	pkt_fwd_get_stat get;
}g_wifi_net_device_stat;

int32_t set_destination_node(struct net_device *dev)
{
	eth_dev = dev;
#ifdef DEBUG_PRINT
	printk(KERN_INFO "%s: eth_dev is %s\n",__func__,eth_dev->name);
#endif
	return 0;
}

void register_wif_net_device_stat(pkt_fwd_set_stat set, pkt_fwd_get_stat get){
	g_wifi_net_device_stat.set = set;
	g_wifi_net_device_stat.get = get;
}
EXPORT_SYMBOL(register_wif_net_device_stat);

enum pkt_fwd_stats_enum{
	STA_RX_PACKETS = 0,
	STA_TX_PACKETS,
	ETH_RX_PACKETS,
	ETH_TX_PACKETS,
	RESET_ALL,
};

void display_stats(char* key)
{

	struct net_device *dev = NULL;

	pr_info("OPTIONS:\nall\neth\nsta\nreset\n");

	if (!strncmp(key, ETH_IF_NAME,3)) {
		pr_info("Packets Received & Forwarded on Eth interfaces :\n");
		rcu_read_lock();
		for_each_netdev_rcu(&init_net, dev){
			if (dev->type == ARPHRD_ETHER && !strncmp(dev->name, STA_IF_NAME, 3)){
				dev_hold(dev);
				pr_info("received on ETH (for  %s): %u\n", dev->name, g_wifi_net_device_stat.get(dev, ETH_RX_PACKETS));
				pr_info("forwarded on ETH (from %s): %u\n", dev->name, g_wifi_net_device_stat.get(dev, ETH_TX_PACKETS));
				dev_put(dev);
			}
		}
		rcu_read_unlock();
	}

	if (!strncmp(key, STA_IF_NAME,3)) {
		pr_info("Packets Received & Forwarded on STA interfaces :\n");
		rcu_read_lock();
		for_each_netdev_rcu(&init_net, dev){
			if (dev->type == ARPHRD_ETHER && !strncmp(dev->name, STA_IF_NAME, 3)){
				dev_hold(dev);
				pr_info("received on Sta (for  %s): %u\n", dev->name, g_wifi_net_device_stat.get(dev, STA_RX_PACKETS));
				pr_info("forwarded on Sta (from %s): %u\n", dev->name, g_wifi_net_device_stat.get(dev, STA_TX_PACKETS));
				dev_put(dev);
			}
		}
		rcu_read_unlock();
	}

	if (!strncmp(key,"reset",5)) {
		sta_bcast_mcast_frwded = 0;
		eth_tx_dropped = 0;
		sta_tx_dropped = 0;
		rcu_read_lock();
		for_each_netdev_rcu(&init_net, dev){
			if (dev->type == ARPHRD_ETHER && !strncmp(dev->name, STA_IF_NAME, 3) ){
				dev_hold(dev);
				g_wifi_net_device_stat.set(dev, RESET_ALL);
				dev_put(dev);
			}
		}
		rcu_read_unlock();
	}

	if (!strncmp(key,"all",3)) {

		rcu_read_lock();
		for_each_netdev_rcu(&init_net, dev){
			if (dev->type == ARPHRD_ETHER && !strncmp(dev->name, STA_IF_NAME, 3) ){
				dev_hold(dev);
				pr_info("UPLINK\n");
				pr_info("received on ETH (for  %s): %u\n", dev->name, g_wifi_net_device_stat.get(dev, ETH_RX_PACKETS));
				pr_info("forwarded on Sta (from %s): %u\n", dev->name, g_wifi_net_device_stat.get(dev, STA_TX_PACKETS));
				pr_info("DOWNLINK\n");
				pr_info("received on Sta (for  %s): %u\n", dev->name, g_wifi_net_device_stat.get(dev, STA_RX_PACKETS));
				pr_info("forwarded on ETH (from %s): %u\n", dev->name, g_wifi_net_device_stat.get(dev, ETH_TX_PACKETS));
				dev_put(dev);
			}
		}
		rcu_read_unlock();

		pr_info("Packets dropped in uplink: %u\n",sta_tx_dropped);
		pr_info("Packets dropped in downlink: %u\n", eth_tx_dropped);
		pr_info("Broadcast/Multicast packets forwarded: %u\n",sta_bcast_mcast_frwded);
	}

}

ssize_t write_stats(struct file *filp,const char *buf,size_t count,loff_t *offp)
{
	unsigned long ret;
	char proc_buf[5];
	memset(proc_buf,'\0', sizeof(proc_buf));
	ret = copy_from_user(proc_buf, buf, 5);
	if (ret) {
		printk(KERN_ERR "%s:copy from user failed \n",__func__);
		return count;
	}
	display_stats(proc_buf);
	return count;
}

//extern void set_pkt_fwd_stat(struct net_device *dev, int indx);
int32_t sendto_packet_handling_flow(struct sk_buff *skb)
{
	struct ethhdr *mh = NULL;
	const struct net_device_ops *ops = NULL;
	struct net_device *stn_net_device = NULL;

	/* Validate the sanity of skb */
	if ((skb != NULL) && (virt_addr_valid(skb)))
		mh = eth_hdr(skb);
	else
		return PACK_RET_TO_LNX_STACK;

#ifdef DRV_DEBUG
	pr_info("dst=%02x:%02x:%02x:%02x:%02x:%02x\n", mh->h_dest[0], mh->h_dest[1], mh->h_dest[2],
			mh->h_dest[3], mh->h_dest[4], mh->h_dest[5]);
	pr_info("src=%02x:%02x:%02x:%02x:%02x:%02x\n", mh->h_source[0], mh->h_source[1], mh->h_source[2],
			mh->h_source[3], mh->h_source[4], mh->h_source[5]);
#endif

	/* Eth -> sta -> AP */
	/* 1. Check the packet type
	   2. If the type is ETHERNET_TYPE, then check the src mac of the skb
	   3. Using 'dev_getbyhwaddr_rcu'  with global net name space 'init_net' to retrieve STA dev node by MAC address
	   4. If it matches with the station mac, then send the skb to the particulation station
	   5. return SUCCESS */

	if ((skb->dev->if_type == ETHERNET_TYPE)) {
		rcu_read_lock();
		stn_net_device = dev_getbyhwaddr_rcu( &init_net, ARPHRD_ETHER, mh->h_source);
		rcu_read_unlock();
		if (likely(stn_net_device)) {
#ifdef DRV_DEBUG
			pr_info("Eth -> sta -> AP, %s\n", stn_net_device->name);
#endif
			skb->pkt_type = PACKET_OUTGOING;
			skb->dev = stn_net_device;
			ops = stn_net_device->netdev_ops;
			/* check interface is in dormant state */
			if (unlikely((netif_dormant(stn_net_device) == true) && (ntohs(mh->h_proto) != ETH_P_ARP))) {
				uint64_t current_time = 0;
				getnstimeofday(&throttle_expire);
				current_time = throttle_expire.tv_sec;
				if ((current_time - stn_net_device->last_kickout_time) > THROTTLE_TIMEOUT) {
					stn_net_device->last_kickout_time = 0;
                                        /* To clear dormant state flag on interface */
					netif_dormant_off(stn_net_device);
				}
				else {
					sta_tx_dropped++;
					dev_kfree_skb_any(skb);
					return PACK_HANDLED;
				}
			}

			if(likely(stn_net_device->flags & IFF_UP)) {
				skb->data = (unsigned char *)eth_hdr(skb);
				skb->len += ETH_HEADER_SIZE;
				g_wifi_net_device_stat.set(stn_net_device, ETH_RX_PACKETS);

				if (ops->ndo_start_xmit(skb, stn_net_device)) {
					pr_err("%s, Eth -> sta -> AP, xmit failed\n", __func__);
					sta_tx_dropped++;
					dev_kfree_skb_any(skb);
				} else {
					g_wifi_net_device_stat.set(stn_net_device, STA_TX_PACKETS);
				}
			} else {
				sta_tx_dropped++;
				dev_kfree_skb_any(skb);
			}
			return PACK_HANDLED;
		} else{
#ifdef DRV_DEBUG
			pr_err("%s, failed to get net_device from namespace\n", __func__);
#endif
			return PACK_RET_TO_LNX_STACK;
		}
	}

	/* AP -> sta -> ETH */
	if ((skb->dev->if_type == STATION_TYPE)) {
		if (is_unicast_ether_addr(mh->h_dest)) {
			rcu_read_lock();
			stn_net_device = dev_getbyhwaddr_rcu( &init_net, ARPHRD_ETHER, mh->h_dest);
			rcu_read_unlock();

			if(!stn_net_device){
#ifdef DRV_DEBUG
				pr_err("%s, failed to get net_device from namespace\n", __func__);
#endif
				return PACK_RET_TO_LNX_STACK;
			}
			g_wifi_net_device_stat.set(stn_net_device, STA_RX_PACKETS);
#ifdef DRV_DEBUG
			pr_info("AP -> sta -> ETH, %s\n", stn_net_device->name);
#endif
		}
		else { //broadcast
			sta_bcast_mcast_frwded++;
		}
		skb->pkt_type = PACKET_OUTGOING;
		skb->dev = eth_dev;
		ops = eth_dev->netdev_ops;
		skb->data = (unsigned char *)eth_hdr(skb);
		skb->len += ETH_HLEN;
		if ((ops->ndo_start_xmit(skb, eth_dev)) != 0) {
			eth_tx_dropped ++;
			dev_kfree_skb_any(skb);
		} else {
			if (stn_net_device){ //not a broadcast, update stats
				g_wifi_net_device_stat.set(stn_net_device, ETH_TX_PACKETS);
			}
		}
#ifdef DRV_DEBUG
		pr_info("data len : %d skb_len : %d\n", skb->data_len, skb->len);
		pr_info("Head : %p data : %p \n", skb->head, skb->data);
		pr_info("th : %d nh : %d mh : %d\n", skb->transport_header, skb->network_header, skb->mac_header);
#endif
		return PACK_HANDLED;
	}
	return  PACK_RET_TO_LNX_STACK;
}
