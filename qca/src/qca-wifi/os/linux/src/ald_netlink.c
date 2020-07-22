/*
 * Copyright (c) 2015, 2017, 2019-2020 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2015 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/*
 *  Copyright (c) 2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "linux/if.h"
#include "linux/socket.h"
#include <net/rtnetlink.h>
#include <net/sock.h>

#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/cache.h>
#include <linux/proc_fs.h>

#include "if_athvar.h"
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
#include "ald_netlink.h"
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_vdev_if.h>
#endif

#ifdef QCA_SUPPORT_SON
#include <wlan_son_pub.h>
#endif
#include <wlan_utility.h>
#include <dp_txrx.h>

struct ald_netlink *ald_nl = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
static void ald_nl_receive(struct sk_buff *__skb);
#else
static void ald_nl_receive(struct sock *sk, int len);
#endif

int ald_init_netlink(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION (3,10,0)
    struct netlink_kernel_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.groups = 1;
    cfg.input = &ald_nl_receive;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
    struct netlink_kernel_cfg cfg = {
    .groups = 1,
    .input  = ald_nl_receive,
    };
#endif

    if (ald_nl == NULL) {
        ald_nl = (struct ald_netlink *)qdf_mem_malloc(sizeof(struct ald_netlink));

        if(ald_nl == NULL)
            return -ENODEV;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)/* Also for >= 3,10,0 */
        ald_nl->ald_sock = (struct sock *)netlink_kernel_create(&init_net, NETLINK_ALD, &cfg);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
        ald_nl->ald_sock = (struct sock *)netlink_kernel_create(&init_net, NETLINK_ALD,
                                   THIS_MODULE, &cfg);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
        ald_nl->ald_sock = (struct sock *)netlink_kernel_create(&init_net, NETLINK_ALD,
                                   1, &ald_nl_receive, NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,22)
        ald_nl->ald_sock = (struct sock *)netlink_kernel_create(NETLINK_ALD,
                                   1, &ald_nl_receive, (struct mutex *) NULL, THIS_MODULE);
#else
        ald_nl->ald_sock = (struct sock *)netlink_kernel_create(NETLINK_ALD,
                                   1, &ald_nl_receive, THIS_MODULE);
#endif

        if (ald_nl->ald_sock == NULL) {
            qdf_mem_free(ald_nl);
            ald_nl = NULL;

            qdf_nofl_info("%s NETLINK_KERNEL_CREATE FAILED\n", __func__);

            return -ENODEV;
        }

        atomic_set(&ald_nl->ald_refcnt, 1);
    } else {
        atomic_inc(&ald_nl->ald_refcnt);
    }

    return 0;
}

int ald_destroy_netlink(void)
{
    if (ald_nl == NULL) {
        qdf_nofl_info("\n%s ald_nl is NULL\n", __func__);
        return -ENODEV;
    }

    if (!atomic_dec_return(&ald_nl->ald_refcnt)) {
        if (ald_nl->ald_sock)
	    netlink_kernel_release(ald_nl->ald_sock);

        qdf_mem_free(ald_nl);
        ald_nl = NULL;
    }

    return 0;
}


static void ald_notify(wlan_if_t vap, u_int32_t info_cmd, u_int32_t info_len, void *info_data)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh = NULL;
    u_int8_t *nldata = NULL;
    u_int32_t pid;

    if (ald_nl == NULL || vap == NULL)
        return;

    pid = vap->ald_pid;

    if (pid == WLAN_DEFAULT_NETLINK_PID) return;

    skb = nlmsg_new(info_len, GFP_ATOMIC);
    if (!skb) {
        qdf_nofl_info("%s: No memory, info_cmd = %d\n", __func__, info_cmd);
        return;
    }

    nlh = nlmsg_put(skb, pid, 0, info_cmd, info_len, 0);
    if (!nlh) {
        qdf_nofl_info("%s: nlmsg_put() failed, info_cmd = %d\n", __func__, info_cmd);
        kfree_skb(skb);
        return;
    }

    nldata = NLMSG_DATA(nlh);
    memcpy(nldata, info_data, info_len);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
    NETLINK_CB(skb).pid = 0;        /* from kernel */
#else
    NETLINK_CB(skb).portid = 0;  /* from kernel */
#endif

#if QCA_SUPPORT_SON
    if (wlan_son_is_vdev_event_bcast_enabled(vap->vdev_obj)) {
        NETLINK_CB(skb).dst_group = QCA_ALD_GENERIC_EVENTS;  /* broadcast */
        netlink_broadcast(ald_nl->ald_sock, skb, 0, QCA_ALD_GENERIC_EVENTS, GFP_ATOMIC);
    } else
#endif
    {
        NETLINK_CB(skb).dst_group = 0;  /* unicast */
        netlink_unicast(ald_nl->ald_sock, skb, pid, MSG_DONTWAIT);
    }
}

static void ald_send_info_iter_func(wlan_if_t vap)
{
    struct net_device *dev;
    struct ald_stat_info *info = NULL;

    info = qdf_mem_malloc(sizeof(struct ald_stat_info));

    if ((info == NULL) || (vap->vdev_obj == NULL) || (wlan_vap_delete_in_progress(vap))) {
            return;
    }

    if ((wlan_vdev_is_up(vap->vdev_obj) == QDF_STATUS_SUCCESS) &&
            vap->ald_pid != WLAN_DEFAULT_NETLINK_PID) {

        info->cmd = IEEE80211_ALD_ALL;

        dev = ((osif_dev *)vap->iv_ifp)->netdev;
        if (strlcpy(info->name, dev->name, IFNAMSIZ) >= IFNAMSIZ) {
              qdf_err("source too long");
              return ;
        }

        vap->iv_ald->staticp = info;
        wlan_ald_get_statistics(vap, NULL);
        vap->iv_ald->staticp = NULL;

        ald_notify(vap, IEEE80211_ALD_ALL, sizeof(struct ald_stat_info), info);
    }
    qdf_mem_free(info);
}

static void ald_nl_hifitbl_update(wlan_if_t vap, struct nlmsghdr *nlh)
{
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    struct ieee80211com *ic = vap->iv_ic;
    osif_dev* osifp = (osif_dev *)vap->iv_ifp;
#endif
    struct wlan_objmgr_vdev *vdev = vap->vdev_obj;
    struct wlan_objmgr_pdev *pdev;
    ol_txrx_soc_handle soc;
    rwlock_t *me_lock;

    pdev = wlan_vdev_get_pdev(vdev);
    soc = wlan_psoc_get_dp_handle(wlan_vdev_get_psoc(vdev));
    me_lock = dp_get_me_mcast_lock(soc, wlan_vdev_get_id(vdev));

    if(!me_lock)
       return;

    write_lock_bh(me_lock);
    dp_me_update_mcast_table(soc, wlan_vdev_get_id(vdev),
                             wlan_objmgr_pdev_get_pdev_id(pdev), NLMSG_DATA(nlh),
                             nlh->nlmsg_len, NLMSG_HDRLEN);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (osifp->nss_wifiol_ctx && ic->nss_vops && dp_get_me_mode(soc, wlan_vdev_get_id(vdev))) {
        ic->nss_vops->ic_osif_nss_vdev_me_reset_snooplist(osifp);
        ic->nss_vops->ic_osif_nss_vdev_me_update_hifitlb(
                        osifp,
                        dp_get_vdev_me_handle(soc, wlan_vdev_get_id(vdev)));
    }
#endif

    write_unlock_bh(me_lock);
}

/* Note: This function takes RTNL lock */
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
static void ald_nl_receive(struct sk_buff *__skb)
#else
static void ald_nl_receive(struct sock *sk, int len)
#endif
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    wlan_if_t vap;
    u_int32_t pid;
    int32_t ifindex;
    struct net_device *dev;
    osif_dev  *osifp;

#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
    if ((skb = skb_get(__skb)) != NULL) {
#else
    if ((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL) {
#endif
        nlh = nlmsg_hdr(skb);
        pid = nlh->nlmsg_pid;
        ifindex = nlh->nlmsg_flags;

        dev = dev_get_by_index(&init_net, ifindex);
        if (!dev) {
            qdf_nofl_info("%s: Invalid interface index:%d\n", __func__, ifindex);
            kfree_skb(skb);
            return;
        }

        osifp = ath_netdev_priv(dev);
        if (osifp ->is_deleted)
        {
            qdf_nofl_info("%s: vap[%s] has been deleted\n", __func__, dev->name);
            goto out;
        }

        vap = osifp->os_if;
        if(vap == NULL) {
            goto out;
        }

        if(ald_nl == NULL) {
            goto out;
        }

        /* Take rtnl lock on ald netlink path, so no other thread queries in parallel
         * Note: This lock needs to be removed when moving to nl80211 or IOCTL path. */
        rtnl_lock();
        if (vap->ald_pid  !=  pid) {
            vap->ald_pid = pid;
        }
        if (nlh->nlmsg_type == IEEE80211_ALD_ALL)
            ald_send_info_iter_func(vap);
        else if (nlh->nlmsg_type == IEEE80211_ALD_MCTBL_UPDATE) {
            ald_nl_hifitbl_update(vap, nlh);
        }
        rtnl_unlock();

out:
        dev_put(dev);
        kfree_skb(skb);
    }
}

int ald_assoc_notify(wlan_if_t vap, u_int8_t *macaddr, u_int8_t aflag,
                     u_int16_t reasonCode) {
    struct net_device *dev;
    wlan_chan_t chan;
    struct ald_assoc_info info;

    info.cmd = IEEE80211_ALD_ASSOCIATE;
    dev = ((osif_dev *)vap->iv_ifp)->netdev;
    if (strlcpy(info.name, dev->name , IFNAMSIZ) >= IFNAMSIZ) {
          qdf_print("source too long");
          return -1;
    }
    chan = wlan_get_current_channel(vap, true);
    if(chan->ic_freq * 100000 < 500000)
        info.afreq = ALD_FREQ_24G;
    else
        info.afreq = ALD_FREQ_5G;
    info.aflag = aflag;
    memcpy(info.macaddr, macaddr, QDF_MAC_ADDR_SIZE);
    info.reasonCode = reasonCode;

    ald_notify(vap, IEEE80211_ALD_ASSOCIATE, sizeof(info), &info);
    return 0;
}

/* function for 75% buffers full warning */
int ald_buffull_notify(wlan_if_t vap)
{
    struct net_device *dev;
    struct ald_buffull_info info;

    info.cmd = IEEE80211_ALD_BUFFULL_WRN;
    dev = ((osif_dev *)vap->iv_ifp)->netdev;
    if (strlcpy(info.name, dev->name , IFNAMSIZ) >= IFNAMSIZ) {
        qdf_print("source too long");
        return -1;
    }
    info.resv = ATH_TXBUF;

    ald_notify(vap, IEEE80211_ALD_BUFFULL_WRN, sizeof(info), &info);
    return 0;

}

/* function to notify CBS event */
int ald_cbs_notify(wlan_if_t vap, ald_cbs_event_type type)
{
    struct net_device *dev;
    struct ald_cbs_info info;

    info.cmd = IEEE80211_ALD_CBS;
    dev = ((osif_dev *)vap->iv_ifp)->netdev;
    if (strlcpy(info.name, dev->name, IFNAMSIZ) >= IFNAMSIZ) {
        qdf_err("source too long\n");
        return -1;
    }

    info.type = type;
    ald_notify(vap, IEEE80211_ALD_CBS, sizeof(info), &info);
    return 0;
}

/* function to notify ACS Neighbour Scan complete */
int ald_acs_complete_notify(wlan_if_t vap) {
    struct net_device *dev;
    struct ald_cbs_info info;

    info.cmd = IEEE80211_ALD_ACS_COMPLETE;
    dev = ((osif_dev *)vap->iv_ifp)->netdev;
    if (strlcpy(info.name, dev->name, IFNAMSIZ) >= IFNAMSIZ) {
        qdf_err("source too long\n");
        return -1;
    }

    info.type = ALD_CBS_COMPLETE;
    ald_notify(vap, IEEE80211_ALD_ACS_COMPLETE, sizeof(info), &info);
    return 0;
}

/* function to notify CAC complete */
int ald_cac_complete_notify(wlan_if_t vap, u_int8_t radar_detected)
{
    struct net_device *dev;
    struct ald_cac_complete_info info;

    info.cmd = IEEE80211_ALD_CAC_COMPLETE;
    dev = ((osif_dev *)vap->iv_ifp)->netdev;
    if (strlcpy(info.name, dev->name, IFNAMSIZ) >= IFNAMSIZ) {
        qdf_err("source too long\n");
        return -1;
    }
    info.radar_detected = radar_detected;

    ald_notify(vap, IEEE80211_ALD_CAC_COMPLETE, sizeof(info), &info);
    return 0;
}

/* function to notify change in BSS assoc allowance status */
int ald_assoc_allowance_status_notify(wlan_if_t vap, u_int8_t *bssid, u_int8_t assoc_status) {
    struct net_device *dev;
    struct ald_assoc_allowance_info info;

    info.cmd = IEEE80211_ALD_ASSOC_ALLOWANCE_STATUS_CHANGE;
    dev = ((osif_dev *)vap->iv_ifp)->netdev;
    if (strlcpy(info.name, dev->name, IFNAMSIZ) >= IFNAMSIZ) {
        qdf_err("source too long\n");
        return -1;
    }

    memcpy(info.bssid, bssid, IEEE80211_ADDR_LEN);
    info.assoc_status = assoc_status;
    ald_notify(vap, IEEE80211_ALD_ASSOC_ALLOWANCE_STATUS_CHANGE, sizeof(info), &info);
    return 0;
}

/* function to send WNM request frame to userspace */
int ald_wnm_frame_recvd_notify(wlan_if_t vap, u_int8_t action, u_int8_t *macaddr, u_int8_t *frame,
                               uint16_t frame_len) {
    struct net_device *dev;
    struct ald_wnm_frame_info info;

    info.cmd = action;
    dev = ((osif_dev *)vap->iv_ifp)->netdev;
    if (strlcpy(info.name, dev->name, IFNAMSIZ) >= IFNAMSIZ) {
        qdf_err("source too long\n");
        return -1;
    }

    memcpy(info.macaddr, macaddr, IEEE80211_ADDR_LEN);
    memcpy(info.frame, frame, frame_len);
    info.frameSize = frame_len;
    ald_notify(vap, IEEE80211_ALD_WNM_FRAME_RECEIVED, sizeof(info), &info);
    return 0;
}

/* function to send ANQP neighbor report request frame to userspace */
int ald_anqp_frame_recvd_notify(wlan_if_t vap, u_int8_t *macaddr, u_int8_t *frame,
                               uint16_t frame_len) {
    struct net_device *dev;
    struct ald_anqp_frame_info info;

    dev = ((osif_dev *)vap->iv_ifp)->netdev;
    if ((frame_len > ALD_MAX_FRAME_SZ) ||
        (strlcpy(info.name, dev->name, IFNAMSIZ) >= IFNAMSIZ)) {
        qdf_err("source too long\n");
        return -1;
    }

    memcpy(info.macaddr, macaddr, IEEE80211_ADDR_LEN);
    memcpy(info.frame, frame, frame_len);
    info.frameSize = frame_len;

    ald_notify(vap, IEEE80211_ALD_ANQP_FRAME_RECEIVED, sizeof(info), &info);
    return 0;
}

int ieee80211_ioctl_ald_getStatistics(struct net_device *dev, void *vinfo, void *w, char *extra)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int retv = 0;
    struct ald_stat_info *param = NULL;

    param = (struct ald_stat_info *)qdf_mem_malloc(sizeof(struct ald_stat_info));
    if (!param)
        return -ENOMEM;

    if (copy_from_user(param, ((union iwreq_data *)w)->data.pointer, sizeof(struct ald_stat_info))) {
        OS_FREE(param);
        return -EFAULT;
    }
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG,
            "%s parameter is %s 0x%x get1\n", __func__, param->name, param->cmd);

    retv = wlan_ald_get_statistics(vap, param);
    vap->iv_ald->staticp = NULL;

    if(!copy_to_user(((union iwreq_data *)w)->data.pointer, param, sizeof(struct ald_stat_info))) {
        qdf_print("%s:%d copy to user failed", __func__, __LINE__);
        retv = -EFAULT;
    }
    qdf_mem_free(param);
    return retv;
}

void
ieee80211_buffull_handler(struct ieee80211com *ic)
{
    struct ieee80211vap *vap;
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap) {
            IEEE80211_DELIVER_EVENT_BUFFULL(vap);
            break;
        }
    }

}
qdf_export_symbol(ieee80211_buffull_handler);

#endif
