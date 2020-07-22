/*
 * Copyright (c) 2011-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * copyright (c) 2011 Atheros Communications Inc.
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
#include "wlan_mlme_vdev_mgmt_ops.h"
#include <cdp_txrx_cmn.h>
#include <cdp_txrx_ctrl.h>
#include <cdp_txrx_wds.h>
#include <dp_txrx.h>
#include <wlan_osif_priv.h>

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#include <osif_nss_wifiol_vdev_if.h>
#endif
#include <wlan_objmgr_psoc_obj.h>
#include <wlan_objmgr_pdev_obj.h>
#include <cdp_txrx_mon.h>
#include <ieee80211_objmgr_priv.h>

#if MESH_MODE_SUPPORT
#include <if_meta_hdr.h>
#endif

#if QCA_SUPPORT_GPR
#include "ieee80211_ioctl_acfg.h"
#endif

#include <wlan_vdev_mgr_tgt_if_tx_api.h>
#include <wlan_vdev_mgr_tgt_if_rx_defs.h>
#include "vdev_mgr/core/src/vdev_mgr_ops.h"
#include "include/wlan_vdev_mlme.h"
#include <wlan_vdev_mgr_ucfg_api.h>
#include <wlan_vdev_mgr_utils_api.h>
#include <wlan_mlme_dbg.h>
#include <wlan_mlme_dispatcher.h>
#include <osif_private.h>
#include <ieee80211_channel.h>
#include <wlan_dfs_tgt_api.h>
#include <wlan_dfs_utils_api.h>
#include <wlan_dfs_ucfg_api.h>
#include <wlan_utility.h>
#include <wlan_psoc_mlme.h>
#include <wlan_psoc_mlme_main.h>

#ifdef WLAN_SUPPORT_FILS
#include <wlan_fd_ucfg_api.h>
#include <wlan_fd_utils_api.h>
#endif /* WLAN_SUPPORT_FILS */

#define DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS  (IEEE80211_INACT_RUN * IEEE80211_INACT_WAIT)
#define DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_IDLE_TIME_SECS          (DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS - 5)
#define DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MIN_IDLE_TIME_SECS          (DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_IDLE_TIME_SECS/2)

uint8_t wlanphymode2ieeephymode[WLAN_PHYMODE_11AXA_HE80_80 + 1] = {
	IEEE80211_MODE_AUTO,                /* WLAN_PHYMODE_AUTO,          */
	IEEE80211_MODE_11A,                 /* WLAN_PHYMODE_11A,           */
	IEEE80211_MODE_11B,                 /* WLAN_PHYMODE_11B,           */
	IEEE80211_MODE_11G,                 /* WLAN_PHYMODE_11G,           */
	0,                                  /* WLAN_PHYMODE_11G_ONLY,      */
	IEEE80211_MODE_11NA_HT20,           /* WLAN_PHYMODE_11NA_HT20,     */
	IEEE80211_MODE_11NG_HT20,           /* WLAN_PHYMODE_11NG_HT20,     */
	IEEE80211_MODE_11NA_HT40,           /* WLAN_PHYMODE_11NA_HT40,     */
	IEEE80211_MODE_11NG_HT40PLUS,       /* WLAN_PHYMODE_11NG_HT40PLUS, */
	IEEE80211_MODE_11NG_HT40MINUS,      /* WLAN_PHYMODE_11NG_HT40MINUS,*/
	IEEE80211_MODE_11NG_HT40,           /* WLAN_PHYMODE_11NG_HT40,     */
	IEEE80211_MODE_11AC_VHT20,          /* WLAN_PHYMODE_11AC_VHT20,    */
	0,                                  /* WLAN_PHYMODE_11AC_VHT20_2G, */
	IEEE80211_MODE_11AC_VHT40,          /* WLAN_PHYMODE_11AC_VHT40,    */
	IEEE80211_MODE_11AC_VHT40PLUS,      /* WLAN_PHYMODE_11AC_VHT40PLUS_2G,*/
	IEEE80211_MODE_11AC_VHT40MINUS,     /* WLAN_PHYMODE_11AC_VHT40MINUS_2G*/
	0,                                  /* WLAN_PHYMODE_11AC_VHT40_2G, */
	IEEE80211_MODE_11AC_VHT80,          /* WLAN_PHYMODE_11AC_VHT80,    */
	0,                                  /* WLAN_PHYMODE_11AC_VHT80_2G, */
	IEEE80211_MODE_11AC_VHT160,         /* WLAN_PHYMODE_11AC_VHT160,   */
	IEEE80211_MODE_11AC_VHT80_80,       /* WLAN_PHYMODE_11AC_VHT80_80, */
	IEEE80211_MODE_11AXA_HE20,          /* WLAN_PHYMODE_11AXA_HE20,    */
	IEEE80211_MODE_11AXG_HE20,          /* WLAN_PHYMODE_11AXG_HE20,    */
	IEEE80211_MODE_11AXA_HE40,          /* WLAN_PHYMODE_11AXA_HE40MINUS*/
	IEEE80211_MODE_11AXG_HE40PLUS,      /* WLAN_PHYMODE_11AXG_HE40PLUS,*/
	IEEE80211_MODE_11AXG_HE40MINUS,     /* WLAN_PHYMODE_11AXG_HE40MINUS*/
	IEEE80211_MODE_11AXG_HE40,          /* WLAN_PHYMODE_11AXG_HE40,    */
	IEEE80211_MODE_11AXA_HE80,          /* WLAN_PHYMODE_11AXA_HE80,    */
	0,                                  /* WLAN_PHYMODE_11AXA_HE80,    */
	IEEE80211_MODE_11AXA_HE160,         /* WLAN_PHYMODE_11AXA_HE160,   */
	IEEE80211_MODE_11AXA_HE80_80,       /* WLAN_PHYMODE_11AXA_HE80_80, */
};
qdf_export_symbol(wlanphymode2ieeephymode);

uint32_t num_chain_from_chain_mask(uint32_t mask)
{
    int num_rf_chain = 0;

    while (mask) {
        if (mask & 0x1)
            num_rf_chain++;

        mask >>= 1;
    }

    return num_rf_chain;
}

#if ATH_NON_BEACON_AP
bool static inline is_beacon_tx_suspended(struct ieee80211vap *vap)
{
    return (IEEE80211_VAP_IS_NON_BEACON_ENABLED(vap) ||
                  ieee80211_mlme_beacon_suspend_state(vap) ||
                  ieee80211_nawds_disable_beacon(vap));
}
#else
bool static inline is_beacon_tx_suspended(struct ieee80211vap *vap)
{
     return (ieee80211_mlme_beacon_suspend_state(vap) ||
                  ieee80211_nawds_disable_beacon(vap));
}
#endif

#if ATH_SUPPORT_WRAP
static inline void
wrap_disable_da_war_on_all_radios(struct ieee80211com *ic,
                                  struct cdp_soc_t *soc_txrx_handle,
                                  uint8_t vdev_id)
{
    int i;
    struct ieee80211vap *tmpvap = NULL;
    cdp_config_param_type val = {0};

    /* set wrap_disable_da_war to true so that none of the vaps in the ic
     * will have da_war enabled */
    ic->wrap_disable_da_war = true;

    /* Disable DA_WAR for current vap */
    cdp_txrx_set_vdev_param(soc_txrx_handle, vdev_id, CDP_ENABLE_WDS, val);

    /* Disable DA_WAR for all vaps in current current ic */
    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        cdp_txrx_set_vdev_param(soc_txrx_handle,
                                wlan_vdev_get_id(tmpvap->vdev_obj), CDP_ENABLE_WDS, val);
    }

    /* Disable DA_WAR for all vaps in other ics */
    for (i = 0; i < MAX_RADIO_CNT-1; i++) {
        struct ieee80211com *other_ic = NULL;
        spin_lock(&ic->ic_lock);
        if (ic->other_ic[i] == NULL) {
            spin_unlock(&ic->ic_lock);
            continue;
        }
        other_ic = ic->other_ic[i];
        other_ic->wrap_disable_da_war = true;
        spin_unlock(&ic->ic_lock);

        TAILQ_FOREACH(tmpvap, &other_ic->ic_vaps, iv_next) {
            cdp_txrx_set_vdev_param(soc_txrx_handle,
                                    wlan_vdev_get_id(tmpvap->vdev_obj), CDP_ENABLE_WDS, val);
        }
    }
}
#endif

QDF_STATUS
vdev_mlme_set_param(struct vdev_mlme_obj *vdev_mlme,
                    enum wlan_mlme_cfg_id param_id,
                    struct wlan_vdev_mgr_cfg mlme_cfg)
{
    osif_dev *osifp;
    struct wlan_objmgr_vdev *vdev;
    struct vdev_osif_priv *osif_priv;

    if (!vdev_mlme || !(vdev = vdev_mlme->vdev)) {
        mlme_err("Couldn't set param_id = %d ", param_id);
        return QDF_STATUS_E_FAILURE;
    }

    osif_priv = wlan_vdev_get_ospriv(vdev);
    if (!osif_priv)
        goto set_param_fail;

    osifp = (osif_dev *)(osif_priv->legacy_osif_priv);
    if (!osifp || osifp->is_delete_in_progress)
        goto set_param_fail;

    return wlan_util_vdev_mlme_set_param(vdev_mlme, param_id, mlme_cfg);

set_param_fail:
    mlme_debug("PSOC_%d VDEV_%d : %d param set not allowed",
             wlan_psoc_get_id(wlan_vdev_get_psoc(vdev)),
             wlan_vdev_get_id(vdev), param_id);
    return QDF_STATUS_E_FAILURE;
}

qdf_export_symbol(vdev_mlme_set_param);

static QDF_STATUS mlme_ext_vap_setup(struct vdev_mlme_obj *vdev_mlme,
                                     u_int32_t flags,
                                     const u_int8_t *mataddr,
                                     const u_int8_t *bssid)
{
    enum QDF_OPMODE opmode;
    uint32_t mbssid_flags = 0;
    uint8_t vdevid_trans = 0;
    uint16_t type = 0;
    uint16_t sub_type = 0;
    struct wlan_objmgr_vdev *vdev;
    struct ieee80211com *ic;
    struct ieee80211vap *vap;
#if ATH_SUPPORT_WRAP
    u_int8_t bssid_var[QDF_MAC_ADDR_SIZE];
    u_int8_t mataddr_var[QDF_MAC_ADDR_SIZE];
#endif

    vdev = vdev_mlme->vdev;
    vap = vdev_mlme->ext_vdev_ptr;
    ic = vap->iv_ic;

    opmode = wlan_vdev_mlme_get_opmode(vdev);
    switch (opmode) {
    case QDF_STA_MODE:
        type = WLAN_VDEV_MLME_TYPE_STA;
        break;
    case QDF_IBSS_MODE:
        type = WLAN_VDEV_MLME_TYPE_IBSS;
        break;
    case QDF_MONITOR_MODE:
        type = WLAN_VDEV_MLME_TYPE_MONITOR;
        break;
    case QDF_SAP_MODE:
    case QDF_WDS_MODE:
    case QDF_BTAMP_MODE:
        type = WLAN_VDEV_MLME_TYPE_AP;
        break;
    default:
        return QDF_STATUS_E_FAILURE;
    }

    if (flags & IEEE80211_P2PDEV_VAP) {
        sub_type = WLAN_VDEV_MLME_SUBTYPE_P2P_DEVICE;
    }else if (flags & IEEE80211_P2PCLI_VAP) {
        sub_type = WLAN_VDEV_MLME_SUBTYPE_P2P_CLIENT;
    }else if (flags & IEEE80211_P2PGO_VAP) {
        sub_type = WLAN_VDEV_MLME_SUBTYPE_P2P_GO;
    }

    if (flags & IEEE80211_SPECIAL_VAP) {
        vap->iv_special_vap_mode = 1;
    }
#if ATH_SUPPORT_NAC
    if (flags & IEEE80211_SMART_MONITOR_VAP) {
        vap->iv_smart_monitor_vap =1;
        sub_type = WLAN_VDEV_MLME_SUBTYPE_SMART_MONITOR;
    }
#endif

    vap->mhdr_len = 0;
#if MESH_MODE_SUPPORT
    if (flags & IEEE80211_MESH_VAP) {
        if (!ic->ic_mesh_vap_support) {
            mlme_err("Mesh vap not supported by this radio!!");
            return QDF_STATUS_E_CANCELED;
        }
        vap->iv_mesh_vap_mode =1;
        sub_type = WLAN_VDEV_MLME_SUBTYPE_MESH;
        vap->mhdr_len = sizeof(struct meta_hdr_s);
        vap->mhdr = 0;
    }
#endif

#if ATH_SUPPORT_WRAP
    OS_MEMCPY(mataddr_var, mataddr, QDF_MAC_ADDR_SIZE);
    OS_MEMCPY(bssid_var, bssid, QDF_MAC_ADDR_SIZE);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    vap->iv_nss_qwrap_en = 1;
#endif
    if ((opmode == QDF_SAP_MODE) && (flags & IEEE80211_WRAP_VAP)) {
        vap->iv_wrap = 1;
        ic->ic_nwrapvaps++;
    } else if ((opmode == QDF_STA_MODE) && (flags & IEEE80211_CLONE_MACADDR)) {
        if (!(flags & IEEE80211_WRAP_NON_MAIN_STA))
        {
            /*
             * Main ProxySTA VAP for uplink WPS PBC and
             * downlink multicast receive.
             */
            vap->iv_mpsta = 1;
        } else {
            /*
             * Generally, non-Main ProxySTA VAP's don't need to
             * register umac event handlers. We can save some memory
             * space by doing so. This is required to be done before
             * ieee80211_vap_setup. However we still give the scan
             * capability to the first ATH_NSCAN_PSTA_VAPS non-Main
             * PSTA VAP's. This optimizes the association speed for
             * the first several PSTA VAP's (common case).
             */
#define ATH_NSCAN_PSTA_VAPS 0
            if (ic->ic_nscanpsta >= ATH_NSCAN_PSTA_VAPS)
                vap->iv_no_event_handler = 1;
            else
                ic->ic_nscanpsta++;
        }
        vap->iv_psta = 1;
        ic->ic_npstavaps++;
    }

    if (flags & IEEE80211_CLONE_MATADDR) {
        vap->iv_mat = 1;
        OS_MEMCPY(vap->iv_mat_addr, mataddr_var, QDF_MAC_ADDR_SIZE);
    }

    if (flags & IEEE80211_WRAP_WIRED_STA) {
        vap->iv_wired_pvap = 1;
    }
    if (vap->iv_psta) {
        if (!vap->iv_mpsta) {
            sub_type = WLAN_VDEV_MLME_SUBTYPE_PROXY_STA;
        }
    }

#endif

    if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE)) {
        if (opmode == QDF_SAP_MODE) {
            /* Set up this VDEV as transmitting or non-transmitting */
           if (ieee80211_mbssid_setup(vap)) {
               mlme_err("MBSSID setup failed for vap! \n");
               return QDF_STATUS_E_FAILURE;
            }
        }

        if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
            mbssid_flags = WLAN_VDEV_MLME_FLAGS_NON_TRANSMIT_AP;
            vdevid_trans = ic->ic_mbss.transmit_vap->iv_unit;
        } else {
            mbssid_flags = WLAN_VDEV_MLME_FLAGS_TRANSMIT_AP;
	}
    } else {
        mbssid_flags = WLAN_VDEV_MLME_FLAGS_NON_MBSSID_AP;
    }

    vdev_mlme->mgmt.mbss_11ax.mbssid_flags = mbssid_flags;
    vdev_mlme->mgmt.mbss_11ax.vdevid_trans = vdevid_trans;
    vdev_mlme->mgmt.generic.type = type;
    vdev_mlme->mgmt.generic.subtype = sub_type;
    vdev_mlme->mgmt.inactivity_params.keepalive_max_unresponsive_time_secs =
                    DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS;
    vdev_mlme->mgmt.inactivity_params.keepalive_max_idle_inactive_time_secs =
                    DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_IDLE_TIME_SECS;
    vdev_mlme->mgmt.inactivity_params.keepalive_min_idle_inactive_time_secs =
                    DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MIN_IDLE_TIME_SECS;
    vdev_mlme->proto.generic.nss_2g = ic->ic_rx_chainmask;
    vdev_mlme->proto.generic.nss_5g = ic->ic_tx_chainmask;

    return QDF_STATUS_SUCCESS;
}

static struct ieee80211vap
*mlme_ext_vap_create_pre_init(struct ieee80211com *ic,
                              struct vdev_mlme_obj *vdev_mlme,
                              enum ieee80211_opmode opmode,
                              u_int32_t            flags,
                              const u_int8_t      *mataddr,
                              const u_int8_t      *bssid)
{
    struct ieee80211vap *vap = NULL;
    struct wlan_objmgr_vdev *vdev = vdev_mlme->vdev;

#if ATH_SUPPORT_WRAP
    if ((opmode == IEEE80211_M_STA) && (ic->ic_nstavaps > 0)) {
       if (!(flags & IEEE80211_WRAP_WIRED_STA) &&
           !(flags & IEEE80211_CLONE_MATADDR )) {
           return NULL;
       }
    }
#endif

    /* OL initialization
     * This also takes care of vap allocation through avn
     * vap allocation will be moved here after removing
     * avn and scn dependencies
     */
    vap = ic->ic_vap_create_pre_init(vdev_mlme, flags);
    if (!vap) {
        mlme_err("Pre init validation failed for creating vap");
        return NULL;
    }

    vap->vdev_obj = vdev;
    vap->iv_ic = ic;
    vap->iv_opmode = opmode;
    vdev_mlme->ext_vdev_ptr = vap;
    vap->vdev_mlme = vdev_mlme;
    if (opmode == IEEE80211_M_STA) {
        ieee80211_vap_reset_ap_vaps_set(vap);
    }

    if (mlme_ext_vap_setup(vdev_mlme, flags,
                           mataddr, bssid) != QDF_STATUS_SUCCESS) {
        mlme_err("Unable to setup vap params");
        goto mlme_ext_vap_create_pre_init_alloc_end;
    }

    return vap;

mlme_ext_vap_create_pre_init_alloc_end:
    ic->ic_vap_free(vap);
    return NULL;
}

static QDF_STATUS mlme_ext_vap_create_complete(
                                    struct vdev_mlme_obj *vdev_mlme,
                                    int                 opmode,
                                    int                 scan_priority_base,
                                    int                 flags,
                                    const u_int8_t      *bssid,
                                    const u_int8_t      *mataddr)
{
    struct cdp_soc_t *soc_txrx_handle;
    struct ieee80211vap *vap = vdev_mlme->ext_vdev_ptr;
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_objmgr_vdev *vdev = vdev_mlme->vdev;
    struct wlan_objmgr_psoc *psoc = wlan_vdev_get_psoc(vdev);
    uint8_t vdev_id;
    int nactivevaps = 0;
#if DBDC_REPEATER_SUPPORT
    dp_pdev_link_aggr_t *pdev_lag;
#endif
    cdp_config_param_type val = {0};

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    vdev_id = wlan_vdev_get_id(vdev);
    vap->iv_is_up = false;
    vap->iv_is_started = false;
    vap->iv_unit = vdev_id;

    ieee80211_vap_setup(ic, vap, vdev_mlme, opmode, scan_priority_base,
                        flags, bssid);

    /* FIMPLE: update to core mlme structures */
    vdev_mlme->mgmt.generic.ampdu = IEEE80211_AMPDU_SUBFRAME_MAX;
    vdev_mlme->mgmt.generic.amsdu = ic->ic_vht_amsdu;

    /*  Enable MU-BFER & SU-BFER if the Tx chain number
     *  is 0x2, 0x3 and 0x4 and not otherwise.   */
    if(ieee80211_get_txstreams(ic, vap) < 2) {
        vdev_mlme->proto.vht_info.subfer = 0;
        vdev_mlme->proto.vht_info.mubfer = 0;
    }
#if ATH_SUPPORT_WRAP
    if (vap->iv_mpsta) {
        vap->iv_ic->ic_mpsta_vap = vap;
        wlan_pdev_nif_feat_cap_set(vap->iv_ic->ic_pdev_obj,
                                   WLAN_PDEV_F_WRAP_EN);
    }
    if (vap->iv_wrap) {
         vap->iv_ic->ic_wrap_vap = vap;
    }
#if ATH_PROXY_NOACK_WAR
    if (vap->iv_mpsta || vap->iv_wrap) {
        ic->proxy_ast_reserve_wait.blocking = 1;
        qdf_semaphore_init(&(ic->proxy_ast_reserve_wait.sem_ptr));
        qdf_semaphore_acquire(&(ic->proxy_ast_reserve_wait.sem_ptr));
    }
#endif
#endif
    ieee80211vap_set_macaddr(vap, bssid);

#if ATH_SUPPORT_WRAP
    if (vap->iv_wrap || vap->iv_psta) {
        if (ic->ic_nwrapvaps) {
            ieee80211_ic_enh_ind_rpt_set(vap->iv_ic);
        }
    }
#endif

    /* Enabling the advertisement of STA's maximum capabilities instead of
     * the negotiated channel width capabilties (HT and VHT) with the AP */
    if (vap->iv_opmode == IEEE80211_M_STA)
        vap->iv_sta_max_ch_cap = 1;

    /* set user selected channel width to an invalid value by default */
    vap->iv_chwidth = IEEE80211_CWM_WIDTHINVALID;
    vap->iv_he_ul_ppdu_bw = IEEE80211_CWM_WIDTHINVALID;

    /* Enable 256 QAM by default */
    vap->iv_256qam = 1;

    vap->iv_no_cac = 0;

     /*
      * init IEEE80211_DPRINTF control object
      * Register with asf.
      */
    ieee80211_dprintf_init(vap);

#if DBG_LVL_MAC_FILTERING
    vap->iv_print.dbgLVLmac_on = 0; /*initialize dbgLVLmac flag*/
#endif

    nactivevaps = ieee80211_vaps_active(ic);
    if (nactivevaps==0) {
        ic->ic_opmode = opmode;
    }

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (ic->ic_nss_vap_create(vdev_mlme) != QDF_STATUS_SUCCESS) {
         ieee80211_acl_detach(vap);
#if DBDC_REPEATER_SUPPORT
        if (opmode == IEEE80211_M_STA) {
#if ATH_SUPPORT_WRAP
            /*
             * set sta_vdev to NULL only if its mpsta or a normal sta but not for
             * psta
             */
            if (vap->iv_mpsta || (!vap->iv_mpsta && !vap->iv_psta))
#endif
                dp_lag_pdev_set_sta_vdev(ic->ic_pdev_obj, NULL);
        }

        if (opmode == IEEE80211_M_HOSTAP)
            dp_lag_pdev_set_ap_vdev(ic->ic_pdev_obj, vdev_id, NULL);
#endif
        goto mlme_ext_vap_create_complete_end;
    }
#endif

    /*Setting default value of security type to cdp_sec_type_none*/
    val.cdp_vdev_param_cipher_en = cdp_sec_type_none;
    cdp_txrx_set_vdev_param(soc_txrx_handle,
            vdev_id, CDP_ENABLE_CIPHER,
            val);

    /* Setting default value to be retrieved
     * when iwpriv get_inact command is used */

#if ATH_SUPPORT_WRAP
    if (vap->iv_psta) {
        val.cdp_vdev_param_proxysta = 1;
        cdp_txrx_set_vdev_param(soc_txrx_handle, vdev_id, CDP_ENABLE_PROXYSTA, val);
    }
    if (vap->iv_psta && vap->iv_ic->ic_wrap_com->wc_isolation) {
        struct ieee80211vap *mpsta_vap = vap->iv_ic->ic_mpsta_vap;

        val.cdp_vdev_param_qwrap_isolation = 1;
        cdp_txrx_set_vdev_param(soc_txrx_handle,
                     vdev_id,
                     CDP_ENABLE_QWRAP_ISOLATION, val);
        cdp_txrx_set_vdev_param(soc_txrx_handle,
                     wlan_vdev_get_id(mpsta_vap->vdev_obj),
                     CDP_ENABLE_QWRAP_ISOLATION, val);
    }

#endif

#if UMAC_SUPPORT_WNM
    /* configure wnm default settings */
    ieee80211_vap_wnm_set(vap);
#endif

#if MESH_MODE_SUPPORT
    if (vap->iv_mesh_vap_mode) {
        val.cdp_vdev_param_mesh_mode = 1;
        cdp_txrx_set_vdev_param(soc_txrx_handle, vdev_id, CDP_MESH_MODE, val);
    }
#endif
#ifndef ATH_WIN_NWF
    vap->iv_tx_encap_type = htt_cmn_pkt_type_ethernet;
    vap->iv_rx_decap_type = htt_cmn_pkt_type_ethernet;
#else
    vap->iv_tx_encap_type = htt_cmn_pkt_type_native_wifi;
    vap->iv_rx_decap_type = htt_cmn_pkt_type_native_wifi;
#endif
    /* disable RTT by default. WFA requirement */
    vap->rtt_enable=0;

    /* Enable EXT NSS support on vap by default if FW provides support */
    if (ic->ic_ext_nss_capable) {
        vap->iv_ext_nss_support = 1;
    }

    if (opmode == IEEE80211_M_HOSTAP)
        vap->iv_rev_sig_160w = DEFAULT_REV_SIG_160_STATUS;

#if ATH_SUPPORT_WRAP
    if (opmode == IEEE80211_M_STA)
        ic->ic_nstavaps++;
#endif

    /* Enable WDS by default in AP mode, except for QWRAP mode */
    if (opmode == IEEE80211_M_HOSTAP) {
        val.cdp_vdev_param_wds = 1;
#if ATH_SUPPORT_WRAP
        if (!vap->iv_wrap && !ic->wrap_disable_da_war) {
            cdp_txrx_set_vdev_param(soc_txrx_handle,
                                    vdev_id, CDP_ENABLE_WDS, val);
        } else {
            wrap_disable_da_war_on_all_radios(ic, soc_txrx_handle, vdev_id);
        }
#else
        cdp_txrx_set_vdev_param(soc_txrx_handle, vdev_id, CDP_ENABLE_WDS, val);
#endif
    }

#if ATH_SUPPORT_WRAP
    if (opmode == IEEE80211_M_STA && vap->iv_psta) {
        wrap_disable_da_war_on_all_radios(ic, soc_txrx_handle, vdev_id);
    }
#endif



#if DBDC_REPEATER_SUPPORT
    pdev_lag = dp_get_lag_handle(vdev);

    if (pdev_lag) {
        if (opmode == IEEE80211_M_HOSTAP) {
            dp_lag_pdev_set_ap_vdev(ic->ic_pdev_obj, vdev_id, vdev);
        } else {
#if ATH_SUPPORT_WRAP
            /*
             * set sta_vdev to vdev only if its mpsta or a normal sta but not
             * for psta
             */
            if (vap->iv_mpsta || (!vap->iv_mpsta && !vap->iv_psta))
#endif
                dp_lag_pdev_set_sta_vdev(ic->ic_pdev_obj, vdev);
        }
    }
#endif

    return QDF_STATUS_SUCCESS;

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
mlme_ext_vap_create_complete_end:
    return QDF_STATUS_E_FAILURE;
#endif
}

struct ieee80211vap
*mlme_ext_vap_create(struct ieee80211com *ic,
                     struct vdev_mlme_obj *vdev_mlme,
                     enum ieee80211_opmode opmode,
                     int                 scan_priority_base,
                     u_int32_t           flags,
                     const u_int8_t      bssid[QDF_MAC_ADDR_SIZE],
                     const u_int8_t      mataddr[QDF_MAC_ADDR_SIZE])
{
    QDF_STATUS status;
    struct ieee80211vap *vap = NULL;
    struct wlan_objmgr_vdev *vdev = vdev_mlme->vdev;
    struct wlan_objmgr_psoc *psoc = wlan_vdev_get_psoc(vdev);
    struct vdev_osif_priv *vdev_osifp = NULL;
    struct cdp_soc_t *soc_txrx_handle;

    vdev_osifp = wlan_vdev_get_ospriv(vdev);
    if (!vdev_osifp) {
        QDF_ASSERT(0);
        return NULL;
    }

    /* vap allocation */
    vap = mlme_ext_vap_create_pre_init(ic, vdev_mlme, opmode, flags, mataddr,
		                       bssid);
    if (vap == NULL) {
        mlme_err("failed to create a vap object");
        return NULL;
    }

    /* NSS allocation */
    status = ic->ic_vap_create_init(vdev_mlme);
    if (status != QDF_STATUS_SUCCESS) {
        mlme_err("Pre init failed for creating vap");
        goto mlme_ext_vap_create_init_end;
    }

    /* send create command */
    status = vdev_mgr_create_send(vdev_mlme);
    if (status != QDF_STATUS_SUCCESS) {
        mlme_err("Failed to send create cmd");
        goto mlme_ext_vap_create_send_end;
    }

    status = cdp_vdev_set_dp_ext_txrx_handle(
                                    wlan_psoc_get_dp_handle(psoc),
                                    vdev->vdev_objmgr.vdev_id,
                                    sizeof(dp_vdev_txrx_handle_t));
    if (status != QDF_STATUS_SUCCESS) {
        mlme_err("Failed to set vdev extended handle");
        goto mlme_ext_vap_create_complete_end;
    }

    if (dp_vdev_ext_attach(wlan_psoc_get_dp_handle(psoc), wlan_vdev_get_id(vdev),
                           vdev->vdev_mlme.macaddr) != QDF_STATUS_SUCCESS) {
        mlme_err("Failed to attach vdev extended handle");
        goto mlme_ext_vap_create_complete_end;
    }
    /* send WMI cfg */
    if (tgt_vdev_mgr_create_complete(vdev_mlme) != QDF_STATUS_SUCCESS) {
        mlme_err("Failed to init after create cmd");
        goto mlme_ext_vap_create_complete_end;
    }

    /* feature flag setup and NSS vap creation */
    if (mlme_ext_vap_create_complete(vdev_mlme, opmode, scan_priority_base,
                                     flags, bssid,
                                     mataddr) != QDF_STATUS_SUCCESS) {
        mlme_err("Failed to init after create cmd");
        goto mlme_ext_vap_create_complete_end;
    }

    /* OL specific WMI cfg */
    if (ic->ic_vap_create_post_init(vdev_mlme, flags)
                                                 != QDF_STATUS_SUCCESS) {
        mlme_err("Failed to init after create cmd");
        goto mlme_ext_vap_create_complete_end;
    }

    return vap;

mlme_ext_vap_create_complete_end:

    /* WAR: compoent attach and detach is done since delete request
       and response will expect vdev_mlme object */
    wlan_objmgr_vdev_component_obj_attach((struct wlan_objmgr_vdev *)vdev,
                                          WLAN_UMAC_COMP_MLME,
                                          (void *)vdev_mlme,
                                          QDF_STATUS_SUCCESS);

     ieee80211_dprintf_deregister(vap);
     soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
     cdp_vdev_detach(soc_txrx_handle, wlan_vdev_get_id(vdev), NULL, NULL);
     vdev_mgr_delete_send(vdev_mlme);
     wlan_objmgr_vdev_component_obj_detach((struct wlan_objmgr_vdev *)vdev,
                                           WLAN_UMAC_COMP_MLME,
                                           (void *)vdev_mlme);

mlme_ext_vap_create_send_end:
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    ic->ic_nss_vap_destroy(vap->vdev_obj);
#endif
mlme_ext_vap_create_init_end:
    vdev_mlme->ext_vdev_ptr = NULL;
    vap->vdev_mlme = NULL;
    ic->ic_vap_free(vap);

    return NULL;
}

static QDF_STATUS mlme_ext_vap_post_delete_setup(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
#if QCA_SUPPORT_GPR
#if UMAC_SUPPORT_ACFG
    acfg_netlink_pvt_t *acfg_nl;
#endif
#endif

    if (!ic)
        return QDF_STATUS_E_FAILURE;

#if ATH_SUPPORT_WRAP
    if (ieee80211vap_get_opmode(vap) == IEEE80211_M_STA) {
        ic->ic_nstavaps--;
    }
#endif

#if QCA_SUPPORT_GPR
    ic = vap->iv_ic;
#if UMAC_SUPPORT_ACFG
    acfg_nl = (acfg_netlink_pvt_t *)ic->ic_acfg_handle;
    if (qdf_semaphore_acquire_intr(acfg_nl->sem_lock)){
        /*failed to acquire mutex*/
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                 "%s(): failed to acquire mutex!\n", __func__);
    }
#endif
    if (ic->ic_gpr_enable) {
        ic->ic_gpr_enable_count--;
        if (ic->ic_gpr_enable_count == 0) {
            qdf_hrtimer_kill(&ic->ic_gpr_timer);
            qdf_mem_free(ic->acfg_frame);
            ic->acfg_frame = NULL;
            ic->ic_gpr_enable = 0;
            qdf_err("\nStopping GPR timer as this is last vap with gpr \n");
        }
    }
#if UMAC_SUPPORT_ACFG
    qdf_semaphore_release(acfg_nl->sem_lock);
#endif
#endif
    /* deregister IEEE80211_DPRINTF control object */
    ieee80211_dprintf_deregister(vap);

    ic->ic_vap_post_delete(vap);

    /*
     * Should a callback be provided for notification once the
     * txrx vdev object has actually been deleted?
     */
#if DBDC_REPEATER_SUPPORT
    if (ieee80211vap_get_opmode(vap) == IEEE80211_M_STA) {
#if ATH_SUPPORT_WRAP
        /*
         * set sta_vdev to NULL only if its mpsta or a normal sta but not for
         * psta
         */
        if (vap->iv_mpsta || (!vap->iv_mpsta && !vap->iv_psta))
#endif
            dp_lag_pdev_set_sta_vdev(vap->iv_ic->ic_pdev_obj, NULL);
    }

    if (ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP)
	    dp_lag_pdev_set_ap_vdev(ic->ic_pdev_obj, vap->iv_unit, NULL);
#endif

#if ATH_SUPPORT_WRAP
    if (vap->iv_mpsta) {
        vap->iv_ic->ic_mpsta_vap = NULL;
        wlan_pdev_nif_feat_cap_clear(vap->iv_ic->ic_pdev_obj,
                                     WLAN_PDEV_F_WRAP_EN);
    }
    if (vap->iv_wrap) {
         vap->iv_ic->ic_wrap_vap = NULL;
    }
#endif

    if (ic && wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE)) {
        if (!IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
            ic->ic_mbss.transmit_vap = NULL;
        } else {
            qdf_clear_bit(vap->vdev_mlme->mgmt.mbss_11ax.profile_idx - 1,
                          &ic->ic_mbss.bssid_index_bmap[0]);
            IEEE80211_VAP_MBSS_NON_TRANS_DISABLE(vap);
            vap->iv_mbss.mbssid_add_del_profile = 0;
        }
    }

    return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_ext_vap_delete(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_objmgr_psoc *psoc = wlan_vdev_get_psoc(vap->vdev_obj);
    struct cdp_soc_t *soc_txrx_handle;
#if ATH_SUPPORT_NAC_RSSI
    char nullmac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#endif

    /* delete key before vdev delete */
    delete_default_vap_keys(vap);
#if ATH_SUPPORT_WRAP
    /*
     * Both WRAP and ProxySTA VAP's populate keycache slot with
     * vap->iv_myaddr even when security is not used.
     */
    if (vap->iv_wrap) {
        ic->ic_nwrapvaps--;
    } else if (vap->iv_psta) {
        if (!vap->iv_mpsta) {
            if (vap->iv_no_event_handler == 0)
                ic->ic_nscanpsta--;
        }
    ic->ic_npstavaps--;
    }
#endif
    ic->ic_vap_delete(vap->vdev_obj);

#if ATH_SUPPORT_NAC
    /* For HKv2, Nac entries are delted in AST table by FW
     * so host doesn't have to send nac delete cmd.
     * nac entries in dp_pdev are deleted by host
     * in vdev detach. Nac deletes are sent for non
     * HKv2 case only.
     */
    if (vap->iv_smart_monitor_vap) {
        struct ieee80211_nac *nac = &vap->iv_nac;
        int i = 0;
        vap->iv_smart_monitor_vap = 0;
        if (!vap->iv_ic->ic_hw_nac_monitor_support) {
           for (i = 0; i < NAC_MAX_CLIENT; i++) {
                vap->iv_neighbour_rx(vap , 0, IEEE80211_NAC_PARAM_DEL,
                                     IEEE80211_NAC_MACTYPE_CLIENT,
                                     nac->client[i].macaddr);
           }
        }
    }
#endif
    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

#if ATH_SUPPORT_NAC_RSSI
    if (vap->iv_scan_nac_rssi &&
       !IEEE80211_ADDR_EQ((vap->iv_nac_rssi.client_mac), nullmac)) {
       cdp_update_filter_neighbour_peers(soc_txrx_handle,
                                         wlan_vdev_get_id(vap->vdev_obj),
                                         IEEE80211_NAC_PARAM_DEL,
                                         vap->iv_nac_rssi.client_mac);
    }
#endif

    if (vdev_mgr_delete_send(vap->vdev_mlme) != QDF_STATUS_SUCCESS)
        mlme_err("Unable to remove an interface for ath_dev.");

    return mlme_ext_vap_post_delete_setup(vap);
}

QDF_STATUS mlme_ext_vap_down(struct wlan_objmgr_vdev *vdev)
{
    struct ieee80211vap *vap;
    struct ieee80211com *ic;
    QDF_STATUS status;
    struct vdev_mlme_obj *vdev_mlme = NULL;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap) {
        mlme_err("(vdev-id:%d) vap  is NULL", wlan_vdev_get_id(vdev));
        return QDF_STATUS_E_FAILURE;
    }

    vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);
    if (!vap) {
        mlme_err("(vdev-id:%d) vdev_mlme  is NULL", wlan_vdev_get_id(vdev));
        return QDF_STATUS_E_FAILURE;
    }

    ic = vap->iv_ic;
    if (!ic) {
        mlme_err("(vdev-id:%d) ic  is NULL", wlan_vdev_get_id(vdev));
        return QDF_STATUS_E_FAILURE;
    }

    ic->ic_opmode = ieee80211_new_opmode(vap, false);

    if (vap->iv_down(vdev) != QDF_STATUS_SUCCESS) {
        mlme_err("Unable to bring down the interface for ath_dev.");
        return QDF_STATUS_E_FAILURE;
    }

    if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) &&
        ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP) {
        /* Remove this AP info in rnr_buf in soc and notify lower band AP
         * to advertize updated RNR cache
         */
        wlan_remove_vap_from_6ghz_rnr_cache(vap);
        wlan_tmpl_update_lower_band_vdevs(wlan_pdev_get_psoc(ic->ic_pdev_obj));
    }

    /* bring down vdev in target */
    status = vdev_mgr_down_send(vdev_mlme);
    if (QDF_IS_STATUS_SUCCESS(status))
        vap->iv_is_up = false;

    wlan_vdev_mlme_sm_deliver_evt_sync(vap->vdev_obj,
                                       WLAN_VDEV_SM_EV_DOWN_COMPLETE,
                                       0, NULL);
    return status;
}

void mlme_ext_vap_flush_bss_peer_tids(struct ieee80211vap *vap)
{
    u_int32_t peer_tid_bitmap = 0xffffffff;
    struct ieee80211_node *ni;

    ni = ieee80211_ref_bss_node(vap, WLAN_MLME_HANDLER_ID);
    if (ni != NULL) {
        if (vdev_mgr_peer_flush_tids_send(vap->vdev_mlme, ni->ni_macaddr,
                                          peer_tid_bitmap) !=
                                                        QDF_STATUS_SUCCESS)
            mlme_err("Unable to Flush tids peer in Target");
        ieee80211_free_node(ni, WLAN_MLME_HANDLER_ID);
    }

    return;
}

QDF_STATUS mlme_ext_vap_stop(struct wlan_objmgr_vdev *vdev)
{
    QDF_STATUS status = QDF_STATUS_E_FAILURE;
    struct ieee80211vap *vap;
    ieee80211_vap_event evt;
    struct wlan_objmgr_pdev *pdev;
    unsigned long bringdown_pend_vdev_arr[2];
    struct ieee80211com *ic;
    enum ieee80211_opmode opmode;
    struct cdp_soc_t *soc_txrx_handle;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap) {
        mlme_err("(vdev-id:%d) vap  is NULL", wlan_vdev_get_id(vdev));
        return QDF_STATUS_E_FAILURE;
    }

    ic = vap->iv_ic;
    if (!ic) {
        mlme_err("(vdev-id:%d) ic  is NULL", wlan_vdev_get_id(vdev));
        return QDF_STATUS_E_FAILURE;
    }

    pdev = wlan_vdev_get_pdev(vdev);
    if (pdev == NULL) {
        mlme_err("(vdev-id:%d) PDEV is NULL", wlan_vdev_get_id(vdev));
        return QDF_STATUS_E_FAILURE;
    }

    opmode = ieee80211vap_get_opmode(vap);
    qdf_timer_stop(&vap->peer_cleanup_timer);

    soc_txrx_handle =
           wlan_psoc_get_dp_handle(wlan_pdev_get_psoc(ic->ic_pdev_obj));

    switch (opmode) {
    case IEEE80211_M_MONITOR:
        cdp_reset_monitor_mode(soc_txrx_handle,
                               wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj), 0);
        break;
   case IEEE80211_M_STA:
        OS_CANCEL_TIMER(&vap->iv_cswitch_timer);
        /* channel_switch_state is set to true when AP announces
         * channel switch and is reset when chanel switch completes.
         * As STA mode channel switch timer is cancelled here,
         * channel_switch_state will endup telling CSA in progress
         * which is wrong.
         * reset channel_switch_state here to reflect correct state
         */
        vap->channel_switch_state = 0;
        OS_CANCEL_TIMER(&vap->iv_disconnect_sta_timer);
        break;
    default:
        break;
    }

    spin_lock_dpc(&vap->init_lock);

    /* Flush all TIDs for bss node - to cleanup
     * pending traffic in bssnode
     */
    mlme_ext_vap_flush_bss_peer_tids(vap);

    if (vap->iv_stop_pre_init(vdev) == QDF_STATUS_E_CANCELED) {
        spin_unlock_dpc(&vap->init_lock);
        vap->iv_is_started = false;
        goto mlme_ext_vap_stop_end;
    }

    /* bring down vdev in target */
    if (vdev_mgr_stop_send(vap->vdev_mlme)) {
        mlme_err("Unable to send stop to target.");
        spin_unlock_dpc(&vap->init_lock);
        wlan_vdev_mlme_sm_deliver_evt_sync(vdev,
                                           WLAN_VDEV_SM_EV_STOP_FAIL,
                                           0, NULL);
        goto mlme_ext_vap_stop_end;
    } else {
        vap->iv_is_started = false;
    }

    spin_unlock_dpc(&vap->init_lock);
    status = QDF_STATUS_SUCCESS;

mlme_ext_vap_stop_end:
    evt.type = IEEE80211_VAP_STOPPING;
    ieee80211_vap_deliver_event(vap, &evt);

    if (wlan_pdev_mlme_op_get(pdev, WLAN_PDEV_OP_RADAR_DETECT_DEFER)) {
        /* Reset the bitmap */
        bringdown_pend_vdev_arr[0] = 0;
        bringdown_pend_vdev_arr[1] = 0;

        wlan_pdev_chan_change_pending_vdevs(pdev, bringdown_pend_vdev_arr,
                                            WLAN_MLME_SB_ID);

        /* If all the pending vdevs goes down, then clear RADAR detect
         * defer flag
         */
         if (!bringdown_pend_vdev_arr[0] && !bringdown_pend_vdev_arr[1])
             wlan_pdev_mlme_op_clear(pdev,
                                     WLAN_PDEV_OP_RADAR_DETECT_DEFER);
    }

    return status;
}

QDF_STATUS mlme_ext_vap_up(struct ieee80211vap *vap, bool restart)
{
    QDF_STATUS status;
    struct ieee80211com *ic           = vap->iv_ic;
    enum ieee80211_opmode opmode      = ieee80211vap_get_opmode(vap);
    struct ieee80211_node *ni         = vap->iv_bss;
    uint32_t aid         = 0;
    uint32_t value       = 0;
    struct cdp_soc_t *soc_txrx_handle;
    enum htt_cmn_pkt_type pkt_type;
    uint8_t bssid_null[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    struct vdev_mlme_obj *vdev_mlme = vap->vdev_mlme;
    struct wlan_vdev_mgr_cfg mlme_cfg;

    soc_txrx_handle =
              wlan_psoc_get_dp_handle(wlan_pdev_get_psoc(ic->ic_pdev_obj));

    if (!soc_txrx_handle) {
        mlme_err("Failed to get DP handles");
        return QDF_STATUS_E_FAILURE;
    }

    switch (opmode) {
        case IEEE80211_M_STA:
            /* Set assoc id */
            aid = IEEE80211_AID(ni->ni_associd);
            vdev_mlme->proto.sta.assoc_id = aid;

            /* Set the beacon interval of the bss */
            vdev_mlme->proto.generic.beacon_interval = ni->ni_intval;

            /* set uapsd configuration */
            if (ieee80211_vap_wme_is_set(vap) &&
                    (ni->ni_ext_caps & IEEE80211_NODE_C_UAPSD)) {
                value = 0;
                if (vap->iv_uapsd & WME_CAPINFO_UAPSD_VO) {
                    value |= WLAN_MLME_HOST_STA_PS_UAPSD_AC3_DELIVERY_EN |
                        WLAN_MLME_HOST_STA_PS_UAPSD_AC3_TRIGGER_EN;
                }
                if (vap->iv_uapsd & WME_CAPINFO_UAPSD_VI) {
                    value |= WLAN_MLME_HOST_STA_PS_UAPSD_AC2_DELIVERY_EN |
                        WLAN_MLME_HOST_STA_PS_UAPSD_AC2_TRIGGER_EN;
                }
                if (vap->iv_uapsd & WME_CAPINFO_UAPSD_BK) {
                    value |= WLAN_MLME_HOST_STA_PS_UAPSD_AC1_DELIVERY_EN |
                        WLAN_MLME_HOST_STA_PS_UAPSD_AC1_TRIGGER_EN;
                }
                if (vap->iv_uapsd & WME_CAPINFO_UAPSD_BE) {
                    value |= WLAN_MLME_HOST_STA_PS_UAPSD_AC0_DELIVERY_EN |
                        WLAN_MLME_HOST_STA_PS_UAPSD_AC0_TRIGGER_EN;
                }
            }

            vdev_mlme->proto.sta.uapsd_cfg = value;
            break;
        case IEEE80211_M_HOSTAP:
        case IEEE80211_M_IBSS:
            /*currently ratemask has to be set before vap is up*/
            if (!vap->iv_ratemask_default) {
               /*
		* ratemask higher 32 bit is reserved for beeliner,
		* use 0x0 for peregrine
		*/
               if (vap->iv_legacy_ratemasklower32 != 0) {
                   vdev_mlme->mgmt.rate_info.type = 0;
                   vdev_mlme->mgmt.rate_info.lower32 = vap->iv_legacy_ratemasklower32;
                   vdev_mlme->mgmt.rate_info.higher32 = 0x0;
                   vdev_mlme->mgmt.rate_info.lower32_2 = 0x0;
                   wlan_util_vdev_mlme_set_ratemask_config(vdev_mlme);
               }
               if (vap->iv_ht_ratemasklower32 != 0) {
                   vdev_mlme->mgmt.rate_info.type = 1;
                   vdev_mlme->mgmt.rate_info.lower32 = vap->iv_ht_ratemasklower32;
                   vdev_mlme->mgmt.rate_info.higher32 = 0x0;
                   vdev_mlme->mgmt.rate_info.lower32_2 = 0x0;
                   wlan_util_vdev_mlme_set_ratemask_config(vdev_mlme);
               }
               if (vap->iv_vht_ratemasklower32 != 0 ||
                   vap->iv_vht_ratemaskhigher32 != 0 ||
                   vap->iv_vht_ratemasklower32_2 != 0) {
                   vdev_mlme->mgmt.rate_info.type = 2;
                   vdev_mlme->mgmt.rate_info.lower32 = vap->iv_vht_ratemasklower32;
                   vdev_mlme->mgmt.rate_info.higher32 = vap->iv_vht_ratemaskhigher32;
                   vdev_mlme->mgmt.rate_info.lower32_2 = vap->iv_vht_ratemasklower32_2;
                   wlan_util_vdev_mlme_set_ratemask_config(vdev_mlme);
               }
               if (vap->iv_he_ratemasklower32 != 0 ||
                   vap->iv_he_ratemaskhigher32 != 0 ||
                   vap->iv_he_ratemasklower32_2 != 0) {
                   vdev_mlme->mgmt.rate_info.type = 3;
                   vdev_mlme->mgmt.rate_info.lower32 = vap->iv_he_ratemasklower32;
                   vdev_mlme->mgmt.rate_info.higher32 = vap->iv_he_ratemaskhigher32;
                   vdev_mlme->mgmt.rate_info.lower32_2 = vap->iv_he_ratemasklower32_2;
                   wlan_util_vdev_mlme_set_ratemask_config(vdev_mlme);
               }
            }
            /* Set the beacon interval of the bss */
            vdev_mlme->proto.generic.beacon_interval = ni->ni_intval;
        break;
    case IEEE80211_M_MONITOR:
        IEEE80211_ADDR_COPY(&vdev_mlme->mgmt.generic.bssid, bssid_null);
        break;
    default:
        break;
    }

    /* Enable non-HT duplicate beacon if 6GHz AP's primary
     * channel is non-PSC */
    if((vap->iv_opmode == IEEE80211_M_HOSTAP) &&
            (!IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) &&
            (vap->iv_cur_mode > IEEE80211_MODE_11AXG_HE20) &&
            (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
            (!wlan_reg_is_6ghz_psc_chan_freq(ic->ic_curchan->ic_freq))) {
        ic->ic_non_ht_dup |= (1 << IEEE80211_NON_HT_DUP_BEACON_S);
        ic->ic_vap_set_param(vap, IEEE80211_CONFIG_6GHZ_NON_HT_DUP,
                                                    ic->ic_non_ht_dup);
    }

    status = vap->iv_up_pre_init(vap->vdev_obj, restart);
    if (QDF_IS_STATUS_ERROR(status)) {
        if (status == QDF_STATUS_E_CANCELED)
            return QDF_STATUS_SUCCESS;
        mlme_err("OL Up pre init failed");
        goto mlme_ext_vap_up_fail;
    }

    ic->ic_opmode = ieee80211_new_opmode(vap,true);

    /* Send beacon template for regular or MBSS Tx VAP */
    if (!IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {

        if (vap->iv_bcn_offload_enable) {
            ic->ic_bcn_tmpl_send(vap->vdev_obj);
        }

#if WLAN_SUPPORT_FILS
        if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) && ic->ic_fd_tmpl_send) {
            ic->ic_fd_tmpl_send(vap->vdev_obj);
            /* Enable the FILS feature capability so that vdev_mgr_up_send()
             * will send the FILS enable WMI by default */
            wlan_vdev_mlme_feat_ext_cap_set(vap->vdev_obj,
                    WLAN_VDEV_FEXT_FILS_DISC_6G_SAP);
        }
#endif /* WLAN_SUPPORT_FILS */

#if DYNAMIC_BEACON_SUPPORT
        if (vap->iv_dbeacon) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "ic_ieee:%u  freq:%u \n",
                ic->ic_curchan->ic_ieee,ic->ic_curchan->ic_freq);
            /* Do not suspend beacon for DFS channels or hidden ssid not enabled */
            if (IEEE80211_IS_CHAN_DFS(ic->ic_curchan) ||
                !IEEE80211_VAP_IS_HIDESSID_ENABLED(vap)) {
                ieee80211_mlme_set_dynamic_beacon_suspend(vap,false);
            } else {
                ieee80211_mlme_set_dynamic_beacon_suspend(vap,true);
            }
        }
#endif

        if (vap->iv_bcn_offload_enable) {
            if (is_beacon_tx_suspended(vap)) {
                /*for non-beaconing VAP, don't send beacon*/
                ic->ic_beacon_offload_control(vap, IEEE80211_BCN_OFFLD_TX_DISABLE);
            } else {
                if (ieee80211_wnm_tim_is_set(vap->wnm))
                    ic->ic_beacon_offload_control(vap,
                                              IEEE80211_BCN_OFFLD_SWBA_ENABLE);
               else
                    ic->ic_beacon_offload_control(vap,
                                              IEEE80211_BCN_OFFLD_SWBA_DISABLE);
            }
        } else {
            if (is_beacon_tx_suspended(vap)) {
                mlme_debug("suspend the beacon: vap-%d(%s) \n",
                            vap->iv_unit,vap->iv_netdev_name);
                if (ic->ic_beacon_offload_control) {
                    /*for non-beaconing VAP, don't send beacon*/
                    ic->ic_beacon_offload_control(vap,
                                              IEEE80211_BCN_OFFLD_TX_DISABLE);
               }
            }
        }
    } /* IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED */

    if (opmode == IEEE80211_M_HOSTAP &&
        IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)){
        if (!restart) {
            /* Add this AP info to rnr_buf in soc only on vap start */
            wlan_update_6ghz_rnr_cache(vap, 1);
        } else {
            /* If in restart case, such as channel change,
             * update the RNR cache with latest info
             */
             wlan_update_6ghz_rnr_cache(vap, 0);
        }
    }

    mlme_debug("Setting Rx Decap type %d, Tx Encap type: %d\n",
            vap->iv_rx_decap_type, vap->iv_tx_encap_type);

    if (vap->iv_rx_decap_type == 0) {
        pkt_type = htt_cmn_pkt_type_raw;
    } else if (vap->iv_rx_decap_type == 1) {
        pkt_type = htt_cmn_pkt_type_native_wifi;
    } else {
        pkt_type = htt_cmn_pkt_type_ethernet;
    }

    mlme_cfg.value = pkt_type;
    wlan_util_vdev_mlme_set_param(vdev_mlme, WLAN_MLME_CFG_RX_DECAP_TYPE,
                                  mlme_cfg);

    if (vap->iv_tx_encap_type == 0) {
        pkt_type = htt_cmn_pkt_type_raw;
    } else if (vap->iv_tx_encap_type == 1) {
        pkt_type = htt_cmn_pkt_type_native_wifi;
    } else {
        pkt_type = htt_cmn_pkt_type_ethernet;
    }

    mlme_cfg.value = pkt_type;
    wlan_util_vdev_mlme_set_param(vdev_mlme, WLAN_MLME_CFG_TX_ENCAP_TYPE,
                                  mlme_cfg);

    if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
        IEEE80211_ADDR_COPY(vdev_mlme->mgmt.mbss_11ax.trans_bssid,
                            ic->ic_mbss.transmit_vap->iv_myaddr);
        vdev_mlme->mgmt.mbss_11ax.profile_num =
                            ic->ic_mbss.num_non_transmit_vaps;
    } else if (opmode != IEEE80211_M_STA) {
        vdev_mlme->mgmt.mbss_11ax.profile_num = 0;
    }

    /* Add a check to see if mpsta is up before bringing up psta interface.
     * This check is made to prevent a corner case during wifi down when mpsta
     * is in bringdown phase and then psta connection happens */
#if ATH_SUPPORT_WRAP
    if (vap->iv_psta && !vap->iv_mpsta) {
        wlan_if_t mpsta_vap = vap->iv_ic->ic_mpsta_vap;
        if (!mpsta_vap || !mpsta_vap->iv_is_started || !mpsta_vap->iv_is_up) {
            mlme_err("mpsta is down, stopped or deleted");
            goto mlme_ext_vap_up_fail;
        }
    }
#endif

    if (opmode != IEEE80211_M_MONITOR)
        IEEE80211_ADDR_COPY(&vdev_mlme->mgmt.generic.bssid, ni->ni_bssid);

    if (vdev_mgr_up_send(vdev_mlme) != QDF_STATUS_SUCCESS) {
        mlme_err("Unable to bring up the interface for ath_dev.");
        goto mlme_ext_vap_up_fail;
    }

    vap->iv_is_up = true;
    if (opmode == IEEE80211_M_HOSTAP && IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        wlan_tmpl_update_lower_band_vdevs(wlan_pdev_get_psoc(ic->ic_pdev_obj));
    }
    return vap->iv_up_complete(vap->vdev_obj);

mlme_ext_vap_up_fail:
    wlan_vdev_mlme_sm_deliver_evt_sync(vap->vdev_obj,
                                       WLAN_VDEV_SM_EV_UP_FAIL,
                                       0, NULL);
    return QDF_STATUS_E_FAILURE;
}

static void mlme_ext_vap_start_param_reset(struct vdev_mlme_obj *vdev_mlme)
{
    vdev_mlme->mgmt.generic.minpower     = 0;
    vdev_mlme->mgmt.generic.maxpower     = 0;
    vdev_mlme->mgmt.generic.maxregpower  = 0;
    vdev_mlme->mgmt.generic.antennamax   = 0;
    vdev_mlme->mgmt.chainmask_info.num_rx_chain = 0;
    vdev_mlme->mgmt.chainmask_info.num_tx_chain = 0;
    vdev_mlme->proto.he_ops_info.he_ops = 0;
    vdev_mlme->mgmt.chainmask_info.num_rx_chain = 0;
    vdev_mlme->mgmt.chainmask_info.num_tx_chain = 0;
    vdev_mlme->mgmt.rate_info.half_rate = FALSE;
    vdev_mlme->mgmt.rate_info.quarter_rate = FALSE;
    vdev_mlme->mgmt.generic.reg_class_id = 0;
}

static QDF_STATUS mlme_ext_vap_start_setup(struct ieee80211vap *vap,
                                           struct ieee80211_ath_channel *chan,
                                           struct wlan_channel *des_chan,
                                           struct vdev_mlme_obj *vdev_mlme)
{
    u_int32_t chan_mode;
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
    uint32_t cfreq1 = 0, cfreq2 = 0;
    uint32_t freq = 0, he_ops = 0;

    freq = ieee80211_chan2freq(ic, chan);
    if (!freq) {
        mlme_err("Invalid frequency");
        return QDF_STATUS_E_INVAL;
    }

    pdev = ic->ic_pdev_obj;
    if (pdev == NULL) {
        QDF_ASSERT(0);
        return QDF_STATUS_E_FAILURE;
    }

    psoc = wlan_pdev_get_psoc(pdev);

    if (psoc == NULL) {
        QDF_ASSERT(0);
        return QDF_STATUS_E_FAILURE;
    }

    mlme_ext_vap_start_param_reset(vdev_mlme);
    chan_mode = ieee80211_chan2mode(chan);

    if ((chan_mode == IEEE80211_MODE_11AC_VHT80) ||
           (chan_mode == IEEE80211_MODE_11AC_VHT160) ||
           (chan_mode == IEEE80211_MODE_11AC_VHT80_80) ||
           (chan_mode == IEEE80211_MODE_11AXA_HE80) ||
           (chan_mode == IEEE80211_MODE_11AXA_HE160) ||
           (chan_mode == IEEE80211_MODE_11AXA_HE80_80)) {
           cfreq1 = chan->ic_vhtop_freq_seg1;

       if ((chan_mode == IEEE80211_MODE_11AC_VHT80_80) ||
              (chan_mode == IEEE80211_MODE_11AC_VHT160) ||
              (chan_mode == IEEE80211_MODE_11AXA_HE80_80) ||
              (chan_mode == IEEE80211_MODE_11AXA_HE160))
           cfreq2 = chan->ic_vhtop_freq_seg2;
    } else if ((chan_mode == IEEE80211_MODE_11NA_HT40PLUS) ||
                   (chan_mode == IEEE80211_MODE_11NG_HT40PLUS) ||
                   (chan_mode == IEEE80211_MODE_11AC_VHT40PLUS) ||
                   (chan_mode == IEEE80211_MODE_11AXA_HE40PLUS) ||
                   (chan_mode == IEEE80211_MODE_11AXG_HE40PLUS)) {
           cfreq1 = freq + 10;
    } else if ((chan_mode == IEEE80211_MODE_11NA_HT40MINUS) ||
                   (chan_mode == IEEE80211_MODE_11NG_HT40MINUS) ||
                   (chan_mode == IEEE80211_MODE_11AC_VHT40MINUS) ||
                   (chan_mode == IEEE80211_MODE_11AXA_HE40MINUS) ||
                   (chan_mode == IEEE80211_MODE_11AXG_HE40MINUS)) {
           cfreq1 = freq - 10;
    } else {
           cfreq1 = freq;
    }

    des_chan->ch_cfreq1 = cfreq1;
    des_chan->ch_cfreq2 = cfreq2;
    if (IEEE80211_IS_CHAN_HALF(chan))
        vdev_mlme->mgmt.rate_info.half_rate = TRUE;

    if (IEEE80211_IS_CHAN_QUARTER(chan))
        vdev_mlme->mgmt.rate_info.quarter_rate = TRUE;

    ieee80211com_set_num_rx_chain(ic,
                              num_chain_from_chain_mask(ic->ic_rx_chainmask));
    ieee80211com_set_num_tx_chain(ic,
                              num_chain_from_chain_mask(ic->ic_tx_chainmask));
    ieee80211com_set_spatialstreams(ic,
                              num_chain_from_chain_mask(ic->ic_rx_chainmask));
    vdev_mlme->mgmt.generic.minpower     = chan->ic_minpower;
    vdev_mlme->mgmt.generic.maxpower     = chan->ic_maxpower;
    vdev_mlme->mgmt.generic.maxregpower  = chan->ic_maxregpower;
    vdev_mlme->mgmt.generic.antennamax   = chan->ic_antennamax;
    vdev_mlme->mgmt.generic.reg_class_id = chan->ic_regClassId;
    vdev_mlme->mgmt.chainmask_info.num_rx_chain = ic->ic_num_rx_chain;
    vdev_mlme->mgmt.chainmask_info.num_tx_chain = ic->ic_num_tx_chain;
#if SUPPORT_11AX_D3
    he_ops               = (ic->ic_he.heop_param |
                            (ic->ic_he.heop_bsscolor_info << HEOP_PARAM_S));
    /* override only bsscolor at this time */
    he_ops              &= ~(IEEE80211_HEOP_BSS_COLOR_MASK <<
                                        HEOP_PARAM_S);
    he_ops              |= (ic->ic_bsscolor_hdl.selected_bsscolor <<
                                        HEOP_PARAM_S);
#else
    he_ops               = ic->ic_he.heop_param;
    /* override only bsscolor at this time */
    he_ops              &= ~IEEE80211_HEOP_BSS_COLOR_MASK;
    he_ops              |= ic->ic_bsscolor_hdl.selected_bsscolor;
#endif
    vdev_mlme->proto.he_ops_info.he_ops = he_ops;

    if (!IEEE80211_IS_CHAN_HE(chan) && !IEEE80211_IS_CHAN_VHT(chan))
    {
        /* IC might support higher than IEEE80211_MAX_PRE11AC_STREAMS,
         * but if we aren't using 11ac or higher, we limit the streams to
         * IEEE80211_MAX_PRE11AC_STREAMS.
         *
         * Note: It would have been preferable to look at the exact PHY mode
         * older than 11ac, and determine max value for streams accordingly.
         * E.g. for pre-11n modes like 11a, we could limit to 1. However, prior
         * to adding 8 stream support, we have been configuring the max value
         * per IC capability (e.g. 4) even for pre-11n modes. To maintain
         * compatility with older FW and preserve any proprietary interactions
         * that might have been built around assumptions based on this
         * behaviour, we only cap to IEEE80211_MAX_PRE11AC_STREAMS (which is 4).
         * XXX: Modify this in the future once confirmed that there are no
         * issues in altering behaviour.
         */
        if (vdev_mlme->mgmt.chainmask_info.num_rx_chain >
                                               IEEE80211_MAX_PRE11AC_STREAMS)
        {
            vdev_mlme->mgmt.chainmask_info.num_rx_chain =
                                               IEEE80211_MAX_PRE11AC_STREAMS;
        }

        if (vdev_mlme->mgmt.chainmask_info.num_tx_chain >
                                                IEEE80211_MAX_PRE11AC_STREAMS)
        {
            vdev_mlme->mgmt.chainmask_info.num_tx_chain =
                                                IEEE80211_MAX_PRE11AC_STREAMS;
        }
    }

    return QDF_STATUS_SUCCESS;
}

enum ieee80211_phymode
wlan_vdev_get_ieee_phymode(enum wlan_phymode wlan_phymode)
{
    if (wlan_phymode == 0xff)
        return IEEE80211_MODE_AUTO;

    if (wlan_phymode > WLAN_PHYMODE_11AXA_HE80_80)
        return IEEE80211_MODE_AUTO;

    return wlanphymode2ieeephymode[wlan_phymode];
}

qdf_export_symbol(wlan_vdev_get_ieee_phymode);

static bool
wlan_is_vdev_restart_on_same_chan(struct wlan_channel *des_chan,
                                  struct wlan_channel *bss_chan)
{
    if (des_chan->ch_freq    == bss_chan->ch_freq &&
        des_chan->ch_cfreq1  == bss_chan->ch_cfreq1 &&
        des_chan->ch_cfreq2  == bss_chan->ch_cfreq2 &&
        des_chan->ch_flags   == bss_chan->ch_flags &&
        des_chan->ch_flagext == bss_chan->ch_flagext &&
        des_chan->ch_width   == bss_chan->ch_width &&
        des_chan->ch_phymode == bss_chan->ch_phymode)
        return true;
    return false;
}

QDF_STATUS mlme_ext_vap_start(struct wlan_objmgr_vdev *vdev,
                              u_int8_t restart)
{
    struct ieee80211com *ic = NULL;
    bool disable_hw_ack= false;
    bool dfs_channel = false;
    struct vdev_mlme_obj *vdev_mlme = NULL;
    struct wlan_channel *des_chan = NULL, *bss_chan = NULL;
    struct wlan_objmgr_pdev *pdev = NULL;
    struct ieee80211_ath_channel *curchan;
    struct ieee80211vap *vap = NULL;
    struct ieee80211_node *ni = NULL;
    uint8_t vdev_id;
    uint32_t freq;
#ifdef QCA_SUPPORT_ADFS_RCAC
    bool is_rcac_enabled = false;
#endif

    vdev_id = wlan_vdev_get_id(vdev);
    pdev = wlan_vdev_get_pdev(vdev);
    if (pdev == NULL) {
        mlme_err("(vdev-id:%d) PDEV is NULL", vdev_id);
        return QDF_STATUS_E_FAILURE;
    }

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!ic) {
        mlme_err("(vdev-id:%d) ic is NULL", vdev_id);
        return QDF_STATUS_E_FAILURE;
    }

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap) {
        mlme_err("(vdev-id:%d) vap  is NULL", vdev_id);
        return QDF_STATUS_E_FAILURE;
    }

    ni = vap->iv_bss;
    if (!ni) {
        mlme_err("(vdev-id:%d) ni is NULL", vdev_id);
        return QDF_STATUS_E_FAILURE;
    }

    des_chan = wlan_vdev_mlme_get_des_chan(vdev);
    if (!des_chan) {
        mlme_err("(vdev-id:%d) desired channel not found", vdev_id);
        return QDF_STATUS_E_FAILURE;
    }

    curchan = ieee80211_find_dot11_channel(
                            ic, des_chan->ch_freq,
                            des_chan->ch_cfreq2,
                            wlan_vdev_get_ieee_phymode(des_chan->ch_phymode));
    if (!curchan) {
        mlme_err("(vdev-id:%d) des chan(%d) is NULL", vdev_id,
                 des_chan->ch_ieee);
        return QDF_STATUS_E_FAILURE;
    }

    if (restart)
        vap->restart_txn = 1;
    else
        vap->restart_txn = 0;

    freq = ieee80211_chan2freq(ic, curchan);
    if (!freq) {
        mlme_err("Invalid frequency");
        return QDF_STATUS_E_FAILURE;
    }

    vdev_mlme = vap->vdev_mlme;
    if (!vdev_mlme) {
        mlme_err("vdev mlme component not found");
        return QDF_STATUS_E_FAILURE;
    }

    bss_chan = wlan_vdev_mlme_get_bss_chan(vdev);
    if (vap->iv_opmode == IEEE80211_M_HOSTAP && bss_chan && restart)
        ic->ic_is_restart_on_same_chan =
                    wlan_is_vdev_restart_on_same_chan(des_chan, bss_chan);

    dfs_channel = (IEEE80211_IS_CHAN_DFS(curchan) ||
        ((IEEE80211_IS_CHAN_11AC_VHT80_80(curchan) ||
          IEEE80211_IS_CHAN_11AC_VHT160(curchan) ||
          IEEE80211_IS_CHAN_11AXA_HE80_80(curchan) ||
          IEEE80211_IS_CHAN_11AXA_HE160(curchan)) &&
          IEEE80211_IS_CHAN_DFS_CFREQ2(curchan)));

    spin_lock_dpc(&vap->init_lock);
#if ATH_SUPPORT_DFS
#ifdef QCA_SUPPORT_ADFS_RCAC
    is_rcac_enabled = ucfg_dfs_is_agile_rcac_enabled(pdev);

    if (is_rcac_enabled && dfs_channel && des_chan)
        /* Since RCAC done will not be remembered after RCAC state machine
         * is stopped, which is done after this, remember that we need to
         * skip the CAC in the vap variable.
         */
        if (utils_dfs_is_precac_done(pdev, des_chan))
            vap->iv_no_cac = true;
#endif

    if (vap->iv_opmode == IEEE80211_M_HOSTAP &&
        dfs_channel &&
        !ieee80211_vap_is_any_running(ic) && !vap->iv_no_cac) {
        /*
         * Do not set HW no ack bit, if STA vap is present and
         * if it is not in Repeater-ind mode
	 */
#if ATH_SUPPORT_WRAP
        if (ic->ic_nstavaps == 0 ||
            (ic->ic_nstavaps >=1 &&
             ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic))) {
           disable_hw_ack = true;
        }
#endif
    }
#endif
    if (!ic->ic_ext_nss_capable) {
        vap->iv_ext_nss_support = 0;
    }

    if (vap->iv_start_pre_init(vdev, curchan, restart)
                                               != QDF_STATUS_SUCCESS) {
       spin_unlock_dpc(&vap->init_lock);
       return QDF_STATUS_SUCCESS;
    }

    qdf_atomic_set(&(vap->iv_is_start_sent), 1);
    qdf_atomic_set(&(vap->iv_is_start_resp_received), 0);

    vdev_mlme->mgmt.generic.disable_hw_ack = disable_hw_ack;
    mlme_ext_vap_start_setup(vap, curchan, des_chan, vdev_mlme);

    if (vap->iv_disabled_legacy_rate_set)
        ieee80211_init_node_rates(vap->iv_bss, vap->iv_bsschan);
#ifdef WLAN_BCN_RATECODE_ENABLE
    vdev_mlme->mgmt.rate_info.bcn_tx_rate_code =
        ic->ic_assemble_ratecode(vap, curchan,
                                 vdev_mlme->mgmt.rate_info.bcn_tx_rate);
#endif

    /* Update changed beacon_interval from vap */
    vdev_mlme->proto.generic.beacon_interval = ni->ni_intval;

    if (vdev_mgr_start_send(vdev_mlme, restart) != QDF_STATUS_SUCCESS) {
        mlme_err("Unable to bring up the interface for ath_dev.");
        if (!restart)
            qdf_atomic_set(&(vap->iv_is_start_sent), 0);
        else
            wlan_vdev_mlme_sm_deliver_evt_sync(vdev,
                                               WLAN_VDEV_SM_EV_RESTART_REQ_FAIL,
                                               0, NULL);
    } else {
        vap->iv_is_started = true;
    }

    if (vap->iv_start_post_init(vdev, curchan, restart) !=
                                                   QDF_STATUS_SUCCESS) {
        qdf_atomic_set(&(vap->iv_is_start_sent), 0);
        spin_unlock_dpc(&vap->init_lock);
        if (!restart)
            wlan_vdev_mlme_sm_deliver_evt_sync(vdev,
                                               WLAN_VDEV_SM_EV_START_REQ_FAIL,
                                               0, NULL);
        return QDF_STATUS_SUCCESS;
    }

    spin_unlock_dpc(&vap->init_lock);
    if (ic->ic_cbs && ic->ic_cbs->cbs_enable) {
        wlan_bk_scan(ic);
    }

    if (restart)
        ieee80211_send_chanswitch_complete_event(ic);

    return QDF_STATUS_SUCCESS;
}

int
mlme_ext_vap_start_response_event_handler(struct vdev_start_response *rsp,
                                          struct vdev_mlme_obj *vdev_mlme)
{
    QDF_STATUS status;
    struct ieee80211com  *ic;
    ieee80211_resmgr_t resmgr;
    wlan_if_t vaphandle;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_vdev *vdev;
    struct wlan_objmgr_psoc *psoc;
    uint8_t vdev_id;
    int restart_resp = 0;

    vdev = vdev_mlme->vdev;
    vaphandle = wlan_vdev_get_mlme_ext_obj(vdev);
    if (NULL == vaphandle) {
        mlme_err("Event received for Invalid/Deleted vap handle");
        return 0;
    }

    qdf_atomic_set(&(vaphandle->iv_is_start_resp_received), 1);
    qdf_atomic_set(&(vaphandle->iv_is_start_sent), 0);

    ic = vaphandle->iv_ic;
    resmgr = ic->ic_resmgr;

    vdev_id = wlan_vdev_get_id(vdev);
    pdev = ic->ic_pdev_obj;
    psoc = wlan_pdev_get_psoc(pdev);

    spin_lock_dpc(&vaphandle->init_lock);

    switch (vaphandle->iv_opmode) {

        case IEEE80211_M_MONITOR:
               /* Handle same as HOSTAP */
        case IEEE80211_M_HOSTAP:
            if (rsp->status != WLAN_MLME_HOST_VDEV_START_OK)
                mlme_err("Received invalid start resp status: %s",
                         string_from_start_rsp_status(rsp->status));

            if ((rsp->status == WLAN_MLME_HOST_VDEV_START_CHAN_INVALID) ||
                (rsp->status ==
                 WLAN_MLME_HOST_VDEV_START_CHAN_INVALID_REGDOMAIN) ||
                (rsp->status == WLAN_MLME_HOST_VDEV_START_CHAN_INVALID_BAND)) {
                spin_unlock_dpc(&vaphandle->init_lock);
                wlan_vdev_mlme_sm_deliver_evt(vdev,
                                              WLAN_VDEV_SM_EV_START_REQ_FAIL,
                                              0, NULL);

                return 0;
            }
            break;
        default:
            break;
    }

    status = vaphandle->iv_vap_start_rsp_handler(rsp, vdev_mlme);
    spin_unlock_dpc(&vaphandle->init_lock);
    if (status == QDF_STATUS_E_AGAIN) {
        /* Notify START Response to do RESTART req with new channel */
        wlan_vdev_mlme_sm_deliver_evt(vdev, WLAN_VDEV_SM_EV_START_RESP,
                                      0, NULL);
        return 0;
    } else if (status == QDF_STATUS_E_CANCELED) {
        wlan_vdev_mlme_sm_deliver_evt(vdev, WLAN_VDEV_SM_EV_START_REQ_FAIL,
                                      0, NULL);
        return 0;
    } else if (status != QDF_STATUS_SUCCESS) {
        return 0;
    }

    if (rsp->resp_type == WLAN_MLME_HOST_VDEV_START_RESP_EVENT) {
        wlan_vdev_mlme_sm_deliver_evt(vdev, WLAN_VDEV_SM_EV_START_RESP, 1,
                                      &restart_resp);
    } else {
        restart_resp = 1;
        wlan_vdev_mlme_sm_deliver_evt(vdev, WLAN_VDEV_SM_EV_RESTART_RESP, 1,
                                      &restart_resp);
    }

    return 0;
}

QDF_STATUS mlme_ext_vap_recover(struct ieee80211vap *vap)
{
    struct vdev_response_timer *vdev_rsp;
    struct wlan_objmgr_psoc *psoc;
    struct psoc_mlme_obj *psoc_mlme;
    uint8_t vdev_id;
    struct wlan_lmac_if_mlme_tx_ops *txops;

    if (!vap)
        return QDF_STATUS_E_FAILURE;

    vdev_id = wlan_vdev_get_id(vap->vdev_obj);
    psoc = wlan_vdev_get_psoc(vap->vdev_obj);
    if (!psoc) {
        mlme_err("VDEV_%d PSOC is NULL", vdev_id);
        return QDF_STATUS_E_FAILURE;

    }
    psoc_mlme = mlme_psoc_get_priv(psoc);
    if (!psoc_mlme) {
        mlme_err("VDEV_%d PSOC_%d PSOC_MLME is NULL", vdev_id,
                wlan_psoc_get_id(psoc));
        return QDF_STATUS_E_FAILURE;
    }

    vdev_rsp =  &psoc_mlme->psoc_vdev_rt[vdev_id];
    txops = wlan_mlme_get_lmac_tx_ops(psoc);
    if (!txops || !txops->vdev_mgr_rsp_timer_stop) {
        mlme_err("Failed to get mlme txrx_ops VDEV_%d PSOC_%d",
                vdev_rsp->vdev_id, wlan_psoc_get_id(psoc));
        return QDF_STATUS_E_FAILURE;
    }

    mlme_debug("Vap recovery: %lu", vdev_rsp->rsp_status);

    if (qdf_atomic_test_bit(START_RESPONSE_BIT,
                                      &vdev_rsp->rsp_status)) {
        txops->vdev_mgr_rsp_timer_stop(psoc, vdev_rsp, START_RESPONSE_BIT);
    }

    if (qdf_atomic_test_bit(RESTART_RESPONSE_BIT,
                                      &vdev_rsp->rsp_status)) {
        txops->vdev_mgr_rsp_timer_stop(psoc, vdev_rsp, RESTART_RESPONSE_BIT);
    }

    if (qdf_atomic_test_bit(STOP_RESPONSE_BIT,
                                      &vdev_rsp->rsp_status)) {
        txops->vdev_mgr_rsp_timer_stop(psoc, vdev_rsp, STOP_RESPONSE_BIT);
    }

    if (qdf_atomic_test_bit(DELETE_RESPONSE_BIT,
                                      &vdev_rsp->rsp_status)) {
        txops->vdev_mgr_rsp_timer_stop(psoc, vdev_rsp, DELETE_RESPONSE_BIT);
    }

    if (qdf_atomic_test_bit(PEER_DELETE_ALL_RESPONSE_BIT,
                                      &vdev_rsp->rsp_status)) {
        txops->vdev_mgr_rsp_timer_stop(psoc, vdev_rsp, PEER_DELETE_ALL_RESPONSE_BIT);
    }

    return QDF_STATUS_SUCCESS;
}

qdf_export_symbol(mlme_ext_vap_recover);

static void mlme_ext_vap_reset_monitor_mode(struct wlan_objmgr_pdev *pdev,
                                            void *obj, void *arg)
{
   struct wlan_objmgr_vdev *vdev = obj;
   struct wlan_objmgr_psoc *psoc;
   enum QDF_OPMODE opmode;
   struct cdp_soc_t *soc_txrx_handle;
   struct ieee80211vap *vap = NULL;

   psoc = wlan_pdev_get_psoc(pdev);
   if (psoc == NULL) {
       mlme_err("psoc is null");
       return;
   }

   vap = wlan_vdev_get_mlme_ext_obj(vdev);
   if (vap == NULL) {
       mlme_err("Legacy vap is null");
       return;
   }

   soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
   if (!soc_txrx_handle) {
       mlme_err("DP handle null");
       return;
   }

   opmode = wlan_vdev_mlme_get_opmode(vdev);
   if (opmode == QDF_SAP_MODE) {
       if (vap->iv_special_vap_mode && !vap->iv_special_vap_is_monitor) {
           if (soc_txrx_handle)
               cdp_reset_monitor_mode(soc_txrx_handle,
                                      wlan_objmgr_pdev_get_pdev_id(pdev), 0);
       }
   } else if (opmode == QDF_MONITOR_MODE) {
       if (soc_txrx_handle)
           cdp_reset_monitor_mode(soc_txrx_handle,
                                  wlan_objmgr_pdev_get_pdev_id(pdev), 0);
   }
}

QDF_STATUS mlme_ext_multi_vdev_restart(
                                    struct ieee80211com *ic,
                                    uint32_t *vdev_ids, uint32_t num_vdevs,
                                    struct vdev_mlme_mvr_param *mvr_param)
{
   uint32_t disable_hw_ack = 0;
   struct mlme_channel_param chan = {0};
   struct wlan_objmgr_pdev *pdev;
   struct ieee80211_ath_channel *curchan;
   struct wlan_objmgr_vdev *vdev;
   struct wlan_channel *bss_chan = NULL, *des_chan = NULL;
   uint8_t i, dfs_channel = 0, vap_no_cac = 0;
   struct ieee80211vap *tmp_vap;
#ifdef QCA_SUPPORT_ADFS_RCAC
   bool is_rcac_enabled = false;
#endif
   bool is_dfs_chan_updated = false;

   pdev = ic->ic_pdev_obj;
   if (pdev == NULL) {
       mlme_err("pdev is null");
       return QDF_STATUS_E_FAILURE;
   }

   curchan = ic->ic_curchan;
   if (curchan == NULL) {
       mlme_err("channel struct is null");
       return QDF_STATUS_E_FAILURE;
   }

   vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_ids[0],
                                               WLAN_DFS_ID);
   if (vdev) {
       des_chan = wlan_vdev_mlme_get_des_chan(vdev);
       bss_chan = wlan_vdev_mlme_get_bss_chan(vdev);
       if (des_chan && bss_chan) {
           ic->ic_is_restart_on_same_chan =
                    wlan_is_vdev_restart_on_same_chan(des_chan, bss_chan);
       }
       wlan_objmgr_vdev_release_ref(vdev, WLAN_DFS_ID);
   }

   /* Update vdev restart related param before issuing restart command */
   mlme_ext_update_multi_vdev_restart_param(ic, vdev_ids, num_vdevs,
                                            FALSE, FALSE);

   /* Issue multiple vdev restart command after beacon update for all VAPs
    * through multiple vdev restart request WMI command to FW when CSA
    * switch count has reached 0.
    */
   if (wlan_pdev_nif_feat_cap_get(pdev, WLAN_PDEV_F_MULTIVDEV_RESTART)) {
       dfs_channel = (IEEE80211_IS_CHAN_DFS(curchan) ||
                     ((IEEE80211_IS_CHAN_11AC_VHT80_80(curchan) ||
                       IEEE80211_IS_CHAN_11AC_VHT160(curchan) ||
                       IEEE80211_IS_CHAN_11AXA_HE80_80(curchan) ||
                       IEEE80211_IS_CHAN_11AXA_HE160(curchan)) &&
                      IEEE80211_IS_CHAN_DFS_CFREQ2(curchan)));

       wlan_objmgr_pdev_iterate_obj_list(pdev, WLAN_VDEV_OP,
                                         mlme_ext_vap_reset_monitor_mode,
                                         NULL, 0, WLAN_MLME_SB_ID);
       mlme_ext_update_channel_param(&chan, ic);
       /*
        * Due to the interpretation in the umac-layer, the phymode value
        * received as part of MVR param is not as per the target's
        * expectation.The target expects the value in the MVR command
        * to be the same as in the channel info structure.
        */
       for (i = 0; i < num_vdevs; i++) {
           (mvr_param + i)->phymode = chan.phy_mode;
       }

       tgt_dfs_set_current_channel_for_freq(pdev,
                                   curchan->ic_freq,
                                   curchan->ic_flags,
                                   curchan->ic_flagext,
                                   curchan->ic_ieee,
                                   curchan->ic_vhtop_ch_num_seg1,
                                   curchan->ic_vhtop_ch_num_seg2,
                                   curchan->ic_vhtop_freq_seg1,
                                   curchan->ic_vhtop_freq_seg2,
                                   &is_dfs_chan_updated);

#if ATH_SUPPORT_DFS
#ifdef QCA_SUPPORT_ADFS_RCAC
       is_rcac_enabled = ucfg_dfs_is_agile_rcac_enabled(pdev);

        if (is_rcac_enabled) {
            /* Since RCAC done will not be remembered after RCAC state machine
             * is stopped, which is done after this, remember that we need to
             * skip the CAC in the vap variable.
             */
            if (dfs_channel && des_chan &&
                utils_dfs_is_precac_done(pdev, des_chan)) {
                TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next)
                     tmp_vap->iv_no_cac = true;
            }
            /* Send RCAC_STOP event to RCAC SM */
            if (is_dfs_chan_updated)
                utils_dfs_rcac_sm_deliver_evt(pdev, DFS_RCAC_SM_EV_RCAC_STOP);
        }
#endif
       /*
        * Do not set HW no ack bit, if STA vap is present and
        * if it is not in Repeater-ind mode
        */
       TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
           if (tmp_vap->iv_no_cac)
               vap_no_cac = 1;
       }

       if (dfs_channel && !ieee80211_vap_is_any_running(ic) && !vap_no_cac) {
#if ATH_SUPPORT_WRAP
           if (!ic->ic_nstavaps ||
                  (ic->ic_nstavaps && ieee80211_ic_enh_ind_rpt_is_set(ic)))
               disable_hw_ack = true;
#endif
       }
#endif

       mlme_nofl_info("phymode for mvr: %u", chan.phy_mode);
       if (vdev_mgr_multiple_restart_send(pdev, &chan, disable_hw_ack,
                                         vdev_ids, num_vdevs, mvr_param)) {
           /* Update vdev restart related param in case of failure */
           mlme_ext_update_multi_vdev_restart_param(ic, vdev_ids, num_vdevs,
                                                   TRUE, FALSE);
           return QDF_STATUS_E_FAILURE;
       }
   }

   /* The channel configured in target is not same always with the
    * vap desired channel due to 20/40 coexistence scenarios, so,
    * channel is saved to configure on VDEV START RESP
    */
   mlme_ext_update_multi_vdev_restart_param(ic, vdev_ids, num_vdevs,
                                            FALSE, TRUE);
   return QDF_STATUS_SUCCESS;
}

void mlme_ext_update_multi_vdev_restart_param(struct ieee80211com *ic,
                                              uint32_t *vdev_ids,
                                              uint32_t num_vdevs,
                                              bool reset,
                                              bool restart_success)
{
    int i = 0;
    struct wlan_objmgr_vdev *vdev;
    struct wlan_objmgr_pdev *pdev;
    struct ieee80211vap *vap = NULL;

    pdev = ic->ic_pdev_obj;
    for (i = 0; i < num_vdevs; i++) {
         vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_ids[i],
                                                     WLAN_MLME_SB_ID);
         if (vdev == NULL)
             continue;

         vap = wlan_vdev_get_mlme_ext_obj(vdev);
         if (vap == NULL) {
             wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
             continue;
         }

         if (!reset) {
             qdf_atomic_set(&(vap->iv_is_start_sent), 1);
         } else {
             qdf_atomic_set(&(vap->iv_is_start_sent), 0);
         }

         ic->ic_update_restart_param(vap, reset, restart_success);
         wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
    }
}

int mlme_ext_update_channel_param(struct mlme_channel_param *ch_param,
                                  struct ieee80211com *ic)
{
    struct ieee80211_ath_channel *c = NULL;

    c = ic->ic_curchan;
    if (!c)
        return -1;

    ch_param->mhz = c->ic_freq;
    ch_param->cfreq1 = c->ic_freq;
    ch_param->cfreq2 = 0;

    if (IEEE80211_IS_CHAN_PASSIVE(c)) {
        ch_param->is_chan_passive = TRUE;
    }
    if (IEEE80211_IS_CHAN_DFS(c))
        ch_param->dfs_set = TRUE;

    if (IEEE80211_IS_CHAN_DFS_CFREQ2(c))
        ch_param->dfs_set_cfreq2 = TRUE;

    if (IEEE80211_IS_CHAN_11AXA_HE80_80(c)) {
        ch_param->allow_vht = TRUE;
        ch_param->allow_ht = TRUE;
        ch_param->cfreq1 = c->ic_vhtop_freq_seg1;
        ch_param->cfreq2 = c->ic_vhtop_freq_seg2;
    } else if (IEEE80211_IS_CHAN_11AXA_HE160(c)) {
        ch_param->allow_vht = TRUE;
        ch_param->allow_ht = TRUE;
        ch_param->cfreq1 = c->ic_vhtop_freq_seg1;
        ch_param->cfreq2 = c->ic_vhtop_freq_seg2;
    } else if (IEEE80211_IS_CHAN_11AXA_HE80(c)) {
        ch_param->allow_vht = TRUE;
        ch_param->allow_ht = TRUE;
        ch_param->cfreq1 = c->ic_vhtop_freq_seg1;
        ch_param->cfreq2 = 0;
    } else if (IEEE80211_IS_CHAN_11AXA_HE40PLUS(c) || IEEE80211_IS_CHAN_11AXA_HE40MINUS(c)) {
        ch_param->allow_vht = TRUE;
        ch_param->allow_ht = TRUE;
        ch_param->cfreq1 = c->ic_vhtop_freq_seg1;
        ch_param->cfreq2 = 0;
    } else if (IEEE80211_IS_CHAN_11AXA_HE20(c)) {
        ch_param->allow_vht = TRUE;
        ch_param->allow_ht = TRUE;
        ch_param->cfreq1 = c->ic_vhtop_freq_seg1;
        ch_param->cfreq2 = 0;
    } else if (IEEE80211_IS_CHAN_11AC_VHT80_80(c)) {
        ch_param->allow_vht = TRUE;
        ch_param->allow_ht = TRUE;
        ch_param->cfreq1 = c->ic_vhtop_freq_seg1;
        ch_param->cfreq2 = c->ic_vhtop_freq_seg2;
    } else  if (IEEE80211_IS_CHAN_11AC_VHT160(c)) {
        ch_param->allow_vht = TRUE;
        ch_param->allow_ht = TRUE;
        ch_param->cfreq1 = c->ic_vhtop_freq_seg1;
        ch_param->cfreq2 = c->ic_vhtop_freq_seg2;
    } else if (IEEE80211_IS_CHAN_11AC_VHT80(c)) {
        ch_param->allow_vht = TRUE;
        ch_param->allow_ht = TRUE;
        ch_param->cfreq1 = ieee80211_get_chan_centre_freq(ic,c);
        ch_param->cfreq2 = 0;
    } else if (IEEE80211_IS_CHAN_11AC_VHT40PLUS(c) || IEEE80211_IS_CHAN_11AC_VHT40MINUS(c)) {
        ch_param->allow_vht = TRUE;
        ch_param->allow_ht = TRUE;
        ch_param->cfreq1 = ieee80211_get_chan_centre_freq(ic,c);
        ch_param->cfreq2 = 0;
    } else if (IEEE80211_IS_CHAN_11AC_VHT20(c)) {
        ch_param->allow_vht = TRUE;
        ch_param->allow_ht = TRUE;
        ch_param->cfreq1 = ieee80211_get_chan_centre_freq(ic,c);
        ch_param->cfreq2 = 0;
    } else if (IEEE80211_IS_CHAN_11NA_HT40PLUS(c) || IEEE80211_IS_CHAN_11NA_HT40MINUS(c)) {
        ch_param->allow_ht = TRUE;
        ch_param->cfreq1 = ieee80211_get_chan_centre_freq(ic,c);
        ch_param->cfreq2 = 0;
    } else if (IEEE80211_IS_CHAN_11NA_HT20(c)) {
        ch_param->allow_ht = TRUE;
        ch_param->cfreq1 = ieee80211_get_chan_centre_freq(ic,c);
        ch_param->cfreq2 = 0;
    } else if (IEEE80211_IS_CHAN_11AXG_HE40PLUS(c) || IEEE80211_IS_CHAN_11AXG_HE40MINUS(c)) {
        ch_param->allow_vht = TRUE;
        ch_param->allow_ht = TRUE;
        ch_param->cfreq1 = ieee80211_get_chan_centre_freq(ic,c);
        ch_param->cfreq2 = 0;
    } else if (IEEE80211_IS_CHAN_11AXG_HE20(c)) {
        ch_param->allow_vht = TRUE;
        ch_param->allow_ht = TRUE;
        ch_param->cfreq1 = ieee80211_get_chan_centre_freq(ic,c);
        ch_param->cfreq2 = 0;
    } else if (IEEE80211_IS_CHAN_11NG_HT40PLUS(c) || IEEE80211_IS_CHAN_11NG_HT40MINUS(c)) {
        ch_param->allow_ht = TRUE;
        ch_param->cfreq1 = ieee80211_get_chan_centre_freq(ic,c);
        ch_param->cfreq2 = 0;
    } else if (IEEE80211_IS_CHAN_11NG_HT20(c)) {
        ch_param->allow_ht = TRUE;
        ch_param->cfreq1 = ieee80211_get_chan_centre_freq(ic,c);
        ch_param->cfreq2 = 0;
    }

    ic->ic_update_phy_mode(ch_param, ic);

    if (IEEE80211_IS_CHAN_HALF(c))
        ch_param->half_rate = TRUE;
    if (IEEE80211_IS_CHAN_QUARTER(c))
        ch_param->quarter_rate = TRUE;

    /* Also fill in power information */
    ch_param->minpower = c->ic_minpower;
    ch_param->maxpower = c->ic_maxpower;
    ch_param->maxregpower = c->ic_maxregpower;
    ch_param->antennamax = c->ic_antennamax;
    ch_param->reg_class_id = c->ic_regClassId;

    return 0;
}

QDF_STATUS mlme_ext_vap_custom_aggr_size_send(
                                        struct vdev_mlme_obj *vdev_mlme,
                                        bool is_amsdu)
{
    return vdev_mgr_set_custom_aggr_size_send(vdev_mlme, is_amsdu);
}

static uint16_t mlme_ext_peer_ref_release(struct ieee80211vap *vap,
                                          bool ref_rel_enable)
{
    qdf_list_t *logical_del_peerlist;
    struct wlan_logically_del_peer *temp_peer = NULL;
    uint16_t logical_deleted_peer_count = 0;
    struct ieee80211_node *ni;
    struct wlan_objmgr_peer *peer;
    qdf_list_node_t *peerlist;
    bool skip_ref_rel;

    logical_del_peerlist =
                  wlan_objmgr_vdev_get_log_del_peer_list(vap->vdev_obj,
                                                         WLAN_MLME_SB_ID);
    if (!logical_del_peerlist)
        return QDF_STATUS_E_FAILURE;

    while (QDF_IS_STATUS_SUCCESS(qdf_list_remove_front(logical_del_peerlist,
                                 &peerlist))) {
           temp_peer = qdf_container_of(peerlist,
                                        struct wlan_logically_del_peer,
                                        list);
           peer = temp_peer->peer;
           ni = wlan_peer_get_mlme_ext_obj(peer);
           skip_ref_rel = false;

           if (vap->iv_bss == ni) {
               mlme_info("Skip for BSS peer");
               skip_ref_rel = true;
           }

           if (skip_ref_rel == false && ref_rel_enable &&
               vap->iv_peer_rel_ref(vap, ni, peer->macaddr))
               mlme_err("Failed to handle peer del failure");

           wlan_objmgr_peer_release_ref(peer, WLAN_MLME_SB_ID);
           qdf_mem_free(temp_peer);
           logical_deleted_peer_count++;
    }
    qdf_list_destroy(logical_del_peerlist);
    qdf_mem_free(logical_del_peerlist);
    return logical_deleted_peer_count;
}

QDF_STATUS mlme_ext_peer_delete_all_response_event_handler(
                                        struct vdev_mlme_obj *vdev_mlme,
                                        struct peer_delete_all_response *rsp)
{
    struct wlan_objmgr_vdev *vdev;
    struct ieee80211vap *vap;
    uint16_t logically_deleted_peer = 0;

    vdev = vdev_mlme->vdev;
    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (NULL == vap) {
        mlme_err("Event received for Invalid/Deleted vap handle");
        return QDF_STATUS_E_FAILURE;
    }

#ifdef QCA_SUPPORT_CP_STATS
    vdev_cp_stats_peer_delete_all_resp_inc(vap->vdev_obj, 1);
#endif

    mlme_ext_peer_ref_release(vap, true);

    /*
     * corner case scenario to delete new peers allocated
     * between peer delete all request and response
     */
    if (wlan_vdev_mlme_get_state(vdev) == WLAN_VDEV_S_SUSPEND &&
        wlan_vdev_get_peer_count(vdev) > 1) {

            logically_deleted_peer = mlme_ext_peer_ref_release(vap, false);
            if ((wlan_vdev_get_peer_count(vdev)-1) >
                                              logically_deleted_peer) {
                mlme_info("PSOC_%d VDEV_%d: Send delete all peers: %d",
                          wlan_psoc_get_id(wlan_vdev_get_psoc(vdev)),
                          wlan_vdev_get_id(vdev),
                          wlan_vdev_get_peer_count(vdev));
                mlme_vdev_send_deauth(vap);
            }
    }

    return QDF_STATUS_SUCCESS;
}


void wlan_mlme_psoc_bcn_update_cb(struct wlan_objmgr_psoc *psoc,
                void *msg,
                uint8_t index)
{
    struct wlan_objmgr_psoc_objmgr *objmgr;
    struct wlan_objmgr_pdev *pdev = NULL;
    int id =0;
    wlan_dev_t ic;
    struct ieee80211vap *vap;

    objmgr = &psoc->soc_objmgr;
    /* Deferred AI: Copy rnr cache from one soc to another
     * if exists so vaps can access its soc's rnr cache
     */
    for (id=0;id<WLAN_UMAC_MAX_PDEVS;id++) {
        pdev = objmgr->wlan_pdev_list[id];
        if (!pdev)
            continue;
        ic = wlan_pdev_get_mlme_ext_obj(pdev);
        if (ic && !IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) && ic->ic_oob_enable) {
            TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
                if (vap && !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap) &&
                    vap->iv_opmode == IEEE80211_M_HOSTAP &&
                    ieee80211_is_vap_state_running(vap)) {
                    vap->iv_oob_update = 1;
                    wlan_vdev_beacon_update(vap);
                    vap->iv_oob_update = 0;
                }
            }
        }
    }
}

QDF_STATUS mlme_oob_bcn_sched_cb(struct scheduler_msg *msg)
{
    wlan_objmgr_iterate_psoc_list(wlan_mlme_psoc_bcn_update_cb,
                                  NULL, WLAN_MLME_NB_ID);
    return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_tmpl_update_lower_band_vdevs(struct wlan_objmgr_psoc *psoc)
{
     struct scheduler_msg msg = {0};
     int ret;

     msg.bodyptr = psoc;
     msg.callback = mlme_oob_bcn_sched_cb;
     msg.flush_callback = NULL;

     ret = scheduler_post_message(QDF_MODULE_ID_MLME,
                     QDF_MODULE_ID_MLME,
                     QDF_MODULE_ID_MLME,
                     &msg);

     return ret;
}
