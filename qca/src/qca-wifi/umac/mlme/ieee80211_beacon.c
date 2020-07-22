/*
 * Copyright (c) 2011-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * 2008 Atheros Communications Inc.
 * All Rights Reserved.
 *
 */

#include <wlan_cmn.h>
#include <qdf_status.h>
#include <reg_services_public_struct.h>
#include <ieee80211_regdmn_dispatcher.h>
#include <osdep.h>
#include "ieee80211_mlme_dfs_dispatcher.h"
#include <ieee80211_var.h>
#include <ieee80211_proto.h>
#include <ieee80211_channel.h>
#include <ieee80211_rateset.h>
#include "ieee80211_mlme_priv.h"
#include "ieee80211_bssload.h"
#include "ieee80211_quiet_priv.h"
#include "ieee80211_ucfg.h"
#include "ieee80211_sme_api.h"
#include <wlan_son_pub.h>
#include <wlan_utility.h>
#ifdef WLAN_CONV_CRYPTO_SUPPORTED
#include "wlan_crypto_global_def.h"
#include "wlan_crypto_global_api.h"
#endif
#include <wlan_vdev_mlme.h>
#include "ol_if_athvar.h"
#include "cfg_ucfg_api.h"

#ifndef NUM_MILLISEC_PER_SEC
#define NUM_MILLISEC_PER_SEC 1000
#endif
/*
 *  XXX: Because OID_DOT11_ENUM_BSS_LIST is queried every 30 seconds,
 *       set the interval of Beacon Store to 30.
 *       This is to make sure the AP(GO)'s own scan_entry always exsits in the scan table.
 *       This is a workaround, a better solution is to add reference counter,
 *       to prevent its own scan_entry been flushed out.
 */
#define INTERVAL_STORE_BEACON 30

#define IEEE80211_TSF_LEN       (8)
/*
 *  XXX: Include an intra-module function from ieee80211_input.c.
 *       When we move regdomain code out to separate .h/.c files
 *       this should go to that .h file.
 */

/*
 * ieee80211_add_rsn_ie: Add RSN IE in the frame
 *
 * @vap : VAP handle
 * @frm : frm pointer to add the IE
 * @bo  : Beacon offsets to mark IEs' start address
 *
 * Return: frm pointer after adding, if RSN IE is added,
 *         NULL elsewhere
 */
static inline uint8_t *ieee80211_add_rsn_ie(struct ieee80211vap *vap,
        uint8_t *frm, struct ieee80211_beacon_offsets **bo)
{
    if (!vap->iv_rsn_override) {
        IEEE80211_VAP_LOCK(vap);
        if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_RSN, -1, &frm,
                TYPE_ALL_BUF, NULL, true)) {

            /* Add RSN IE if not present */
#if ATH_SUPPORT_HS20
            if (!vap->iv_osen) {
#endif

#ifdef WLAN_CONV_CRYPTO_SUPPORTED
                if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj,
                            (1 << WLAN_CRYPTO_AUTH_RSNA))) {
                    frm = wlan_crypto_build_rsnie(vap->vdev_obj, frm, NULL);
                    if(!frm) {
                        (*bo)->bo_rsn = NULL;
                        IEEE80211_VAP_UNLOCK(vap);
                        return NULL;
                    }
                }
#else
                if (RSN_AUTH_IS_RSNA(&vap->iv_rsn))
                    frm = ieee80211_setup_rsn_ie(vap, frm);
#endif

#if ATH_SUPPORT_HS20
            } else {
                (*bo)->bo_rsn = NULL;
            }
#endif
        }
        IEEE80211_VAP_UNLOCK(vap);
    }
    return frm;
}

/*
 * ieee80211_add_vht_ies: Add VHT cap, op, power envelope, channel switch
 *                        wrapper, and EBSS load IEs in the frame
 *
 * @ni  : Node information handle
 * @ic  : State handle
 * @vap : VAP handle
 * @frm : frm pointer to add IEs
 * @bo  : Beacon offsets to mark IEs' start address
 *
 * Return: frm pointer after adding IEs
 */
static inline uint8_t *ieee80211_add_vht_ies(struct ieee80211_node *ni,
        struct ieee80211com *ic, struct ieee80211vap *vap, uint8_t *frm,
        struct ieee80211_beacon_offsets **bo)
{
    if (ieee80211_vap_wme_is_set(vap) &&
        (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
        (IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) ||
         IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
         IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)) &&
            ieee80211vap_vhtallowed(vap)) {
        /* 57. VHT Capabilities */
        (*bo)->bo_vhtcap = frm;
        frm = ieee80211_add_vhtcap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON, NULL, NULL);

        /* 58. VHT Operation */
        (*bo)->bo_vhtop = frm;
        frm = ieee80211_add_vhtop(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON, NULL);

        /* 59. Transmit Power Envelope element */
        if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
            (*bo)->bo_vhttxpwr = frm;
            frm = ieee80211_add_vht_txpwr_envlp(frm, ni, ic,
                                        IEEE80211_FC0_SUBTYPE_BEACON,
                                        !IEEE80211_VHT_TXPWR_IS_SUB_ELEMENT);

            /* 60. Channel Switch Wrapper */
            (*bo)->bo_vhtchnsw = frm;
        } else {
            (*bo)->bo_vhttxpwr = NULL;
            (*bo)->bo_vhtchnsw = NULL;
        }

        /* 61. Extended BSS Load element */
        frm = ieee80211_ext_bssload_beacon_setup(vap, ni, *bo, frm);

    } else {
        (*bo)->bo_vhtcap = NULL;
        (*bo)->bo_vhtop = NULL;
        (*bo)->bo_vhttxpwr = NULL;
        (*bo)->bo_vhtchnsw = NULL;
        (*bo)->bo_ext_bssload = NULL;
    }
    return frm;
}

#if ATH_SUPPORT_IBSS_DFS
static u_int8_t
ieee80211_ibss_dfs_element_enable(struct ieee80211vap *vap, struct ieee80211com *ic)
{
    u_int8_t enable_ibssdfs = 1;

    if (ic->ic_flags & IEEE80211_F_CHANSWITCH) {
        if (!(vap->iv_bsschan->ic_flagext & IEEE80211_CHAN_DFS)) {
            enable_ibssdfs = 0;
        }
    } else {
        if (!(ic->ic_curchan->ic_flagext & IEEE80211_CHAN_DFS)) {
            enable_ibssdfs = 0;
        }
    }

    return enable_ibssdfs;
}
#endif

#if QCN_IE
static void
ieee80211_flag_beacon_sent(struct ieee80211vap *vap) {
    struct ieee80211com *ic = vap->iv_ic;
    qdf_hrtimer_data_t *bpr_hrtimer = &vap->bpr_timer;

    /* If there is a beacon to be scheduled within the timer window,
     * drop the response and cancel the timer. If timer is not active,
     * qdf_hrtimer_get_remaining will return a negative value, so the timer
     * expiry will be less than beacon timestamp and timer won't be cancelled.
     * If timer expiry is greater than the beacon timestamp, then timer will
     * be cancelled.
     */

    if (qdf_ktime_to_ns(qdf_ktime_add(qdf_hrtimer_get_remaining(bpr_hrtimer), qdf_ktime_get())) >
        qdf_ktime_to_ns(vap->iv_next_beacon_tstamp) + ic->ic_bcn_latency_comp * QDF_NSEC_PER_MSEC) {

        /* Cancel the timer as beacon is sent instead of a broadcast response */
    if (qdf_hrtimer_cancel(bpr_hrtimer)) {
            vap->iv_bpr_timer_cancel_count++;

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                "Cancel timer: %s| %d | Delay: %d | Current time %lld | Next beacon tstamp: %lld | "
                "beacon interval: %d ms | Timer cb: %d | Enqueued: %d\n", \
                __func__, __LINE__, vap->iv_bpr_delay, qdf_ktime_to_ns(qdf_ktime_get()), qdf_ktime_to_ns(vap->iv_next_beacon_tstamp), \
                ic->ic_intval, qdf_hrtimer_callback_running(bpr_hrtimer), qdf_hrtimer_is_queued(bpr_hrtimer));
        }
    }

    /* Calculate the next beacon timestamp */
    vap->iv_next_beacon_tstamp = qdf_ktime_add_ns(qdf_ktime_get(), ic->ic_intval * QDF_NSEC_PER_MSEC);

}
#endif /* QCN_IE */

static uint8_t *ieee80211_add_mbss_ie(struct ieee80211_beacon_offsets *bo, uint8_t *frm,
                                        struct ieee80211_node *ni, uint8_t frm_subtype)
{
    struct ieee80211vap *vap;
    struct ieee80211com *ic;
    struct ieee80211vap *tmpvap = NULL;
    u_int8_t *new;

    if (!frm || !ni) {
        return NULL;
    }

    vap = ni->ni_vap;
    ic = vap->iv_ic;
    new = frm;

    /*
     * For a transmitting VAP, if IE already exists and
     * there is atleast one non-transmitting VAP profile,
     * we return right away
     */
    if (!IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
        if (ic->ic_mbss.num_non_transmit_vaps) {
            if (*frm == IEEE80211_ELEMID_MBSSID) {
                bo->bo_mbssid_ie = frm;
                frm += bo->bo_mbssid_ie_len;
                return frm;
            }
        }
        else {
            /* No non-transmitting VAPs available, so return */
            return frm;
        }
    }

    /*
     * Add a profile for non-transmitting VAP to IE
     */
    if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
        if (!ieee80211_is_vap_state_stopping(vap)) {
            if (!qdf_atomic_read(&vap->iv_mbss.iv_added_to_mbss_ie)) {
                new = ieee80211_mbss_add_profile(frm, ni,
                        &ic->ic_mbss.num_non_transmit_vaps,
                        frm_subtype);
                if (!new) {
                    return NULL;
                } else {
                    /* success with adding profile */
                    bo->bo_mbssid_ie = frm;
                    bo->bo_mbssid_ie_len = new - frm;
                    qdf_atomic_set(&vap->iv_mbss.iv_added_to_mbss_ie, 1);
                    return new;
                }
            } else {
                /* VAP profile already part of IE */
                if (*frm == IEEE80211_ELEMID_MBSSID) {
                    frm += bo->bo_mbssid_ie_len;
                    return frm;
                }
            }
        } else { /* is_vap_stopping */
            /*
             * VAP has been stopped, fall through and add
             * other VAPs except this one to IE
             */
            qdf_atomic_set(&vap->iv_mbss.iv_added_to_mbss_ie, 0);
        }
    } /* NON_TRANSMIT_ENABLED */

    /*
     * Below code is run in three cases:
     * 1. If it is a transmitting VAP, IE doesn't exist, and there is
     *    atleast one non-transmitting VAP
     * 2. If a non-transmiting VAP has been stopped, other non-transmitting
     *    VAPs are added to IE excluding the VAP in STOPPED state
     * 3. If the IE in beacon has been overwritten
     */

    ic->ic_mbss.num_non_transmit_vaps = 0;

    /* When beacon already has the MBSSID IE, the IE needs to be zeroed out */
    if (bo->bo_mbssid_ie == frm)
        memset(bo->bo_mbssid_ie, 0, bo->bo_mbssid_ie_len);

    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(tmpvap) &&
            !ieee80211_is_vap_state_stopping(tmpvap) &&
            tmpvap->iv_is_up) {
            new = ieee80211_mbss_add_profile(frm, tmpvap->iv_bss,
                                                 &ic->ic_mbss.num_non_transmit_vaps,
                                                 frm_subtype);
        if (!new)
                return NULL;

        qdf_atomic_set(&tmpvap->iv_mbss.iv_added_to_mbss_ie, 1);
        }
    } /* TAILQ_FOREACH */

    if (ic->ic_mbss.num_non_transmit_vaps != 0) {
        bo->bo_mbssid_ie = frm;
        bo->bo_mbssid_ie_len = new - frm;
    } else {
        bo->bo_mbssid_ie = NULL;
        bo->bo_mbssid_ie_len = 0;
    }

    return new;
}

/*
 * Delete VAP profile from MBSSID IE
 */
void ieee80211_mbssid_del_profile(struct ieee80211vap *vap)
{
  struct ieee80211com *ic = vap->iv_ic;
  struct ol_ath_vap_net80211 *avn;

  avn = OL_ATH_VAP_NET80211(ic->ic_mbss.transmit_vap);
  vap->iv_mbss.mbssid_add_del_profile = 1;
  ic->ic_vdev_beacon_template_update(vap);
  if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan))
      avn->av_pr_rsp_wbuf = ieee80211_prb_rsp_alloc_init(vap->iv_bss,
                        &avn->av_prb_rsp_offsets);

}

#if OBSS_PD
void ieee80211_sr_ie_reset(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;

    vap->iv_sr_ie_reset = 1;
    ic->ic_vdev_beacon_template_update(vap);
}
qdf_export_symbol(ieee80211_sr_ie_reset);
#endif /* OBSS PD */

static u_int8_t *
ieee80211_beacon_init(struct ieee80211_node *ni, struct ieee80211_beacon_offsets *bo,
                      u_int8_t *frm)
{
    struct ieee80211vap *vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_rateset *rs = &ni->ni_rates;
#ifndef WLAN_CONV_CRYPTO_SUPPORTED
    struct ieee80211_rsnparms *rsn = &vap->iv_rsn;
#endif
    int enable_htrates;
    struct ieee80211_bwnss_map nssmap;
#if UMAC_SUPPORT_WNM
    u_int8_t *fmsie = NULL;
    u_int32_t fms_counter_mask = 0;
    u_int8_t fmsie_len = 0;
#endif /* UMAC_SUPPORT_WNM */
    int num_of_rates = 0, num_of_xrates = 0;
    enum ieee80211_phymode mode;
    struct ieee80211_rateset *rs_op;
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);
#if DBDC_REPEATER_SUPPORT
    struct global_ic_list *ic_list = ic->ic_global_list;
#endif
    struct ieee80211vap *orig_vap;
    struct ieee80211_node *non_transmit_ni = NULL;
    struct ol_ath_vap_net80211 *av;
    uint8_t len = 0;

    orig_vap = vap = ni->ni_vap;

    if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
        /* We operate on tx vap's beacon buffer */
        vap = ic->ic_mbss.transmit_vap;
        non_transmit_ni = ni;
        ni = vap->iv_bss;
    }

    av = OL_ATH_VAP_NET80211(vap);

    mode = wlan_get_desired_phymode(vap);
    rs_op = &(vap->iv_op_rates[mode]);

    qdf_mem_zero(&nssmap, sizeof(nssmap));

    KASSERT(vap->iv_bsschan != IEEE80211_CHAN_ANYC, ("no bss chan"));

    /* ------------- Fixed Fields ------------- */
    /* 1. Timestamp */
    frm += IEEE80211_TSF_LEN; /* Skip TSF field */

    /* 2. Beacon interval */
    *(u_int16_t *)frm = htole16(ieee80211_node_get_beacon_interval(ni));
    frm += 2;

    /* 3. Capability Information */
    ieee80211_add_capability(frm, ni);
    bo->bo_caps = (u_int16_t *)frm;
    frm += 2;

    /* ------------- Regular and Extension IEs ------------- */
    /* 4. Service Set Identifier (SSID) */
    *frm++ = IEEE80211_ELEMID_SSID;

    if (IEEE80211_VAP_IS_HIDESSID_ENABLED(vap)) {
        *frm++ = 0;
    } else {
        *frm++ = ni->ni_esslen;
        OS_MEMCPY(frm, ni->ni_essid, ni->ni_esslen);
        frm += ni->ni_esslen;
    }

    /* 5. Supported Rates and BSS Membership Selectors */
    bo->bo_rates = frm;
    if (vap->iv_flags_ext2 & IEEE80211_FEXT2_BR_UPDATE) {
        frm = ieee80211_add_rates(frm, rs_op);
    } else{
        frm = ieee80211_add_rates(frm, rs);
    }

    /* 6. DSSS Parameter Se */
    /* XXX better way to check this? */
    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) &&
            !IEEE80211_IS_CHAN_FHSS(vap->iv_bsschan)) {
        *frm++ = IEEE80211_ELEMID_DSPARMS;
        *frm++ = 1;
        *frm++ = ieee80211_chan2ieee(ic, vap->iv_bsschan);
    }

    /* 7. CF Parameter Set */
    bo->bo_cf_params = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_CFPARMS, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_cf_params = NULL;

    bo->bo_tim = frm;
    if (vap->iv_opmode == IEEE80211_M_IBSS) {
        /* 8. IBSS Parameter Set */
        *frm++ = IEEE80211_ELEMID_IBSSPARMS;
        *frm++ = 2;
        *frm++ = 0; *frm++ = 0;                      /* Review ATIM window */
        bo->bo_tim_len = 0;
    } else {
        /* 9. Traffic indication map (TIM) */
        struct ieee80211_ath_tim_ie *tie = (struct ieee80211_ath_tim_ie *) frm;

        tie->tim_ie        = IEEE80211_ELEMID_TIM;
        tie->tim_len       = 4;                      /* length */
        tie->tim_count     = 0;                      /* DTIM count */
        tie->tim_period    = vap->vdev_mlme->proto.generic.dtim_period;    /* DTIM period */
        tie->tim_bitctl    = 0;                      /* bitmap control */
        tie->tim_bitmap[0] = 0;                      /* Partial Virtual Bitmap */
        frm               += sizeof(struct ieee80211_ath_tim_ie);
        bo->bo_tim_len     = 1;
    }
    bo->bo_tim_trailer = frm;

    /* 10. Country */
    /* cfg80211_TODO: IEEE80211_FEXT_COUNTRYIE
     * ic_country.iso are we populating ?
     * we are building channel list from ic
     * so we should have proper IE generated
     */
    if (IEEE80211_IS_COUNTRYIE_ENABLED(ic) && ieee80211_vap_country_ie_is_set(vap)) {
        frm = ieee80211_add_country(frm, vap);
    }

    /* 11. Power Constraint */
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
        bo->bo_pwrcnstr = frm;
        *frm++ = IEEE80211_ELEMID_PWRCNSTR;
        *frm++ = 1;
        *frm++ = IEEE80211_PWRCONSTRAINT_VAL(vap);
    } else {
         bo->bo_pwrcnstr = NULL;
    }

    /* 12. Channel Switch Announcement */
    bo->bo_chanswitch = frm;

#if ATH_SUPPORT_IBSS_DFS
    if(vap->iv_ibssdfs_state == IEEE80211_IBSSDFS_CHANNEL_SWITCH)
    {
        /* Add the csa ie when we are in CSA mode */
        frm = ieee80211_add_ibss_csa(frm, vap);
        /* decrement TBTT count */
        ((struct ieee80211_ath_channelswitch_ie *)
         (bo->bo_chanswitch))->tbttcount =
                         ic->ic_chanchange_tbtt - vap->iv_chanchange_count;
    }
#endif

    /* 13. Quiet */
    frm = ieee80211_quiet_beacon_setup(vap, ic, bo, frm);

#if ATH_SUPPORT_IBSS_DFS
    /* 14. IBSS DFS */
    if (vap->iv_opmode == IEEE80211_M_IBSS) {
        if (ieee80211_ibss_dfs_element_enable(vap, ic)) {
            ieee80211_build_ibss_dfs_ie(vap);
            bo->bo_ibssdfs = frm;
            frm = ieee80211_add_ibss_dfs(frm, vap);
        } else {
            bo->bo_ibssdfs = NULL;
            OS_MEMZERO(&vap->iv_ibssdfs_ie_data, sizeof(struct ieee80211_ibssdfs_ie));
        }
    }
#endif /* ATH_SUPPORT_IBSS_DFS */

    /* 15. TPC Report:
     * Add the TPC Report IE in the beacon if 802.11h or RRM capability
     * is set.
     */
    if ((ieee80211_ic_doth_is_set(ic) &&
         ieee80211_vap_doth_is_set(vap)) ||
         ieee80211_vap_rrm_is_set(vap)) {
        bo->bo_tpcreport = frm;
        frm = ieee80211_add_tpc_ie(frm, vap);
    } else {
        bo->bo_tpcreport = NULL;
    }

    /* 16. ERP */
    if (IEEE80211_IS_CHAN_ANYG(vap->iv_bsschan) ||
        IEEE80211_IS_CHAN_11NG(vap->iv_bsschan) ||
        IEEE80211_IS_CHAN_11AXG(vap->iv_bsschan)) {
        bo->bo_erp = frm;
        frm = ieee80211_add_erp(frm, ic);
    } else {
        bo->bo_erp = NULL;
    }

    /* 17.  Extended Supported Rates and BSS Membership Selectors */
    bo->bo_xrates = frm;
    if (vap->iv_flags_ext2 & IEEE80211_FEXT2_BR_UPDATE) {
        num_of_rates = rs_op->rs_nrates;
        if (num_of_rates > IEEE80211_RATE_SIZE) {
            num_of_xrates = num_of_rates - IEEE80211_RATE_SIZE;
        }
        if(num_of_xrates > 0){
            frm = ieee80211_add_xrates(vap, frm, rs_op);
        }
    } else {
        frm = ieee80211_add_xrates(vap, frm, rs);
    }

    /* 18. RSN */
    bo->bo_rsn = frm;
    frm = ieee80211_add_rsn_ie(vap, frm, &bo);
    if (!frm)
        return NULL;

    /* 19. QBSS Load */
    frm = ieee80211_qbssload_beacon_setup(vap, ni, bo, frm);

    /* 20. EDCA Parameter Set */
    bo->bo_edca = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_EDCA, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_edca = NULL;

    /* 21. QoS Capability */
    bo->bo_qos_cap = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_QOS_CAP, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_qos_cap = NULL;

    /* 22. AP Channel Report */
    if (vap->ap_chan_rpt_enable) {
        bo->bo_ap_chan_rpt = frm;
        frm = ieee80211_add_ap_chan_rpt_ie (frm, vap);
    } else {
        bo->bo_ap_chan_rpt = NULL;
    }

    /* 23. BSS Average Access Delay */
    bo->bo_bss_avg_delay = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_BSS_AVG_ACCESS_DELAY,
                -1, &frm, TYPE_ALL_BUF, NULL, true))
        bo->bo_bss_avg_delay = NULL;

    /* 24. Antenna */
    bo->bo_antenna = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_ANTENNA, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_antenna = NULL;

    /* 25. BSS Available Admission Capacity */
    bo->bo_bss_adm_cap = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_BSS_ADMISSION_CAP, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_bss_adm_cap = NULL;

#ifndef ATH_SUPPORT_WAPI
    /* 26. BSS AC Access Delay */
    bo->bo_bss_ac_acc_delay = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_BSS_AC_ACCESS_DELAY, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_bss_ac_acc_delay = NULL;
#endif

    /* 27. Measurement Pilot Transmissions */
    bo->bo_msmt_pilot_tx = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_MESUREMENT_PILOT_TX, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_msmt_pilot_tx = NULL;

    /* 28. Multiple BSSID */
    if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE)) {
        frm = ieee80211_add_mbss_ie(&av->av_beacon_offsets, frm,
                                (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(orig_vap)) ?
                                non_transmit_ni: ni, IEEE80211_FRAME_TYPE_BEACON);
        if (!frm)
            return NULL;
    }

    /* 29. RM Enabled Capbabilities */
    frm = ieee80211_add_rrm_cap_ie(frm, ni);

    /* 30. Mobility Domain */
    bo->bo_mob_domain = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_MOBILITY_DOMAIN, -1, &frm,
            TYPE_ALL_BUF, NULL, true))
        bo->bo_mob_domain = NULL;

    /* 31. DSE Registered Location */
    bo->bo_dse_reg_loc = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_DSE_REG_LOCATION, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_dse_reg_loc = NULL;

    /* 32. Extended Channel Switch Announcement */
    bo->bo_ecsa = frm;

    /* 33. Supported Operating Classes */
    bo->bo_opt_class = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_SUPP_OP_CLASS, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_opt_class = NULL;

    /*
     * check for vap is done in ieee80211vap_htallowed.
     * remove iv_bsschan check to support multiple channel operation.
     */
    enable_htrates = ieee80211vap_htallowed(vap);
    if (ieee80211_vap_wme_is_set(vap) &&
        (IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) ||
         IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
         IEEE80211_IS_CHAN_11N(vap->iv_bsschan)) &&
        enable_htrates) {

        if (!(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan))) {
            /* 34. HT Capabilities */
            bo->bo_htcap = frm;
            frm = ieee80211_add_htcap(frm, ni, IEEE80211_FC0_SUBTYPE_BEACON);

            /* 35. HT Operation */
            bo->bo_htinfo = frm;
            frm = ieee80211_add_htinfo(frm, ni);
        }

        /* 36. 20/40 BSS Coexistence */
        bo->bo_2040_coex = frm;
        if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_2040_COEXT, -1, &frm,
                    TYPE_ALL_BUF, NULL, true))
            bo->bo_2040_coex = NULL;

        /* 37. Overlapping BSS Scan Parameters */
        if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
            bo->bo_obss_scan = frm;
            frm = ieee80211_add_obss_scan(frm, ni);
        } else {
            bo->bo_obss_scan = NULL;
        }
    } else {
        bo->bo_htcap = NULL;
        bo->bo_htinfo = NULL;
        bo->bo_2040_coex = NULL;
        bo->bo_obss_scan = NULL;
    }

    /* 38. Extended Capabilities */
    bo->bo_extcap = frm;
    frm = ieee80211_add_extcap(frm, ni, IEEE80211_FC0_SUBTYPE_BEACON);

#if UMAC_SUPPORT_WNM
    /* 39. FMS Descriptor */
    if (ieee80211_vap_wnm_is_set(vap) && ieee80211_wnm_fms_is_set(vap->wnm)) {
        bo->bo_fms_desc = frm;
        ieee80211_wnm_setup_fmsdesc_ie(ni, 0, &fmsie, &fmsie_len, &fms_counter_mask);
        if (fmsie_len)
            OS_MEMCPY(frm, fmsie, fmsie_len);
        frm += fmsie_len;
        bo->bo_fms_trailer = frm;
        bo->bo_fms_len = (u_int16_t)(frm - bo->bo_fms_desc);
    } else {
        bo->bo_fms_desc = NULL;
        bo->bo_fms_len = 0;
        bo->bo_fms_trailer = NULL;
    }
#endif /* UMAC_SUPPORT_WNM */

    /* 40. QoS Traffic Capability */
    bo->bo_qos_traffic = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_QOS_TRAFFIC_CAP, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_qos_traffic = NULL;

    /* 41. Time Advertisement */
    bo->bo_time_adv = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_TIME_ADVERTISEMENT, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_time_adv = NULL;


    /* 42. Interworking (Hotspot 2.0) */
    bo->bo_interworking = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_INTERWORKING, -1, &frm,
            TYPE_ALL_BUF, NULL, true))
        bo->bo_interworking = NULL;


    /* 43. Advertisement Protocol (Hotspot 2.0) */
    bo->bo_adv_proto = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_ADVERTISEMENT_PROTO, -1, &frm,
            TYPE_ALL_BUF, NULL, true))
        bo->bo_adv_proto = NULL;


    /* 44. Roaming Consortium (Hotspot 2.0) */
    bo->bo_roam_consortium = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_ROAMING_CONSORTIUM, -1, &frm,
            TYPE_ALL_BUF, NULL, true))
        bo->bo_roam_consortium = NULL;

    /* 45. Emergency Alert Identifier */
    bo->bo_emergency_id = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_EMERGENCY_ALERT_ID, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_emergency_id = NULL;

    /* 46. Mesh ID */
    bo->bo_mesh_id = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_MESH_ID, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_mesh_id = NULL;

    /* 47. Mesh Configuration */
    bo->bo_mesh_conf = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_MESH_CONFIG, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_mesh_conf = NULL;

    /* 48. Mesh Awake window */
    bo->bo_mesh_awake_win = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_MESH_AWAKE_WINDOW, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_mesh_awake_win = NULL;

    /* 49. Beacon Timing */
    bo->bo_beacon_time = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_BEACON_TIMING, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_beacon_time = NULL;

    /* 50. MCCAOP Advertisement Overview */
    bo->bo_mccaop_adv_ov = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_MCCAOP_ADV_OVERVIEW, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_mccaop_adv_ov = NULL;

    /* 51. MCCAOP Advertisement */
    bo->bo_mccaop_adv = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_MCCAOP_ADV, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_mccaop_adv = NULL;

    /* 52. Mesh Channel Switch Parameters */
    bo->bo_mesh_cs_param = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_MESH_CHANSWITCH_PARAM, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_mesh_cs_param = NULL;

    /* 53. QMF Policy */
    bo->bo_qmf_policy = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_QMF_POLICY, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_qmf_policy = NULL;

    /* 54. QLoad Report */
    bo->bo_qload_rpt = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_QLOAD_REPORT, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_qload_rpt = NULL;

    /* 55. HCCA TXOP Update Count */
    bo->bo_hcca_upd_cnt = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_HCCA_TXOP_UPD_CNT, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_hcca_upd_cnt = NULL;

    /* 56. Multi-band */
    bo->bo_multiband = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_MULTIBAND, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_multiband = NULL;

    /*
     * VHT capable:
     * Add VHT capabilties (57), operation (58), Tx Power envelope (59),
     * Channel Switch Wrapper (60) and Extended BSS Load (61) elements,
     * if device is in 11ac operating mode (or) 256QAM is enabled in 2.4G
     */
    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        frm = ieee80211_add_vht_ies(ni, ic, vap, frm, &bo);
    } else {
        /*
         * Add Channel switch wrapper IE for 6G
         */
        bo->bo_vhtcap = NULL;
        bo->bo_vhtop = NULL;
        bo->bo_ext_bssload = NULL;
        bo->bo_vhttxpwr = NULL;
        bo->bo_vhtchnsw = frm;
    }

    /* 62. Quiet Channel */
    bo->bo_quiet_chan = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_QUIET_CHANNEL, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_quiet_chan = NULL;

    /* 63. Operating Mode Notification */
    bo->bo_opt_mode_note = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_OP_MODE_NOTIFY, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_opt_mode_note = NULL;

    /* 64. Reduced Neighbor Report */
    if (vap->rnr_enable) {
        bo->bo_rnr = frm;
        frm = ieee80211_add_rnr_ie(frm, vap, vap->iv_bss->ni_essid, vap->iv_bss->ni_esslen);
    } else {
        bo->bo_rnr = NULL;
    }
    /* rnr_enable enables advertisement of all vaps across radios and scanned APs.
     * When rnr_enable is set, it takes precedence over oob_enable as oob_enable
     * advertises only subset (6Ghz APs) of rnr_enable. oob_enable is used by default
     * and can be turned off to stop 6Ghz AP advertisement in lower band APs.
     */
    if (!vap->rnr_enable && ic->ic_oob_enable && !IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        bo->bo_rnr = frm;
        frm = ieee80211_add_oob_rnr_ie(frm, vap, vap->iv_bss->ni_essid,
                                       vap->iv_bss->ni_esslen,
                                       IEEE80211_FC0_SUBTYPE_BEACON);
    } else {
        bo->bo_rnr = NULL;
    }

    /* 65. TVHT Operation */
    bo->bo_tvht = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_TVHT_OP, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_tvht = NULL;


#if QCN_ESP_IE
    /* 66. Estimated Service Parameters */
    if(ic->ic_esp_periodicity){
        bo->bo_esp_ie = frm;
        frm = ieee80211_add_esp_info_ie(frm, ic, &bo->bo_esp_ie_len);
    }
#endif

    /* 67. Future Channel Guidance */
    bo->bo_future_chan = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_FUTURE_CHANNEL_GUIDE, &frm, TYPE_ALL_BUF, NULL, true))
        bo->bo_future_chan = NULL;

    /* 68. Common Advertisement Group (CAG) Number */
    bo->bo_cag_num = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_CAG_NUMBER, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_cag_num = NULL;

    /* 69. FILS Indication */
    bo->bo_fils_ind = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_FILS_INDICATION, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_fils_ind = NULL;

    /* 70. AP-CSN */
    bo->bo_ap_csn = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_AP_CSN, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_ap_csn = NULL;

    /* 71. Differentiated Initial Link Setup */
    bo->bo_diff_init_lnk = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_DIFF_INIT_LNK_SETUP, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_diff_init_lnk = NULL;

    /* 72. Service Hint */
    bo->bo_service_hint = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_SERVICE_HINT, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_service_hint = NULL;

    /* 73. Service Hash */
    bo->bo_service_hash = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_SERVICE_HASH, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_service_hash = NULL;

    /*
     * HE capable:
     */
    if (ieee80211_vap_wme_is_set(vap) &&
        IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) && ieee80211vap_heallowed(vap)) {
        /* 76. HE Capabilities */
        bo->bo_hecap = frm;
        frm = ieee80211_add_hecap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON);

        /* 77. HE Operation */
        bo->bo_heop = frm;
        frm = ieee80211_add_heop(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON, NULL);
    } else {
        bo->bo_hecap = NULL;
        bo->bo_heop  = NULL;
    }

    /* 78. TWT */
    bo->bo_twt = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_TWT, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_twt = NULL;

    /* 79. UORA Parameter Set */
#if ATH_SUPPORT_UORA
    if(ieee80211_vap_wme_is_set(vap) &&
       ieee80211vap_heallowed(vap) &&
       IEEE80211_IS_CHAN_11AX(ic->ic_curchan) &&
       ieee80211vap_uora_is_enabled(vap)) {
        bo->bo_uora_param = frm;
        frm = ieee80211_add_uora_param(frm, vap->iv_ocw_range);
    } else {
        bo->bo_uora_param = NULL;
    }
#endif

    /* 80. BSS Color Change Announcement */
    bo->bo_bcca = frm;

#ifdef OBSS_PD
    /*
     * 81. Spatial Reuse Parameter Set
     * Check if OBSS PD service is enabled and add SRP IE in beacon
     * between BSS Color Change Announcement IE and MU EDCA IE as
     * per section 9.3.3.3 in 11ax draft 3.0
     */
    if(ic->ic_he_sr_enable &&
       IEEE80211_IS_CHAN_11AX(ic->ic_curchan) && ieee80211vap_heallowed(vap)) {
        bo->bo_srp_ie = frm;
        frm = ieee80211_add_srp_ie(ic, frm);
    }
#endif

    /* 82. MU EDCA Parameter Set */
    if(ieee80211_vap_wme_is_set(vap) &&
       ieee80211vap_heallowed(vap) &&
       ieee80211vap_muedca_is_enabled(vap)) {
        bo->bo_muedca = frm;
        frm = ieee80211_add_muedca_param(frm, &vap->iv_muedcastate);
    } else {
        bo->bo_muedca = NULL;
    }

    /* 83. ESS Report */
    bo->bo_ess_rpt = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_ESS_REPORT, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_ess_rpt = NULL;

    /* 84. NDP Feedback Report Parameter Set */
    bo->bo_ndp_rpt_param = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_NDP_FEEDBACK_REPORT_PARAM,
                &frm, TYPE_ALL_BUF, NULL, true))
        bo->bo_ndp_rpt_param = NULL;

    /* 85. HE BSS Load */
    bo->bo_he_bss_load = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_HE_BSS_LOAD,
                &frm, TYPE_ALL_BUF, NULL, true))
        bo->bo_he_bss_load = NULL;

    /* 87. HE 6GHz Band Capabilities */
    if (ieee80211_vap_wme_is_set(vap) && IEEE80211_IS_CHAN_11AX(vap->iv_bsschan)
            && ieee80211vap_heallowed(vap)
            && IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        bo->bo_he_6g_bandcap = frm;
        frm = ieee80211_add_6g_bandcap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON);
    } else {
        bo->bo_he_6g_bandcap = NULL;
    }

    /* Adding Max Channel Switch Time IE here since no order
     * is mentioned in the specification
     */
    bo->bo_mcst = frm;

    /* Secondary channel offset
     * Added here since no order
     * is mentioned in the specification
     */
    bo->bo_secchanoffset = frm;

    /* Adding RSNX IE here since no order is mentioned in the
     * specification
     */
    bo->bo_rsnx = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_RSNX, -1, &frm,
                TYPE_ALL_BUF, NULL, true))
        bo->bo_rsnx = NULL;

#if ATH_SUPPORT_WAPI
    /* WAPI IE, if supported
     * Added here since no order
     * is mentioned in the specification
     */
#ifdef WLAN_CONV_CRYPTO_SUPPORTED
    if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj, (1 << WLAN_CRYPTO_AUTH_WAPI)))
#else
    if (RSN_AUTH_IS_WAI(rsn))
#endif
    {
        frm = ieee80211_setup_wapi_ie(vap, frm);
        if (!frm)
            return NULL;
    }
#endif

    /* ------------- LAST. Vendor IEs ------------- */
    /* Ath Advertisement capabilities */
    bo->bo_ath_caps = frm;
    if (vap->iv_ena_vendor_ie == 1) {
        if (vap->iv_bss && vap->iv_bss->ni_ath_flags) {
            frm = ieee80211_add_athAdvCap(frm, vap->iv_bss->ni_ath_flags,
                    vap->iv_bss->ni_ath_defkeyindex);
        } else {
            frm = ieee80211_add_athAdvCap(frm, 0, IEEE80211_INVAL_DEFKEY);
        }
        vap->iv_update_vendor_ie = 0;
    }

    /* Ath Extended Capabilities */
    if (ic->ic_ath_extcap) {
        frm = ieee80211_add_athextcap(frm,
                ic->ic_ath_extcap, ic->ic_weptkipaggr_rxdelim);
    }

#if DBDC_REPEATER_SUPPORT
    /* Extender */
    if (ic_list->same_ssid_support) {
        bo->bo_extender_ie = frm;
        frm = ieee80211_add_extender_ie(vap, IEEE80211_FRAME_TYPE_BEACON, frm);
    }
#endif

    /* HT Cap and HT Info/Operation Vendor IEs */
    if ((!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
        (IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) ||
         IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
         IEEE80211_IS_CHAN_11N(vap->iv_bsschan)) &&
            IEEE80211_IS_HTVIE_ENABLED(ic) && enable_htrates) {
        frm = ieee80211_add_htcap_vendor_specific(frm, ni, IEEE80211_FC0_SUBTYPE_BEACON);

        bo->bo_htinfo_vendor_specific = frm;
        frm = ieee80211_add_htinfo_vendor_specific(frm, ni);
    } else {
        bo->bo_htinfo_vendor_specific = NULL;
    }

    /* MBO */
    if (ieee80211_vap_mbo_check(vap) || ieee80211_vap_oce_check(vap)) {
        bo->bo_mbo_cap = frm;
        frm = ieee80211_setup_mbo_ie(IEEE80211_FC0_SUBTYPE_BEACON, vap, frm, ni);
    } else {
        bo->bo_mbo_cap = NULL;
    }

    /* Next Channel */
    if(IEEE80211_IS_CSH_OPT_APRIORI_NEXT_CHANNEL_ENABLED(ic)
            && IEEE80211_IS_CHAN_DFS(ic->ic_curchan) && ic->ic_tx_next_ch)
    {
        bo->bo_apriori_next_channel = frm;
        frm = ieee80211_add_next_channel(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON);
    } else {
        bo->bo_apriori_next_channel = NULL;
    }

    /* Prop NSS Map IE if EXT NSS is not supported */
    if (!(vap->iv_ext_nss_support) &&
            !(ic->ic_disable_bcn_bwnss_map) &&
            !(ic->ic_disable_bwnss_adv) &&
            !ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask)) {
        bo->bo_bwnss_map = frm;
        frm = ieee80211_add_bw_nss_maping(frm, &nssmap);
    } else {
        bo->bo_bwnss_map = NULL;
    }

#if QCN_IE
    /* QCN IE for the feature set */
    bo->bo_qcn_ie = frm;
    frm = ieee80211_add_qcn_info_ie(frm, vap, &bo->bo_qcn_ie_len,
                                    QCN_MAC_PHY_PARAM_IE_TYPE, NULL);
#endif

    /* SON mode IE which requires WDS as a prereq */
    bo->bo_xr = frm;
    if (IEEE80211_VAP_IS_WDS_ENABLED(vap) &&
            !son_vdev_map_capability_get(vap->vdev_obj, SON_MAP_CAPABILITY)) {
        u_int16_t whcCaps = QCA_OUI_WHC_AP_INFO_CAP_WDS;

        bo->bo_whc_apinfo = frm;
        if (son_vdev_feat_capablity(vap->vdev_obj, SON_CAP_GET, WLAN_VDEV_F_SON)) {
            whcCaps |= QCA_OUI_WHC_AP_INFO_CAP_SON;
        }
        frm = son_add_ap_info_ie(frm, whcCaps, vap->vdev_obj, &bo->bo_whc_apinfo_len);
    }

    /* VHT Vendor IE for 256QAM support in 2.4G Interop */
    if ((ieee80211_vap_wme_is_set(vap) &&
         (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
         IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)) &&
            ieee80211vap_vhtallowed(vap) &&
              ieee80211vap_11ng_vht_interopallowed(vap)) {
        /* Add VHT capabilities IE and VHT OP IE in Vendor specific IE*/
        bo->bo_interop_vhtcap = frm;
        frm = ieee80211_add_interop_vhtcap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON);
    } else {
        bo->bo_interop_vhtcap = NULL;
    }

    /* WME param */
    if (ieee80211_vap_wme_is_set(vap) &&
        (vap->iv_opmode == IEEE80211_M_HOSTAP ||
#if ATH_SUPPORT_IBSS_WMM
         vap->iv_opmode == IEEE80211_M_IBSS ||
#endif
         vap->iv_opmode == IEEE80211_M_BTAMP)) {

        bo->bo_wme = frm;
        frm = ieee80211_add_wme_param(frm, &vap->iv_wmestate, IEEE80211_VAP_IS_UAPSD_ENABLED(vap));
        ieee80211vap_clear_flag(vap, IEEE80211_F_WMEUPDATE);
    } else {
        bo->bo_wme = NULL;
    }

    /* WPA
     * Check if os shim has setup WPA IE itself
     */
    if (!vap->iv_rsn_override) {
        IEEE80211_VAP_LOCK(vap);
        len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON,IEEE80211_ELEMID_VENDOR, 1, &frm,
                TYPE_ALL_BUF, NULL, true);
        if (len) {
            /* Remove WPA from frame so that it will be added
             * when other vendor IEs are added
             */
            frm -= len;
            qdf_mem_zero(frm, len);
        } else {

            /* Adding WPA IE if not present in buffers*/
#ifdef WLAN_CONV_CRYPTO_SUPPORTED
            if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj,
                        (1 << WLAN_CRYPTO_AUTH_WPA))) {
                frm = wlan_crypto_build_wpaie(vap->vdev_obj, frm);
                if(!frm) {
                    IEEE80211_VAP_UNLOCK(vap);
                    return NULL;
                }
            }
#else
            if (RSN_AUTH_IS_WPA(rsn))
                frm = ieee80211_setup_wpa_ie(vap, frm);
#endif
        }
        IEEE80211_VAP_UNLOCK(vap);
    }

    /* Software and Hardware version */
    bo->bo_software_version_ie = frm;
    frm = ieee80211_add_sw_version_ie(frm, ic);

    bo->bo_generic_vendor_capabilities = frm;
    frm = ieee80211_add_generic_vendor_capabilities_ie(frm, ic);
    if (!frm)
        return NULL;

    /* ------------- LAST. App IE Buffer or list, and Optional IEs ------------- */
    bo->bo_appie_buf = frm;
    bo->bo_appie_buf_len = 0;

    IEEE80211_VAP_LOCK(vap);
    len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
            IEEE80211_ELEMID_VENDOR, 0, &frm, TYPE_ALL_BUF, NULL, false);
    IEEE80211_VAP_UNLOCK(vap);
    bo->bo_appie_buf_len = len;

    bo->bo_tim_trailerlen = frm - bo->bo_tim_trailer;
    bo->bo_chanswitch_trailerlen = frm - bo->bo_chanswitch;
    bo->bo_ecsa_trailerlen = frm - bo->bo_ecsa;
    bo->bo_mcst_trailerlen = frm - bo->bo_mcst;
    bo->bo_vhtchnsw_trailerlen = frm - bo->bo_vhtchnsw;
    bo->bo_secchanoffset_trailerlen = frm - bo->bo_secchanoffset;
    bo->bo_bcca_trailerlen          = frm - bo->bo_bcca;
#if ATH_SUPPORT_IBSS_DFS
    if (vap->iv_opmode == IEEE80211_M_IBSS &&
        (bo->bo_ibssdfs != NULL)) {
        struct ieee80211_ibssdfs_ie * ibss_dfs_ie = (struct ieee80211_ibssdfs_ie *)bo->bo_ibssdfs;
        bo->bo_ibssdfs_trailerlen = frm - (bo->bo_ibssdfs + 2 + ibss_dfs_ie->len);
    } else {
        bo->bo_ibssdfs_trailerlen = 0;
    }
#endif /* ATH_SUPPORT_IBSS_DFS */
#if UMAC_SUPPORT_WNM
    bo->bo_fms_trailerlen = frm - bo->bo_fms_trailer;
#endif /* UMAC_SUPPORT_WNM */
    return frm;
}

/*
 * Make a copy of the Beacon Frame store for this VAP. NOTE: this copy is not the
 * most recent and is only updated when certain information (listed below) changes.
 *
 * The frame includes the beacon frame header and all the IEs, does not include the 802.11
 * MAC header. Beacon frame format is defined in ISO/IEC 8802-11. The beacon frame
 * should be the up-to-date one used by the driver except that real-time parameters or
 * information elements that vary with data frame flow control or client association status,
 * such as timestamp, radio parameters, TIM, ERP and HT information elements do not
 * need to be accurate.
 *
 */
static void
store_beacon_frame(struct ieee80211vap *vap, u_int8_t *wh, int frame_len)
{

    if (ieee80211_vap_copy_beacon_is_clear(vap)) {
        ASSERT(0);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                "ieee80211_vap_copy_beacon_is_clear is true\n");
        return;
    }

    if (vap->iv_beacon_copy_buf == NULL) {
        /* The beacon copy buffer is not allocated yet. */

        vap->iv_beacon_copy_buf = OS_MALLOC(vap->iv_ic->ic_osdev, IEEE80211_RTS_MAX, GFP_KERNEL);
        if (vap->iv_beacon_copy_buf == NULL) {
            /* Unable to allocate the memory */
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: Unable to alloc beacon copy buf. Size=%d\n",
                              __func__, IEEE80211_RTS_MAX);
            return;
        }
    }

    ASSERT(frame_len <= IEEE80211_RTS_MAX);
    OS_MEMCPY(vap->iv_beacon_copy_buf, wh, frame_len);
    vap->iv_beacon_copy_len = frame_len;
#if UMAC_SUPPORT_P2P
/*
 *  XXX: When P2P connect, the wireless connection icon will be changed to Red-X,
 *       while the connection is OK.
 *       It is because of the query of OID_DOT11_ENUM_BSS_LIST.
 *       By putting AP(GO)'s own beacon information into the scan table,
 *       that problem can be solved.
 */
    ieee80211_scan_table_update(vap,
                                (struct ieee80211_frame*)wh,
                                frame_len,
                                IEEE80211_FC0_SUBTYPE_BEACON,
                                0,
                                ieee80211_get_current_channel(vap->iv_ic));
#endif
}

wbuf_t ieee80211_prb_rsp_alloc_init(struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211vap *vap, *tx_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *orig_vap;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    u_int8_t *frm;
    u_int16_t capinfo;
    bool add_wpa_ie = true;
    struct ieee80211_bwnss_map nssmap;
    u_int8_t rx_chainmask;
    struct ieee80211_node *non_transmit_ni = NULL;

#ifndef WLAN_CONV_CRYPTO_SUPPORTED
    struct ieee80211_rsnparms *rsn;
#endif
#if QCN_IE
    u_int16_t ie_len;
#endif
#if DBDC_REPEATER_SUPPORT
    struct global_ic_list *ic_list;
#endif
#if QCN_ESP_IE
    u_int16_t esp_ie_len;
#endif
    struct ol_ath_vap_net80211 *avn = NULL;
    bool is_buffer_preallocated;
    bool is_mbssid_enabled;

    qdf_mem_zero(&nssmap, sizeof(nssmap));
    if (!ic) {
        qdf_err("Ic is NULL");
        return NULL;
    }

    is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                        WLAN_PDEV_F_MBSS_IE_ENABLE);

    vap = ni->ni_vap;

    if(!vap) {
        qdf_err("Vap is NULL");
	return NULL;
    }
    if (is_mbssid_enabled) {
        tx_vap = ic->ic_mbss.transmit_vap;
    }
    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) || (!is_mbssid_enabled &&
        !vap->iv_he_6g_bcast_prob_rsp) || (is_mbssid_enabled &&
        !tx_vap->iv_he_6g_bcast_prob_rsp)) {
        qdf_debug("20 Tu Prb resp not applicable");
        return NULL;
    }

#ifndef WLAN_CONV_CRYPTO_SUPPORTED
    rsn = &vap->iv_rsn;
#endif
#if DBDC_REPEATER_SUPPORT
    ic_list = ic->ic_global_list;
#endif
    rx_chainmask = ieee80211com_get_rx_chainmask(ic);

    orig_vap = ni->ni_vap;
    if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
        /* We operate on tx vap's beacon buffer */
        vap = ic->ic_mbss.transmit_vap;
        non_transmit_ni = ni;
        ni = vap->iv_bss;
    }
    avn = OL_ATH_VAP_NET80211(vap);
    if(!avn) {
        return NULL;
    } else if (avn->av_pr_rsp_wbuf) {
        /* Skip buffer alloc if Probe response buffer is already allocated */
        wbuf = avn->av_pr_rsp_wbuf;
        is_buffer_preallocated = true;
    } else {
        if (ic && ic->ic_osdev) {
            wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
            is_buffer_preallocated = false;
        } else {
            return NULL;
        }
    }

    if (wbuf == NULL)
        return NULL;

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT |
        IEEE80211_FC0_SUBTYPE_PROBE_RESP;
    wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
    *(u_int16_t *)wh->i_dur = 0;
    if(ic->ic_softap_enable){
        IEEE80211_ADDR_COPY(ni->ni_bssid, vap->iv_myaddr);
    }
    IEEE80211_ADDR_COPY(wh->i_addr1, IEEE80211_GET_BCAST_ADDR(ic));
    IEEE80211_ADDR_COPY(wh->i_addr2, vap->iv_myaddr);
    IEEE80211_ADDR_COPY(wh->i_addr3, ni->ni_bssid);
    *(u_int16_t *)wh->i_seq = 0;

    frm = (u_int8_t *)&wh[1];
    /*
     * probe response frame format
     *  [8] time stamp
     *  [2] beacon interval
     *  [2] cabability information
     *  [tlv] ssid
     *  [tlv] supported rates
     *  [tlv] parameter set (FH/DS)
     *  [tlv] parameter set (QUIET)
     *  [tlv] parameter set (IBSS)
     *  [tlv] extended rate phy (ERP)
     *  [tlv] extended supported rates
     *  [tlv] country (if present)
     *  [3] power constraint
     *  [tlv] WPA
     *  [tlv] WME
     *  [tlv] HT Capabilities
     *  [tlv] HT Information
     *      [tlv] Atheros Advanced Capabilities
     */
    OS_MEMZERO(frm, 8);  /* timestamp should be filled later */
    frm += 8;
    *(u_int16_t *)frm = htole16(vap->iv_bss->ni_intval);
    frm += 2;
    if (vap->iv_opmode == IEEE80211_M_IBSS){
        if(ic->ic_softap_enable)
            capinfo = IEEE80211_CAPINFO_ESS;
        else
            capinfo = IEEE80211_CAPINFO_IBSS;
     }
    else
        capinfo = IEEE80211_CAPINFO_ESS;
    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap))
        capinfo |= IEEE80211_CAPINFO_PRIVACY;
    if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
        IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan))
        capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
    if (ic->ic_flags & IEEE80211_F_SHSLOT)
        capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap))
        capinfo |= IEEE80211_CAPINFO_SPECTRUM_MGMT;
    if (ieee80211_vap_rrm_is_set(vap)) {
        capinfo |= IEEE80211_CAPINFO_RADIOMEAS;
    }
    *(u_int16_t *)frm = htole16(capinfo);
    bo->bo_caps = (u_int16_t *)frm;
    frm += 2;

    /* SSID IE */
    frm = ieee80211_add_ssid(frm, vap->iv_bss->ni_essid,
                             vap->iv_bss->ni_esslen);
    /* Supported Rates IE */
    bo->bo_rates = frm;
    frm = ieee80211_add_rates(frm, &vap->iv_bss->ni_rates);

    /* IBSS Parameter IE */
    if (vap->iv_opmode == IEEE80211_M_IBSS) {
        *frm++ = IEEE80211_ELEMID_IBSSPARMS;
        *frm++ = 2;
        *frm++ = 0; *frm++ = 0;     /* TODO: ATIM window */
    }

    /* Country IE */
    if (IEEE80211_IS_COUNTRYIE_ENABLED(ic) && ieee80211_vap_country_ie_is_set(vap)) {
        frm = ieee80211_add_country(frm, vap);
    }

    /* Power Constraint IE */
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
        bo->bo_pwrcnstr = frm;
        *frm++ = IEEE80211_ELEMID_PWRCNSTR;
        *frm++ = 1;
        *frm++ = IEEE80211_PWRCONSTRAINT_VAL(vap);
    } else {
        bo->bo_pwrcnstr = 0;
    }

    /* Quiet IE */
    frm = ieee80211_add_quiet(vap, ic, frm);

    /* TPC Report IE :
     * Add the TPC Report IE in the probe response if 802.11h or RRM capability
     * is set.
     */
    if ((ieee80211_ic_doth_is_set(ic) &&
         ieee80211_vap_doth_is_set(vap)) ||
         ieee80211_vap_rrm_is_set(vap)) {
        bo->bo_tpcreport = frm;
        frm = ieee80211_add_tpc_ie(frm, vap);
    } else {
        bo->bo_tpcreport = NULL;
    }

    /* ERP IE */
    if (IEEE80211_IS_CHAN_ANYG(ic->ic_curchan) ||
        IEEE80211_IS_CHAN_11NG(ic->ic_curchan) ||
        IEEE80211_IS_CHAN_11AXG(ic->ic_curchan)) {
        bo->bo_erp = frm;
        frm = ieee80211_add_erp(frm, ic);
    } else {
        bo->bo_erp = NULL;
    }

#if ATH_SUPPORT_WAPI
#ifdef WLAN_CONV_CRYPTO_SUPPORTED
    if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj, (1 << WLAN_CRYPTO_AUTH_WAPI)))
#else
    if (RSN_AUTH_IS_WAI(rsn))
#endif
    {
        frm = ieee80211_setup_wapi_ie(vap, frm);
        if (!frm) {
            wbuf_release(ic->ic_osdev, wbuf);
            return NULL;
        }
    }
#endif

    /* Extended Rates IE */
    frm = ieee80211_add_xrates(vap, frm, &vap->iv_bss->ni_rates);

    /* BSS Load IE */
    frm = ieee80211_add_qbssload(frm, ni);

    /* Add MBSS IE */
    if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE)) {
        frm = ieee80211_add_mbss_ie(&avn->av_prb_rsp_offsets, frm,
                                (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(orig_vap)) ?
                                non_transmit_ni: ni, IEEE80211_FRAME_TYPE_PROBERESP);
        if (!frm)
            return NULL;
    }

    /* Add rrm capbabilities, if supported */
    frm = ieee80211_add_rrm_cap_ie(frm, ni);

    /* Add extended capbabilities, if applicable */
    bo->bo_extcap = frm;
    frm = ieee80211_add_extcap(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);

    if (ieee80211_vap_wme_is_set(vap) &&  IEEE80211_IS_CHAN_11AX(ic->ic_curchan)
         && ieee80211vap_heallowed(vap)) {
        /* Add HE Capabilities IE */
        bo->bo_hecap = frm;
        frm = ieee80211_add_hecap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP);

        /* Add HE Operation IE */
        bo->bo_heop = frm;
        frm = ieee80211_add_heop(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP, NULL);
        if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        /* Add HE 6GHz Band Capabilities IE */
            bo->bo_he_6g_bandcap = frm;
            frm = ieee80211_add_6g_bandcap(frm, ni, ic,
                        IEEE80211_FC0_SUBTYPE_PROBE_RESP);
        }
    } else {
        bo->bo_hecap = NULL;
        bo->bo_heop  = NULL;
    }


    if (add_wpa_ie && !vap->iv_rsn_override) {
#ifdef WLAN_CONV_CRYPTO_SUPPORTED
        if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj, (1 << WLAN_CRYPTO_AUTH_WPA))) {
            frm = wlan_crypto_build_wpaie(vap->vdev_obj, frm);
            if (!frm) {
                wbuf_release(ic->ic_osdev, wbuf);
                return NULL;
            }
        }
#else
        if (RSN_AUTH_IS_WPA(rsn))
            frm = ieee80211_setup_wpa_ie(vap, frm);
#endif
    }

#if OBSS_PD
    if (ic->ic_he_sr_enable &&
        IEEE80211_IS_CHAN_11AX(ic->ic_curchan) && ieee80211vap_heallowed(vap)) {
        bo->bo_srp_ie = frm;
        frm = ieee80211_add_srp_ie(ic, frm);
    }
#endif

    /* Add MU EDCA parameter element */
    if(ieee80211_vap_wme_is_set(vap) &&
            ieee80211vap_heallowed(vap) &&
            IEEE80211_IS_CHAN_11AX(ic->ic_curchan) &&
            ieee80211vap_muedca_is_enabled(vap)) {
        bo->bo_muedca = frm;
        frm = ieee80211_add_muedca_param(frm, &vap->iv_muedcastate);
    }

    if (ieee80211_vap_wme_is_set(vap) &&
        (vap->iv_opmode == IEEE80211_M_HOSTAP || vap->iv_opmode == IEEE80211_M_BTAMP)) {/* don't support WMM in ad-hoc for now */
        bo->bo_wme = frm;
        frm = ieee80211_add_wme_param(frm, &vap->iv_wmestate, IEEE80211_VAP_IS_UAPSD_ENABLED(vap));
    } else {
        bo->bo_wme = NULL;
    }
    if (vap->iv_ena_vendor_ie == 1) {
        if (vap->iv_bss->ni_ath_flags) {
            frm = ieee80211_add_athAdvCap(frm, vap->iv_bss->ni_ath_flags,
                                            vap->iv_bss->ni_ath_defkeyindex);
        } else {
            frm = ieee80211_add_athAdvCap(frm, 0, IEEE80211_INVAL_DEFKEY);
        }
    }
    /* Insert ieee80211_ie_ath_extcap IE to beacon */
    if (ic->ic_ath_extcap)
        frm = ieee80211_add_athextcap(frm, ic->ic_ath_extcap, ic->ic_weptkipaggr_rxdelim);

    if (!(vap->iv_ext_nss_support) && !(ic->ic_disable_bwnss_adv) && !ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask))  {
        frm = ieee80211_add_bw_nss_maping(frm, &nssmap);
    }


    IEEE80211_VAP_LOCK(vap);
    if (vap->iv_opt_ie.length) {
        OS_MEMCPY(frm, vap->iv_opt_ie.ie,
                  vap->iv_opt_ie.length);
        frm += vap->iv_opt_ie.length;
    }

    /* Add hardware & software version in probe response */
    frm = ieee80211_add_sw_version_ie(frm, ic);

    /* Add the Application IE's */
    frm = ieee80211_mlme_app_ie_append(vap, IEEE80211_FRAME_TYPE_PROBERESP, frm);
    IEEE80211_VAP_UNLOCK(vap);

    if (IEEE80211_VAP_IS_WDS_ENABLED(vap) &&
            !son_vdev_map_capability_get(vap->vdev_obj, SON_MAP_CAPABILITY)) {
        u_int16_t whcCaps = QCA_OUI_WHC_AP_INFO_CAP_WDS;
        u_int16_t ie_len;

        /* SON mode requires WDS as a prereq */
        if (son_vdev_feat_capablity(vap->vdev_obj,
                                    SON_CAP_GET,
                                    WLAN_VDEV_F_SON)) {
            whcCaps |= QCA_OUI_WHC_AP_INFO_CAP_SON;
        }

        frm = son_add_ap_info_ie(frm, whcCaps, vap->vdev_obj, &ie_len);
    }
#if QCN_IE
    /*Add QCN IE for the feature set*/
    frm = ieee80211_add_qcn_info_ie(frm, vap, &ie_len,
                                    QCN_MAC_PHY_PARAM_IE_TYPE, NULL);
#endif
#if QCN_ESP_IE
    if (ic->ic_esp_periodicity){
        frm = ieee80211_add_esp_info_ie(frm, ic, &esp_ie_len);
    }
#endif

    if (vap->ap_chan_rpt_enable) {
        bo->bo_ap_chan_rpt = frm;
        frm = ieee80211_add_ap_chan_rpt_ie (frm, vap);
    } else {
        bo->bo_ap_chan_rpt = NULL;
    }

    if (vap->rnr_enable) {
        bo->bo_rnr = frm;
        frm = ieee80211_add_rnr_ie(frm, vap, vap->iv_bss->ni_essid, vap->iv_bss->ni_esslen);
    } else {
        bo->bo_rnr = NULL;
    }

    if (ieee80211_vap_mbo_check(vap) || ieee80211_vap_oce_check(vap)) {
        bo->bo_mbo_cap = frm;
        frm = ieee80211_setup_mbo_ie(IEEE80211_FC0_SUBTYPE_PROBE_RESP, vap, frm, ni);
    } else {
        bo->bo_mbo_cap = NULL;
    }

#if DBDC_REPEATER_SUPPORT
    if (ic_list->same_ssid_support) {
        /* Add the Extender IE */
        bo->bo_extender_ie = frm;
        frm = ieee80211_add_extender_ie(vap, IEEE80211_FRAME_TYPE_PROBERESP, frm);
    } else {
        bo->bo_extender_ie = NULL;
    }
#endif
    if (!frm) {
        wbuf_release(ic->ic_osdev, wbuf);
        return NULL;
    }

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));

    /* If wbuf's peer desc is already set to ni, then below is skipped.
     * If it is not set, then inc ref count and call wlan_wbuf_set_peer_node,
     * this happens first time wbuf is created and ni is set. On succesive
     * calls to ieee80211_prb_rsp_alloc_init, incrementing ref count can be
     * skipped as wlan_wbuf_set_peer_node is already set.
     */
    if (!is_buffer_preallocated) {
        ni = ieee80211_try_ref_node(ni, WLAN_MGMT_TX_ID);
        if (!ni) {
            wbuf_release(ic->ic_osdev, wbuf);
            return NULL;
        } else {
            wlan_wbuf_set_peer_node(wbuf, ni);
        }
    }

    return wbuf;

}

/*
 * Allocate a beacon frame and fillin the appropriate bits.
 */

wbuf_t
ieee80211_beacon_alloc(struct ieee80211_node *ni,
                       struct ieee80211_beacon_offsets *bo)
{
    wbuf_t wbuf;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_frame *wh;
    u_int8_t *frm;

    /* 
     * For non-tx MBSS VAP, we reinitialize the beacon buffer of tx VAP
     * and return.
     */
    if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
       struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(ic->ic_mbss.transmit_vap);

       vap->iv_mbss.mbssid_add_del_profile = 1;
       ic->ic_vdev_beacon_template_update(vap);
       return avn->av_wbuf;
    }

    if (ic && ic->ic_osdev) {
        wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_BEACON, MAX_TX_RX_PACKET_SIZE);
    } else {
        return NULL;
    }

    if (wbuf == NULL)
        return NULL;

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT |
        IEEE80211_FC0_SUBTYPE_BEACON;
    wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
    *(u_int16_t *)wh->i_dur = 0;
    if(ic->ic_softap_enable){
        IEEE80211_ADDR_COPY(ni->ni_bssid, vap->iv_myaddr);
    }
    IEEE80211_ADDR_COPY(wh->i_addr1, IEEE80211_GET_BCAST_ADDR(ic));
    IEEE80211_ADDR_COPY(wh->i_addr2, vap->iv_myaddr);
    IEEE80211_ADDR_COPY(wh->i_addr3, ni->ni_bssid);
    *(u_int16_t *)wh->i_seq = 0;

    frm = (u_int8_t *)&wh[1];

    OS_MEMZERO(frm, IEEE80211_TSF_LEN); /* Clear TSF field */
    frm = ieee80211_beacon_init(ni, bo, frm);
    if (!frm) {
        wbuf_release(ic->ic_osdev, wbuf);
        return NULL;
    }

    if (ieee80211_vap_copy_beacon_is_set(vap)) {
        store_beacon_frame(vap, (u_int8_t *)wh, (frm - (u_int8_t *)wh));
    }

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t *) wbuf_header(wbuf)));

    ni = ieee80211_try_ref_node(ni, WLAN_MGMT_TX_ID);
    if (!ni) {
        wbuf_release(ic->ic_osdev, wbuf);
        return NULL;
    } else {
        wlan_wbuf_set_peer_node(wbuf, ni);
    }

    IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_MLME, vap->iv_myaddr,
                       "%s \n", __func__);
    return wbuf;
}


/*
 * Suspend or Resume the transmission of beacon for this SoftAP VAP.
 * @param vap           : vap pointer.
 * @param en_suspend    : boolean flag to enable or disable suspension.
 * @ returns 0 if success, others if failed.
 */
int
ieee80211_mlme_set_beacon_suspend_state(
    struct ieee80211vap *vap,
    bool en_suspend)
{
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    struct ieee80211com *ic = vap->iv_ic;
    int ret = 0;

    ASSERT(mlme_priv != NULL);
    if (en_suspend) {
        mlme_priv->im_beacon_tx_suspend++;
        /* Send beacon control command to disable beacon tx */
        if (ic->ic_beacon_offload_control) {
            ret = ic->ic_beacon_offload_control(vap, IEEE80211_BCN_OFFLD_TX_DISABLE);
        }
    }
    else {
        mlme_priv->im_beacon_tx_suspend--;
        /* Send beacon control command to enable beacon tx */
        if (ic->ic_beacon_offload_control) {
            ret = ic->ic_beacon_offload_control(vap, IEEE80211_BCN_OFFLD_TX_ENABLE);
        }
    }

    if (ret) {
        qdf_print("Failed to send beacon offload control message");
    }

    return ret;
}

bool
ieee80211_mlme_beacon_suspend_state(
    struct ieee80211vap *vap)
{
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;

    ASSERT(mlme_priv != NULL);
    return (mlme_priv->im_beacon_tx_suspend != 0);
}

#if DYNAMIC_BEACON_SUPPORT
void ieee80211_mlme_set_dynamic_beacon_suspend(struct ieee80211vap *vap, bool suspend_beacon)
{
    if (vap->iv_dbeacon_runtime != suspend_beacon) {
        wlan_deauth_all_stas(vap); /* dissociating all associated stations */
    }
    if (!suspend_beacon ) { /* DFS channels */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "Resume beacon \n");
        qdf_spin_lock_bh(&vap->iv_dbeacon_lock);
        OS_CANCEL_TIMER(&vap->iv_dbeacon_suspend_beacon);
        if (ieee80211_mlme_beacon_suspend_state(vap)) {
            ieee80211_mlme_set_beacon_suspend_state(vap, false);
        }
        vap->iv_dbeacon_runtime = suspend_beacon;
        qdf_spin_unlock_bh(&vap->iv_dbeacon_lock);
    } else { /* non DFS channels */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "Suspend beacon \n");
        qdf_spin_lock_bh(&vap->iv_dbeacon_lock);
        if (!ieee80211_mlme_beacon_suspend_state(vap)) {
            ieee80211_mlme_set_beacon_suspend_state(vap, true);
        }
        vap->iv_dbeacon_runtime = suspend_beacon;
        qdf_spin_unlock_bh(&vap->iv_dbeacon_lock);
    }
}
qdf_export_symbol(ieee80211_mlme_set_dynamic_beacon_suspend);
#endif

int
ieee80211_bcn_prb_template_update(struct ieee80211_node *ni,
                                   struct ieee80211_bcn_prb_info *templ)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;

    /* If Beacon Tx is suspended, then don't send this beacon */
    if (ieee80211_mlme_beacon_suspend_state(vap)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
            "%s: skip Tx beacon during to suspend.\n", __func__);
        return -1;
    }
#if UMAC_SUPPORT_VAP_PAUSE
    /* if vap is paused do not send any beacons */
    if (ieee80211_vap_is_paused(vap)) {
        return -1;
    }
#endif
    /* Update capabilities bit */
    if (vap->iv_opmode == IEEE80211_M_IBSS)
        templ->caps = IEEE80211_CAPINFO_IBSS;
    else
        templ->caps = IEEE80211_CAPINFO_ESS;
    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap))
        templ->caps |= IEEE80211_CAPINFO_PRIVACY;
    if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
        IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan))
        templ->caps |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
    if (ic->ic_flags & IEEE80211_F_SHSLOT)
        templ->caps |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap))
        templ->caps |= IEEE80211_CAPINFO_SPECTRUM_MGMT;

    if (IEEE80211_VAP_IS_PUREB_ENABLED(vap)){
        templ->caps &= ~IEEE80211_CAPINFO_SHORT_SLOTTIME;
    }
    /* set rrm capbabilities, if supported */
    if (ieee80211_vap_rrm_is_set(vap)) {
        templ->caps |= IEEE80211_CAPINFO_RADIOMEAS;
    }

    /* Update ERP Info */
    if (vap->iv_opmode == IEEE80211_M_HOSTAP ||
        vap->iv_opmode == IEEE80211_M_BTAMP) { /* No IBSS Support */
        if (ieee80211_vap_erpupdate_is_set(vap)) {
            if (ic->ic_nonerpsta != 0 )
                templ->erp |= IEEE80211_ERP_NON_ERP_PRESENT;
            if (ic->ic_flags & IEEE80211_F_USEPROT)
                templ->erp |= IEEE80211_ERP_USE_PROTECTION;
            if (ic->ic_flags & IEEE80211_F_USEBARKER)
                templ->erp |= IEEE80211_ERP_LONG_PREAMBLE;
        }
    }

    /* TBD:
     * There are some more elements to be passed from the host
     * HT caps, HT info, Advanced caps, IBSS DFS, WPA, RSN, RRM
     * APP IEs
     */
    return 0;
}

static void ieee80211_disconnect_sta_vap(struct ieee80211com *ic,
        struct ieee80211vap *stavap)
{
    struct wlan_objmgr_pdev *pdev = NULL;
    QDF_STATUS status;
    int val=0;

    wlan_mlme_sm_get_curstate(stavap, IEEE80211_PARAM_CONNECTION_SM_STATE,
            &val);
    if(val == WLAN_ASSOC_STATE_TXCHANSWITCH) {
        /* If Channel change is initiated by STAVAP then do not indicate mlme
         * sta radar detect (in other words do not disconnect the STA) since
         * STA VAP is trying to come up in a different channel and is doing the
         * Channel Switch, STA is yet to do CAC+ send probe req+ AUTH to the
         * Root AP.
         */
    } else {
        if (!(ic->ic_repeater_move.state == REPEATER_MOVE_START)) {
            pdev = ic->ic_pdev_obj;
            status = wlan_objmgr_pdev_try_get_ref(pdev, WLAN_OSIF_SCAN_ID);
            if (QDF_IS_STATUS_ERROR(status)) {
                scan_info("unable to get reference");
            } else {
                ucfg_scan_flush_results(pdev, NULL);
                wlan_objmgr_pdev_release_ref(pdev, WLAN_OSIF_SCAN_ID);
            }

            /* Disconnect the main sta vap form RootAP, so that in Dependent mode
             * AP vap(s) automatically goes down. Main sta vap scans and connects
             * to the RootAP in the new channel.
             */
            ieee80211_indicate_sta_radar_detect(stavap->iv_bss);
        }
    }
}

void ieee80211_send_chanswitch_complete_event(
        struct ieee80211com *ic)
{
    struct ieee80211vap *stavap;

    STA_VAP_DOWNUP_LOCK(ic);
    stavap = ic->ic_sta_vap;
    if(stavap) {
        /* Only for main STA send the chanswitch complete event */
        int val=0;

        wlan_mlme_sm_get_curstate(stavap, IEEE80211_PARAM_CONNECTION_SM_STATE,
                &val);
        if(val == WLAN_ASSOC_STATE_TXCHANSWITCH) {
            IEEE80211_DELIVER_EVENT_MLME_TXCHANSWITCH_COMPLETE(stavap,
                    IEEE80211_STATUS_SUCCESS);
        }
    }
    STA_VAP_DOWNUP_UNLOCK(ic);
}

static void ieee80211_beacon_change_channel(
        struct ieee80211vap *vap,
        struct ieee80211_ath_channel *c)
{
    struct ieee80211com *ic = vap->iv_ic;
    enum ieee80211_cwm_width ic_cw_width;
    enum ieee80211_cwm_width ic_cw_width_prev = ic->ic_cwm_get_width(ic);
    struct ieee80211vap *tmp_vap = NULL;
    struct ieee80211vap *transmit_vap = NULL;

    if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                WLAN_PDEV_F_MBSS_IE_ENABLE)) {
        transmit_vap = ic->ic_mbss.transmit_vap;
    }

    ic_cw_width = ic->ic_cwm_get_width(ic);

    TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
        if(tmp_vap->iv_opmode == IEEE80211_M_HOSTAP ||
                tmp_vap->iv_opmode == IEEE80211_M_STA  ||
                tmp_vap->iv_opmode == IEEE80211_M_MONITOR) {

            tmp_vap->iv_bsschan = c;
            tmp_vap->iv_des_chan[tmp_vap->iv_des_mode] = c;
            tmp_vap->iv_cur_mode = ieee80211_chan2mode(c);
            tmp_vap->iv_chanchange_count = 0;
            ieee80211vap_clear_flag(tmp_vap, IEEE80211_F_CHANSWITCH);

            /* When MBSSIE FR is enabled, set iv_remove_csa_ie flag only for
             * transmitting vap. Based on this flag beacon template is sent to
             * FW in CSA event handler. Do not set iv_remove_csa_ie flag for
             * non-transmitting vaps, as Host does not send CSA template to FW
             * for these vaps.
             * When MBSSIE FR is disabled, host sends CSA template for all the
             * vaps to FW. Therefore set iv_remove_csa_ie for all the vaps. In
             * this case transmit_vap is NULL.
             */
            if (!transmit_vap || (tmp_vap == transmit_vap))
                tmp_vap->iv_remove_csa_ie = true;

            tmp_vap->iv_no_restart = false;

            if ((tmp_vap->iv_opmode == IEEE80211_M_STA) &&
                    !(IEEE80211_IS_PRIMARY_OR_SECONDARY_CHAN_DFS(c)))
                ieee80211_node_set_chan(tmp_vap->iv_bss);

            /*
             * If multiple vdev restart is supported,channel_switch_set_channel
             * should not be called in CSA case. Check ic_csa_num_vdevs before
             * calling channel_switch_set_channel.
             *
             *
             * If in Rep Independent mode we get a channel change from
             * CAP, set channel for sta vap's, only if it is not in DFS chan.
             * This prevents a case in which STA vap assoc state machine
             * was going into bad state. The reason being, when sta vap moves
             * to DFS channel it sends disconnet notifiction to supplicant but
             * we were doing vap reset before a proper reply hence causing bad
             * state.
             */
            if (!((IEEE80211_IS_PRIMARY_OR_SECONDARY_CHAN_DFS(c)) &&
                   ieee80211_is_cac_required_in_rep_ap(vap, c) &&
                   tmp_vap->iv_opmode == IEEE80211_M_STA) &&
                   (wlan_vdev_is_up(tmp_vap->vdev_obj) == QDF_STATUS_SUCCESS)) {

                if (tmp_vap->iv_opmode == IEEE80211_M_STA) {
                      wlan_pdev_mlme_vdev_sm_seamless_chan_change(ic->ic_pdev_obj,
                                                         tmp_vap->vdev_obj, c);
                }
                else {
                     wlan_vdev_mlme_sm_deliver_evt(tmp_vap->vdev_obj,
                                        WLAN_VDEV_SM_EV_CSA_COMPLETE, 0, NULL);
                }

                /* In case of MBSSID, channel_switch_set_channel() is called in
                 * the for loop for all the vaps. Before receiving the start
                 * response for a vap(say vap-A) ieee80211_beacon_update() for
                 * vap-B is called and vap-B reinits the beacon and sets
                 * channel_switch_state = 0. Hence the vap-A skips the CAC on
                 * reception of vdev_start response from FW in
                 * ieee80211_dfs_cac_start(). Once vap-A skips the CAC it enters
                 * RUN state and therefore  all other vaps skip the CAC.
                 *
                 * To fix the above problem, after channel change clear
                 * vap_active flag for all the vaps and do not send beacon if
                 * vap_active flag is cleared.
                 */
            }

            if ((tmp_vap->iv_opmode == IEEE80211_M_HOSTAP) &&
                    vap->iv_unit != tmp_vap->iv_unit)
                tmp_vap->channel_change_done = 1;

            /* Channel width changed.
             * Update BSS node with the new channel width.
             */
            if((ic_cw_width_prev != ic_cw_width) && (tmp_vap->iv_bss != NULL) &&
               (!wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                            WLAN_PDEV_F_MULTIVDEV_RESTART) ||
                              (ic->ic_csa_num_vdevs == 0))) {
                tmp_vap->iv_bss->ni_chwidth = ic->ic_cwm_get_width(ic);
                ic->ic_chwidth_change(tmp_vap->iv_bss);
            }
        }
    }
}

#define IS_CAC_REQUIRED_FOR_THIS_AP(_pdev, _c, _ic, _is_cac_continuable) \
    mlme_dfs_is_cac_required(_pdev, _c, _ic->ic_curchan, &_is_cac_continuable)
/* **** Channel Switch Algorithm **** *
 * New channel Non-DFS:-
 * 1)Do instant channel change for all vaps.
 *
 * New channel DFS:-
 * 1)Bring down the main STA VAP if present. In dependent mode the STA
 *   brings down the AP VAP(s) and, when re-connected, it brings up AP
 *   VAP(s).
 * 2)If main STA is not present or in independent mode, then
 *   do instant channel change for all VAPs. The channel change
 *   takes care of the CAC automatically.
 *
 * Two types of channel change:-
 * 1)Channel change driven by CSA from root AP
 * 2)Channel change by (A) RADAR or (B) user channel change
 */

/* ieee80211_is_cac_required_in_rep_ap() - Check if CAC is needed on target
 * channel in case of a Repeater VAP.
 * @vap: Pointer to ieee80211_vap structure.
 * @c: Target channel.
 *
 * Change to target channel without CAC if:
 *  A] If root can avoid CAC
 *            and
 *  B] If this AP vap can avoid CAC
 */
bool ieee80211_is_cac_required_in_rep_ap(struct ieee80211vap *vap,
                                         struct ieee80211_ath_channel *c)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    bool is_cac_continuable;

    if (ic->ic_has_rootap_done_cac &&
        !IS_CAC_REQUIRED_FOR_THIS_AP(pdev, c, ic, is_cac_continuable))
        return false;

    return true;
}

static void inline ieee80211_chan_switch_to_new_chan(
        struct ieee80211vap *vap,
        struct ieee80211_ath_channel *c)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211vap *stavap = NULL;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,"%s: Prev Chan=%u freq %d New Chan=%u freq %d mainsta=%pk enh_ind=%u\n",
            __func__,ic->ic_curchan->ic_ieee,ic->ic_curchan->ic_freq,
            c->ic_ieee,c->ic_freq,ic->ic_sta_vap,
            ieee80211_ic_enh_ind_rpt_is_set(ic));
    if (!ieee80211_is_cac_required_in_rep_ap(vap, c)) {
        /* If CAC need not be started in RE-AP, do instant channel change in both
         * dependent and independent mode.
         */
        ieee80211_beacon_change_channel(vap, c);
    } else {
        STA_VAP_DOWNUP_LOCK(ic);
        stavap = ic->ic_sta_vap;
        if(stavap)
            ieee80211_disconnect_sta_vap(ic, stavap);
        if(ieee80211_ic_enh_ind_rpt_is_set(ic) || !stavap ||
           (ic->ic_repeater_move.state == REPEATER_MOVE_START)) {
            STA_VAP_DOWNUP_UNLOCK(ic);
            ieee80211_beacon_change_channel(vap, c);
        } else {
            STA_VAP_DOWNUP_UNLOCK(ic);
        }
    }

    ieee80211_send_chanswitch_complete_event(ic);
}

/* This function adds the Maximum Channel Switch Time IE in the beacon
 *
 * "This element is optionally present in Beacon and Probe Response frames
 * when a Channel Switch Announcement or Extended Channel Switch Announcement
 * element is also present." -- Quote from ieee80211 standard
 *
 * "The Max Channel Switch Time element indicates the time delta between
 * the time the last beacon is transmitted by the AP in the current channel
 * and the expected time of the first beacon transmitted by the AP
 * in the new channel". -- Quote from ieee80211 standard
 *
 *@frm: pointer to the beacon where the IE should be written
 *@max_time: The time delta between  the last beacon TXed in the current
 *           channel and the first beacon in the new channel. In TUs.
 */
static inline void ieee80211_add_max_chan_switch_time_ie(
        uint8_t *frm,
        uint32_t max_time)
{
    struct ieee80211_max_chan_switch_time_ie *max_chan_switch_time_ie;
    uint8_t i;

    max_chan_switch_time_ie = (struct ieee80211_max_chan_switch_time_ie *) frm;
    max_chan_switch_time_ie->elem_id = IEEE80211_ELEMID_EXTN;
    max_chan_switch_time_ie->elem_len = MAX_CHAN_SWITCH_TIME_IE_LEN;
    max_chan_switch_time_ie->elem_id_ext = IEEE80211_ELEMID_EXT_MAX_CHAN_SWITCH_TIME;

    /* Pack the max_time in 3 octets/bytes. Little endian format */
    for(i = 0; i < SIZE_OF_MAX_TIME_INT; i++) {
        max_chan_switch_time_ie->switch_time[i] = (max_time & ONE_BYTE_MASK);
        max_time = (max_time >> BITS_IN_A_BYTE);
    }
}

void ieee80211_add_max_chan_switch_time(struct ieee80211vap *vap, uint8_t *frm)
{
    struct ieee80211com *ic = vap->iv_ic;
    int cac_timeout = 0;
    uint32_t max_switch_time_in_ms = 0;
    uint32_t max_switch_time_in_tu = 0;
    uint32_t cac_in_ms = 0;
    bool is_cac_continuable;
    uint32_t beacon_interval_in_ms = (uint32_t)ieee80211_vap_get_beacon_interval(vap);
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;

    if (!mlme_dfs_is_cac_required(pdev,
                                  ic->ic_chanchange_channel,
                                  ic->ic_curchan,
                                  &is_cac_continuable)) {
        cac_in_ms = 0;
    } else {
        cac_timeout = ieee80211_dfs_get_cac_timeout(ic, ic->ic_chanchange_channel);
        cac_in_ms = cac_timeout * 1000;
    }

    max_switch_time_in_ms = cac_in_ms + beacon_interval_in_ms;
    if(ic->ic_mcst_of_rootap > max_switch_time_in_ms)
    {
        max_switch_time_in_ms = ic->ic_mcst_of_rootap;
    }
    max_switch_time_in_tu = IEEE80211_MS_TO_TU(max_switch_time_in_ms);

    /* Add Maximum Channel Switch Time IE */
    ieee80211_add_max_chan_switch_time_ie(frm, max_switch_time_in_tu);
}

static void inline ieee80211_add_channel_switch_ie(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int *len_changed)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_extendedchannelswitch_ie *ecsa_ie = NULL;
    struct ieee80211_max_chan_switch_time_ie *mcst_ie = NULL;
    uint8_t *tempbuf;
    uint16_t behav_lim = 0;
    uint16_t chan_width;
    bool global_look_up = false;


    /* While IEEE80211_F_CHANSWITCH is set, insert chan switch IEs in 2 cases
     * 1) Adding the CSA IE for the first time
     * 2) We haven't sent out all the CSAs, but beacon reinit happens.
     */
    if (!vap->iv_chanchange_count || vap->beacon_reinit_done) {

        uint8_t csmode = IEEE80211_CSA_MODE_STA_TX_ALLOWED;
        uint8_t vhtchnsw_ielen = 0;
        /* the length of csa, ecsa and max chan switch time(mcst),
         * secondary channel offset and channel switch wrapper IEs is represented
         * by csa_ecsa_mcst_len, but it is initialised with 0 and based on
         * the presence of IEs, the length is increased.
         */
        uint8_t csa_ecsa_mcst_len = 0;

        ieee80211vap_set_flag(vap, IEEE80211_F_CHANSWITCH);
        vap->channel_switch_state = 1;

        if (bo->bo_chanswitch[0] != IEEE80211_ELEMID_CHANSWITCHANN) {
            csa_ecsa_mcst_len += IEEE80211_CHANSWITCHANN_BYTES;
            if (vap->iv_csmode == IEEE80211_CSA_MODE_AUTO) {

                /* No user preference for csmode. Use default behavior.
                 * If chan swith is triggered because of radar found,
                 * ask associated stations to stop transmission by
                 * sending csmode as 1 else let them transmit as usual
                 * by sending csmode as 0.
                 */
                if (ic->ic_flags & IEEE80211_F_DFS_CHANSWITCH_PENDING) {
                    /* Request STA's to stop transmission */
                    csmode = IEEE80211_CSA_MODE_STA_TX_RESTRICTED;
                }
            } else {
                /* User preference for csmode is configured.
                 * Use user preference.
                 */
                csmode = vap->iv_csmode;
            }

            /* Copy out trailer to open up a slot */
            tempbuf = (uint8_t *)qdf_mem_malloc(bo->bo_chanswitch_trailerlen);
            if (!tempbuf) {
                qdf_print("%s : tempbuf is NULL", __func__);
                return;
            }
            qdf_mem_zero(tempbuf, bo->bo_chanswitch_trailerlen);
            qdf_mem_copy(tempbuf, bo->bo_chanswitch,
                    bo->bo_chanswitch_trailerlen);
            qdf_mem_copy(bo->bo_chanswitch + IEEE80211_CHANSWITCHANN_BYTES,
                    tempbuf, bo->bo_chanswitch_trailerlen);
            qdf_mem_free(tempbuf);

            /* Add ie in opened slot */
            bo->bo_chanswitch[0] = IEEE80211_ELEMID_CHANSWITCHANN;
            bo->bo_chanswitch[1] = 3; /* fixed length */
            bo->bo_chanswitch[2] = csmode;
            bo->bo_chanswitch[3] = wlan_reg_freq_to_chan(ic->ic_pdev_obj, ic->ic_chanchange_chan_freq);
            bo->bo_chanswitch[4] = ic->ic_chanchange_tbtt - vap->iv_chanchange_count;

            if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE)) {
                /* If we set iv_bcn_csa_tmp_sent flag non-transmitting vap,
                 * host will be waiting for CSA complete event for
                 * non-transmitting vap. Since FW sends CSA complete only for
                 * transmitting vap and not for non-transmitting vap, host waits
                 * and does not restart the vaps. This leads to beacon stuck
                 * issue. Therefore set iv_bcn_csa_tmp_sent flag only for
                 * transmitting vap.
                 */
                if (!IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap))
                    vap->iv_bcn_csa_tmp_sent = true;
                else
                    vap->iv_bcn_csa_tmp_sent = false;
            } else {
                vap->iv_bcn_csa_tmp_sent = true;
            }

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
                    "%s : %d Add CSA IE, iv_bcn_csa_tmp_sent = %d vap = %d (%s) chan freq = %d\n",
                    __func__, __LINE__, vap->iv_bcn_csa_tmp_sent, vap->iv_unit,
                    vap->iv_netdev_name, ic->ic_chanchange_chan_freq);

            /* Adjust trailer, buffer offsets between CSA and ECSA */
            bo->bo_chanswitch_trailerlen += IEEE80211_CHANSWITCHANN_BYTES;
            bo->bo_tim_trailerlen += IEEE80211_CHANSWITCHANN_BYTES;
            bo->bo_bcca_trailerlen += IEEE80211_CHANSWITCHANN_BYTES;

#if ATH_SUPPORT_IBSS_DFS
            bo->bo_ibssdfs_trailerlen += IEEE80211_CHANSWITCHANN_BYTES;
#endif /* ATH_SUPPORT_IBSS_DFS */

#if UMAC_SUPPORT_WNM
            bo->bo_fms_trailerlen += IEEE80211_CHANSWITCHANN_BYTES;
#endif /* UMAC_SUPPORT_WNM */

        }

            if (bo->bo_quiet)
                bo->bo_quiet += csa_ecsa_mcst_len;

#if ATH_SUPPORT_IBSS_DFS
            if (bo->bo_ibssdfs)
                bo->bo_ibssdfs += csa_ecsa_mcst_len;
#endif

            if (bo->bo_tpcreport) {
                bo->bo_tpcreport += csa_ecsa_mcst_len;
            }

            if (bo->bo_erp)
                bo->bo_erp += csa_ecsa_mcst_len;

            if (bo->bo_xrates)
                bo->bo_xrates += csa_ecsa_mcst_len;

            if (bo->bo_rsn)
                bo->bo_rsn += csa_ecsa_mcst_len;

            if (bo->bo_qbssload)
                bo->bo_qbssload += csa_ecsa_mcst_len;

            if (bo->bo_edca)
                bo->bo_edca += csa_ecsa_mcst_len;

            if (bo->bo_qos_cap)
                bo->bo_qos_cap += csa_ecsa_mcst_len;

            if (bo->bo_ap_chan_rpt)
                bo->bo_ap_chan_rpt += csa_ecsa_mcst_len;

            if (bo->bo_bss_avg_delay)
                bo->bo_bss_avg_delay += csa_ecsa_mcst_len;

            if (bo->bo_antenna)
                bo->bo_antenna += csa_ecsa_mcst_len;

            if (bo->bo_bss_adm_cap)
                bo->bo_bss_adm_cap += csa_ecsa_mcst_len;

#ifndef ATH_SUPPORT_WAPI
            if (bo->bo_bss_ac_acc_delay)
                bo->bo_bss_ac_acc_delay += csa_ecsa_mcst_len;
#endif

            if (bo->bo_msmt_pilot_tx)
                bo->bo_msmt_pilot_tx += csa_ecsa_mcst_len;

            if (bo->bo_mob_domain)
                bo->bo_mob_domain += csa_ecsa_mcst_len;

            if (bo->bo_dse_reg_loc)
                bo->bo_dse_reg_loc += csa_ecsa_mcst_len;

            bo->bo_ecsa += csa_ecsa_mcst_len;

            /* Check for ecsa_ie pointer instead of ic->ic_ecsaie flag
             * to avoid ic->ic_ecsaie being updated in between from IOCTL
             * context.
             */
            if (vap->iv_enable_ecsaie) {
                /* Copy out trailer to open up a slot */
                tempbuf = (uint8_t *)qdf_mem_malloc(bo->bo_ecsa_trailerlen);
                qdf_mem_zero(tempbuf, bo->bo_ecsa_trailerlen);
                ecsa_ie = (struct ieee80211_extendedchannelswitch_ie *) bo->bo_ecsa;
                qdf_mem_copy(tempbuf, bo->bo_ecsa,
                        bo->bo_ecsa_trailerlen);
                qdf_mem_copy(bo->bo_ecsa + IEEE80211_EXTCHANSWITCHANN_BYTES,
                        tempbuf, bo->bo_ecsa_trailerlen);
                qdf_mem_free(tempbuf);

                ecsa_ie->ie = IEEE80211_ELEMID_EXTCHANSWITCHANN;
                ecsa_ie->len = 4;
                ecsa_ie->switchmode = csmode;

                /* If user configured opClass is set, use it else
                 * calculate new opClass from destination channel.
                 */
                if (vap->iv_ecsa_opclass) {
                    ecsa_ie->newClass = vap->iv_ecsa_opclass;
                    ecsa_ie->newchannel =
                        wlan_reg_freq_to_chan(ic->ic_pdev_obj,
                                              ic->ic_chanchange_chan_freq);
                } else {
                    /* Channel look-up tables should not change with CSA */
                    global_look_up = false;
                    wlan_get_bw_and_behav_limit(ic->ic_chanchange_channel,
                                                &chan_width, &behav_lim);

                    if (!behav_lim) {
                        return;
                    }
                    /* Get new OpClass and Channel number from regulatory */
                    wlan_reg_freq_width_to_chan_op_class_auto(ic->ic_pdev_obj,
                                                              ic->ic_chanchange_chan_freq,
                                                              chan_width,
                                                              global_look_up, behav_lim,
                                                              &ecsa_ie->newClass,
                                                              &ecsa_ie->newchannel);
                }

                ecsa_ie->tbttcount = ic->ic_chanchange_tbtt;
                csa_ecsa_mcst_len += IEEE80211_EXTCHANSWITCHANN_BYTES;

                /* Adjust trailers if ECSA is added */
                bo->bo_chanswitch_trailerlen += IEEE80211_EXTCHANSWITCHANN_BYTES;
                bo->bo_tim_trailerlen += IEEE80211_EXTCHANSWITCHANN_BYTES;
                bo->bo_ecsa_trailerlen += IEEE80211_EXTCHANSWITCHANN_BYTES;
                bo->bo_bcca_trailerlen += IEEE80211_EXTCHANSWITCHANN_BYTES;
#if ATH_SUPPORT_IBSS_DFS
                bo->bo_ibssdfs_trailerlen += IEEE80211_EXTCHANSWITCHANN_BYTES;
#endif /* ATH_SUPPORT_IBSS_DFS */

#if UMAC_SUPPORT_WNM
                bo->bo_fms_trailerlen += IEEE80211_EXTCHANSWITCHANN_BYTES;
#endif /* UMAC_SUPPORT_WNM */
            }

            /* Adjust buffer offsets between ECSA and CSA Wrapper */
            if (bo->bo_opt_class)
                bo->bo_opt_class += csa_ecsa_mcst_len;

            if (bo->bo_htcap)
                bo->bo_htcap += csa_ecsa_mcst_len;

            if (bo->bo_htinfo)
                bo->bo_htinfo += csa_ecsa_mcst_len;

            if (bo->bo_2040_coex)
                bo->bo_2040_coex += csa_ecsa_mcst_len;

            if (bo->bo_obss_scan)
                bo->bo_obss_scan += csa_ecsa_mcst_len;

            if (bo->bo_extcap)
                bo->bo_extcap += csa_ecsa_mcst_len;

#if UMAC_SUPPORT_WNM
            if (bo->bo_fms_desc)
                bo->bo_fms_desc += csa_ecsa_mcst_len;

            if (bo->bo_fms_trailer)
                bo->bo_fms_trailer += csa_ecsa_mcst_len;
#endif
            if (bo->bo_qos_traffic)
                bo->bo_qos_traffic += csa_ecsa_mcst_len;

            if (bo->bo_time_adv)
                bo->bo_time_adv += csa_ecsa_mcst_len;

            if (bo->bo_interworking)
                bo->bo_interworking += csa_ecsa_mcst_len;

            if (bo->bo_adv_proto)
                bo->bo_adv_proto += csa_ecsa_mcst_len;

            if (bo->bo_roam_consortium)
                bo->bo_roam_consortium += csa_ecsa_mcst_len;

            if (bo->bo_emergency_id)
                bo->bo_emergency_id  += csa_ecsa_mcst_len;

            if (bo->bo_mesh_id)
                bo->bo_mesh_id += csa_ecsa_mcst_len;

            if (bo->bo_mesh_conf)
                bo->bo_mesh_conf += csa_ecsa_mcst_len;

            if (bo->bo_mesh_awake_win)
                bo->bo_mesh_awake_win += csa_ecsa_mcst_len;

            if (bo->bo_beacon_time)
                bo->bo_beacon_time += csa_ecsa_mcst_len;

            if (bo->bo_mccaop_adv_ov)
                bo->bo_mccaop_adv_ov += csa_ecsa_mcst_len;

            if (bo->bo_mccaop_adv)
                bo->bo_mccaop_adv += csa_ecsa_mcst_len;

            if (bo->bo_mesh_cs_param)
                bo->bo_mesh_cs_param += csa_ecsa_mcst_len;

            if (bo->bo_qmf_policy)
                bo->bo_qmf_policy += csa_ecsa_mcst_len;

            if (bo->bo_qload_rpt)
                bo->bo_qload_rpt += csa_ecsa_mcst_len;

            if (bo->bo_hcca_upd_cnt)
                bo->bo_hcca_upd_cnt += csa_ecsa_mcst_len;

            if (bo->bo_multiband)
                bo->bo_multiband += csa_ecsa_mcst_len;

            if (bo->bo_vhtcap)
                bo->bo_vhtcap += csa_ecsa_mcst_len;

            if (bo->bo_vhtop)
                bo->bo_vhtop += csa_ecsa_mcst_len;

            if (bo->bo_vhttxpwr)
                bo->bo_vhttxpwr += csa_ecsa_mcst_len;

            if (bo->bo_vhtchnsw)
                bo->bo_vhtchnsw += csa_ecsa_mcst_len;

        /* Filling channel switch wrapper element */
        if ((IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
                IEEE80211_IS_CHAN_11AXA(vap->iv_bsschan)) &&
                ieee80211vap_vht_or_above_allowed(vap)
                && (ic->ic_chanchange_channel != NULL) &&
                (bo->bo_vhtchnsw != NULL)) {

            uint8_t *vhtchnsw_ie;

            /* Copy out trailer to open up a slot */
            tempbuf = (uint8_t *)qdf_mem_malloc(bo->bo_vhtchnsw_trailerlen);
            qdf_mem_zero(tempbuf, bo->bo_vhtchnsw_trailerlen);

            if(tempbuf != NULL) {
                qdf_mem_copy(tempbuf, bo->bo_vhtchnsw, bo->bo_vhtchnsw_trailerlen);

                /* Adding channel switch wrapper element */
                vhtchnsw_ie = ieee80211_add_chan_switch_wrp(bo->bo_vhtchnsw,
                        ni, ic, IEEE80211_FC0_SUBTYPE_BEACON,
                        /* When switching to new country by sending ECSA IE,
                         * new country IE should be also be added.
                         * As of now we dont support switching to new country
                         * without bringing down vaps so new country IE is not
                         * required.
                         */
                        (/*ecsa_ie ? IEEE80211_VHT_EXTCH_SWITCH :*/
                         !IEEE80211_VHT_EXTCH_SWITCH));
                vhtchnsw_ielen = vhtchnsw_ie - bo->bo_vhtchnsw;

                /* Copying the rest of beacon buffer */
                qdf_mem_copy(vhtchnsw_ie, tempbuf, bo->bo_vhtchnsw_trailerlen);
                qdf_mem_free(tempbuf);

                if(vhtchnsw_ielen) {
                    /* Adjusting trailers if CSA Wrapper is added */
                    bo->bo_tim_trailerlen += vhtchnsw_ielen;
                    bo->bo_chanswitch_trailerlen += vhtchnsw_ielen;
                    bo->bo_ecsa_trailerlen += vhtchnsw_ielen;
                    bo->bo_vhtchnsw_trailerlen += vhtchnsw_ielen;
                    bo->bo_bcca_trailerlen += vhtchnsw_ielen;

#if ATH_SUPPORT_IBSS_DFS
                    bo->bo_ibssdfs_trailerlen += vhtchnsw_ielen;
#endif /* ATH_SUPPORT_IBSS_DFS */

#if UMAC_SUPPORT_WNM
                    bo->bo_fms_trailerlen += vhtchnsw_ielen;
#endif /* UMAC_SUPPORT_WNM */

                    csa_ecsa_mcst_len += vhtchnsw_ielen;
                }
            }
        }

        /* Adjust buffer offsets between CSA Wrapper and MCST */
        if (bo->bo_ext_bssload)
            bo->bo_ext_bssload += csa_ecsa_mcst_len;

        if (bo->bo_quiet_chan)
            bo->bo_quiet_chan += csa_ecsa_mcst_len;

        if (bo->bo_opt_mode_note)
            bo->bo_opt_mode_note += csa_ecsa_mcst_len;

        if (vap->rnr_enable)
            vap->rnr_enable += csa_ecsa_mcst_len;

        if (bo->bo_tvht)
            bo->bo_tvht += csa_ecsa_mcst_len;


#if QCN_ESP_IE
        if (bo->bo_esp_ie)
            bo->bo_esp_ie += csa_ecsa_mcst_len;
#endif

        if (bo->bo_future_chan)
            bo->bo_future_chan += csa_ecsa_mcst_len;

        if (bo->bo_cag_num)
            bo->bo_cag_num += csa_ecsa_mcst_len;

        if (bo->bo_fils_ind)
            bo->bo_fils_ind += csa_ecsa_mcst_len;

        if (bo->bo_ap_csn)
            bo->bo_ap_csn += csa_ecsa_mcst_len;

        if (bo->bo_diff_init_lnk)
            bo->bo_diff_init_lnk += csa_ecsa_mcst_len;

        if (bo->bo_service_hint)
            bo->bo_service_hint += csa_ecsa_mcst_len;

        if (bo->bo_service_hash)
            bo->bo_service_hash += csa_ecsa_mcst_len;

        if (bo->bo_hecap)
            bo->bo_hecap += csa_ecsa_mcst_len;

        if (bo->bo_heop)
            bo->bo_heop += csa_ecsa_mcst_len;

        if (bo->bo_twt)
            bo->bo_twt += csa_ecsa_mcst_len;

#if ATH_SUPPORT_UORA
        if (bo->bo_uora_param)
            bo->bo_uora_param += csa_ecsa_mcst_len;
#endif

        if (bo->bo_bcca)
            bo->bo_bcca += csa_ecsa_mcst_len;

#if OBSS_PD
        if(bo->bo_srp_ie)
            bo->bo_srp_ie += csa_ecsa_mcst_len;
#endif

        if (bo->bo_muedca)
            bo->bo_muedca += csa_ecsa_mcst_len;

        if (bo->bo_ess_rpt)
            bo->bo_ess_rpt += csa_ecsa_mcst_len;

        if (bo->bo_ndp_rpt_param)
            bo->bo_ndp_rpt_param += csa_ecsa_mcst_len;

        if (bo->bo_he_bss_load)
            bo->bo_he_bss_load += csa_ecsa_mcst_len;

        if (bo->bo_he_6g_bandcap)
            bo->bo_he_6g_bandcap += csa_ecsa_mcst_len;

        bo->bo_mcst += csa_ecsa_mcst_len;

        /* Check if max chan switch time IE(mcst IE) has to be added.
         * If yes, update csa_ecsa_mcst_len
         */
        if (vap->iv_enable_max_ch_sw_time_ie) {
            tempbuf = (uint8_t *)qdf_mem_malloc(bo->bo_mcst_trailerlen);
            qdf_mem_zero(tempbuf, bo->bo_mcst_trailerlen);
            qdf_mem_copy(tempbuf, bo->bo_mcst,
                    bo->bo_mcst_trailerlen);
            qdf_mem_copy(bo->bo_mcst
                    + IEEE80211_MAXCHANSWITCHTIME_BYTES,
                    tempbuf, bo->bo_mcst_trailerlen);
            qdf_mem_free(tempbuf);

            mcst_ie = (struct ieee80211_max_chan_switch_time_ie *)bo->bo_mcst;
            ieee80211_add_max_chan_switch_time(vap, (uint8_t *)mcst_ie);

            /* Adjust trailers alone
             * Buffer offsets will be adjusted after secondary channel offset updation
             */
            bo->bo_tim_trailerlen += IEEE80211_MAXCHANSWITCHTIME_BYTES;
            bo->bo_chanswitch_trailerlen += IEEE80211_MAXCHANSWITCHTIME_BYTES;
            bo->bo_ecsa_trailerlen += IEEE80211_MAXCHANSWITCHTIME_BYTES;
            bo->bo_vhtchnsw_trailerlen += IEEE80211_MAXCHANSWITCHTIME_BYTES;
            bo->bo_mcst_trailerlen += IEEE80211_MAXCHANSWITCHTIME_BYTES;
            bo->bo_bcca_trailerlen += IEEE80211_MAXCHANSWITCHTIME_BYTES;

#if ATH_SUPPORT_IBSS_DFS
            bo->bo_ibssdfs_trailerlen += IEEE80211_MAXCHANSWITCHTIME_BYTES;
#endif /* ATH_SUPPORT_IBSS_DFS */

#if UMAC_SUPPORT_WNM
            bo->bo_fms_trailerlen += IEEE80211_MAXCHANSWITCHTIME_BYTES;
#endif /* UMAC_SUPPORT_WNM */

            csa_ecsa_mcst_len += IEEE80211_MAXCHANSWITCHTIME_BYTES;
        }

        bo->bo_secchanoffset += csa_ecsa_mcst_len;

        /* Add secondary channel offset element if new channel has
         * secondary 20 MHz channel
         */
        if (((IEEE80211_IS_CHAN_11N(vap->iv_bsschan) ||
            IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
            IEEE80211_IS_CHAN_11AX(vap->iv_bsschan)) &&
            (ic->ic_chanchange_secoffset)) &&
            ic->ic_sec_offsetie && bo->bo_secchanoffset) {

            /* Add secondary channel offset element */
            struct ieee80211_ie_sec_chan_offset *sec_chan_offset_ie = NULL;
            tempbuf = (uint8_t *)qdf_mem_malloc(bo->bo_secchanoffset_trailerlen);
            qdf_mem_zero(tempbuf, bo->bo_secchanoffset_trailerlen);

            if(tempbuf) {
                qdf_mem_copy(tempbuf, bo->bo_secchanoffset,
                        bo->bo_secchanoffset_trailerlen);
                qdf_mem_copy(bo->bo_secchanoffset
                        + IEEE80211_SEC_CHAN_OFFSET_BYTES,
                        tempbuf, bo->bo_secchanoffset_trailerlen);
                qdf_mem_free(tempbuf);

                sec_chan_offset_ie = (struct ieee80211_ie_sec_chan_offset *)
                    bo->bo_secchanoffset;
                sec_chan_offset_ie->elem_id = IEEE80211_ELEMID_SECCHANOFFSET;

                /* Element has only one octet of info */
                sec_chan_offset_ie->len = 1;
                sec_chan_offset_ie->sec_chan_offset =
                    ic->ic_chanchange_secoffset;

                /* Adjust trailers, and buffer offsets between MCST and app ie buf */
                bo->bo_tim_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                bo->bo_chanswitch_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                bo->bo_ecsa_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                bo->bo_vhtchnsw_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                bo->bo_mcst_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                bo->bo_secchanoffset_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                bo->bo_bcca_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;

#if ATH_SUPPORT_IBSS_DFS
                bo->bo_ibssdfs_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
#endif /* ATH_SUPPORT_IBSS_DFS */

#if UMAC_SUPPORT_WNM
                bo->bo_fms_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
#endif /* UMAC_SUPPORT_WNM */

                csa_ecsa_mcst_len += IEEE80211_SEC_CHAN_OFFSET_BYTES;
            }
        }

        if (bo->bo_rsnx)
            bo->bo_rsnx += csa_ecsa_mcst_len;

        if (bo->bo_ath_caps)
            bo->bo_ath_caps += csa_ecsa_mcst_len;

        if (bo->bo_extender_ie)
            bo->bo_extender_ie += csa_ecsa_mcst_len;

        if (bo->bo_htinfo_vendor_specific)
            bo->bo_htinfo_vendor_specific += csa_ecsa_mcst_len;

        if (bo->bo_mbo_cap )
            bo->bo_mbo_cap  += csa_ecsa_mcst_len;

        if (bo->bo_apriori_next_channel)
            bo->bo_apriori_next_channel += csa_ecsa_mcst_len;

        if (bo->bo_bwnss_map)
            bo->bo_bwnss_map += csa_ecsa_mcst_len;

#if QCN_IE
        if (bo->bo_qcn_ie)
            bo->bo_qcn_ie += csa_ecsa_mcst_len;
#endif

        if (bo->bo_software_version_ie)
            bo->bo_software_version_ie += csa_ecsa_mcst_len;

        if (bo->bo_xr)
            bo->bo_xr += csa_ecsa_mcst_len;

        if (bo->bo_whc_apinfo)
            bo->bo_whc_apinfo += csa_ecsa_mcst_len;

        if (bo->bo_interop_vhtcap)
            bo->bo_interop_vhtcap += csa_ecsa_mcst_len;

        if (bo->bo_wme)
            bo->bo_wme += csa_ecsa_mcst_len;

        if (bo->bo_appie_buf)
            bo->bo_appie_buf += csa_ecsa_mcst_len;

         /* Indicate new beacon length so other layers may manage memory */
         wbuf_append(wbuf, csa_ecsa_mcst_len);
         *len_changed = 1;
    } else {
        bo->bo_chanswitch[4] =
            ic->ic_chanchange_tbtt - vap->iv_chanchange_count;
        /* ECSA IE is added if enabled
         * Update tbtt count in ECSA IE to same as CSA IE.
         */
        ecsa_ie = (struct ieee80211_extendedchannelswitch_ie *)bo->bo_ecsa;

        if (ecsa_ie->ie == IEEE80211_ELEMID_EXTCHANSWITCHANN) {
            /* ECSA is inserted, so update tbttcount */
            ecsa_ie->tbttcount = bo->bo_chanswitch[4];
        }
    }

    vap->iv_chanchange_count++;

    /* In case of repeater move, send deauth to old root AP one count
     * before channel switch happens
     */
    if (bo->bo_chanswitch[4] == 1 && ic->ic_repeater_move.state == REPEATER_MOVE_START) {
        struct ieee80211vap *rep_sta_vap = ic->ic_sta_vap;
        struct ieee80211_node *ni = ieee80211_vap_find_node(rep_sta_vap,
                rep_sta_vap->iv_bss->ni_bssid, WLAN_MLME_SB_ID);
        if (ni != NULL) {
            ieee80211_send_deauth(ni, IEEE80211_REASON_AUTH_LEAVE);
            ieee80211_free_node(ni, WLAN_MLME_SB_ID);
        }
    }
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
            "%s: CHANSWITCH IE, change in %d \n",
            __func__, bo->bo_chanswitch[4]);
}

static void ieee80211_beacon_reinit(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int *len_changed,
        bool *update_beacon_copy)
{
    uint8_t *frm = NULL;
    struct ieee80211vap *vap = ni->ni_vap;

    frm = (uint8_t *) wbuf_header(wbuf) + sizeof(struct ieee80211_frame);
    frm = ieee80211_beacon_init(ni, bo, frm);
    if (!frm)
        return;

    *update_beacon_copy = true;
    wbuf_set_pktlen(wbuf, (frm - (uint8_t *)wbuf_header(wbuf)));
    *len_changed = 1;
    vap->beacon_reinit_done = true;
}

static void ieee80211_csa_interop_phy_iter_sta(void *arg, wlan_node_t wn)
{
    struct ieee80211_node *bss;
    struct ieee80211_node *ni;
    struct ieee80211vap *vap;
    struct ieee80211com *ic;

    ni = wn;
    bss = arg;

    if (!ni || !bss) {
        return;
    }
    vap = ni->ni_vap;
    ic = vap->iv_ic;

    if (ni == bss) {
        qdf_debug("[%s, %pM] skipping bss node", vap->iv_netdev_name,
                 ni->ni_macaddr);
        return;
    }

    ieee80211_csa_interop_phy_update(ni, -1);
}

static void ieee80211_csa_interop_phy_iter_vap(void *arg, wlan_if_t wif)
{
    struct ieee80211vap *vap;

    vap = wif;
    if (!vap->iv_csa_interop_phy)
        return;

    wlan_iterate_station_list(vap, ieee80211_csa_interop_phy_iter_sta, vap->iv_bss);
}

static void ieee80211_csa_interop_phy(struct ieee80211com *ic)
{
    int err;

    /* Subscribe to ppdu stats to see if STA is transmitting
     * higher bw frames.
     */
    if (ic->ic_subscribe_csa_interop_phy &&
            ieee80211_get_num_csa_interop_phy_vaps(ic)) {
        err = ic->ic_subscribe_csa_interop_phy(ic, true);
        if (!err) {
            wlan_iterate_vap_list(ic, ieee80211_csa_interop_phy_iter_vap, NULL);
            /* start timer to unsubscrive per ppdu stats */
            qdf_timer_mod(&ic->ic_csa_max_rx_wait_timer, g_csa_max_rx_wait_time);
        }
    }
}

/* ieee80211_change_channel: If all the CSAs have been sent, change the channel
 * and reset the channel switch flags.
 *
 * return 0: Perform channel change and reset channel switch flags.
 * return 1: Not all the CSAs have been sent or usenol is 0, so channel change
 * doesn't happen.
 */
static int ieee80211_change_channel(
        struct ieee80211_node *ni,
        bool *update_beacon_copy,
        int *len_changed,
        wbuf_t wbuf,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_ath_channel *c;
    struct ieee80211vap *tmp_vap = NULL;
    struct ieee80211_vap_opmode_count vap_opmode_count;

    if ((vap->iv_flags & IEEE80211_F_CHANSWITCH) &&
            (vap->iv_chanchange_count == ic->ic_chanchange_tbtt) &&
            IEEE80211_CHANCHANGE_BY_BEACONUPDATE_IS_SET(ic)) {

        vap->iv_chanchange_count = 0;

        /*
         * NB: iv_bsschan is in the DSPARMS beacon IE, so must set this
         * prior to the beacon re-init, below.
         */
        if (!ic->ic_chanchange_channel) {
            c = ieee80211_doth_findchan(vap, ic->ic_chanchange_chan_freq);
            if (c == NULL) {
                qdf_err("[%s]: find channel failure ic_chanchange_chan_freq = %d\n",
                         vap->iv_netdev_name, ic->ic_chanchange_chan_freq);
                return 0;
            }
        } else {
            c = ic->ic_chanchange_channel;
        }
        vap->iv_bsschan = c;

#if ATH_SUPPORT_IBSS_DFS
        if (vap->iv_opmode == IEEE80211_M_IBSS) {
            if (IEEE80211_ADDR_EQ(vap->iv_ibssdfs_ie_data.owner,
                        vap->iv_myaddr))
                vap->iv_ibssdfs_state = IEEE80211_IBSSDFS_OWNER;
            else
                vap->iv_ibssdfs_state = IEEE80211_IBSSDFS_JOINER;
        }
#endif

        ieee80211_beacon_reinit(ni, bo, wbuf, len_changed, update_beacon_copy);

        /* Clear IEEE80211_F_CHANSWITCH flag */
        ieee80211vap_clear_flag(vap, IEEE80211_F_CHANSWITCH);

        ieee80211com_clear_flags(ic, IEEE80211_F_CHANSWITCH);

        ieee80211_csa_interop_phy(ic);

        if (ic->ic_chanchange_chwidth != 0) {
            /* Wide Bandwidth Channel Switch for VHT/11ax 5 GHz only.
             * In this case need to update phymode.
             */
            uint64_t chan_flag = ic->ic_chanchange_chanflag;
            enum ieee80211_phymode mode = 0;

            /* 11AX TODO: Recheck future 802.11ax drafts (>2.0) on
             * channel switching rules.
             */

            /*Get phymode from chan_flag value */
            mode = ieee80211_get_phymode_from_chan_flag(ic->ic_curchan,
                    chan_flag);

            if(mode != 0 && (ic->ic_opmode == IEEE80211_M_HOSTAP)){
                ieee80211_setmode(ic, mode, IEEE80211_M_HOSTAP);
                OS_MEMZERO(&vap_opmode_count, sizeof(vap_opmode_count));
                ieee80211_get_vap_opmode_count(ic, &vap_opmode_count);
                /* Allow phymode override in non-repeater mode */
                if (!vap_opmode_count.sta_count) {
                    TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                        wlan_set_desired_phymode(tmp_vap,mode);
                    }
                }

            }
        }

        if (ic->ic_curchan != c) {
            ieee80211_chan_switch_to_new_chan(vap, c);
        } else {
            struct ieee80211vap *transmit_vap = NULL;

            if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                        WLAN_PDEV_F_MBSS_IE_ENABLE)) {
                transmit_vap = ic->ic_mbss.transmit_vap;
            }

            TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                if(tmp_vap->iv_opmode == IEEE80211_M_HOSTAP) {

                    /* When MBSSIE FR is enabled, set iv_remove_csa_ie flag only
                     * for transmitting vap. Based on this flag beacon template
                     * is sent to FW in CSA event handler. Do not set
                     * iv_remove_csa_ie flag for non-transmitting vaps, as Host
                     * does not send CSA template to FW for these vaps.
                     * When MBSSIE FR is disabled, host sends CSA template for
                     * all the vaps to FW. Therefore set iv_remove_csa_ie for
                     * all the vaps. In this case transmit_vap is NULL.
                     */
                    if (!transmit_vap || (tmp_vap == transmit_vap))
                    {
                        tmp_vap->iv_remove_csa_ie = true;
                        tmp_vap->iv_no_restart = true;
                    }

                    /* When MBSSIE FR is enabled, set iv_no_restart flag only
                     * for transmitting vap.
                     */
                    if (transmit_vap && (tmp_vap == transmit_vap)) {
                        tmp_vap->iv_no_restart = true;
                    }

                    tmp_vap->iv_chanchange_count = 0;
                    ieee80211vap_clear_flag(tmp_vap, IEEE80211_F_CHANSWITCH);
                    wlan_vdev_mlme_sm_deliver_evt(tmp_vap->vdev_obj,
                                        WLAN_VDEV_SM_EV_CSA_COMPLETE, 0, NULL);
                }
            }
        }

        /* Resetting VHT channel change variables */
        ic->ic_chanchange_channel = NULL;
        ic->ic_chanchange_chwidth = 0;
        IEEE80211_CHAN_SWITCH_END(ic);

        IEEE80211_CHANCHANGE_STARTED_CLEAR(ic);
        IEEE80211_CHANCHANGE_BY_BEACONUPDATE_CLEAR(ic);
        if (!vap->iv_bcn_offload_enable) {
            if(mlme_dfs_get_rn_use_nol(ic->ic_pdev_obj))
                return 0;
        }
    }
    return 1;
}

static void inline ieee80211_update_capinfo(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211com *ic = vap->iv_ic;
    uint16_t capinfo;

    /* XXX faster to recalculate entirely or just changes? */
    if (vap->iv_opmode == IEEE80211_M_IBSS){
        if(ic->ic_softap_enable)
            capinfo = IEEE80211_CAPINFO_ESS;
        else
            capinfo = IEEE80211_CAPINFO_IBSS;
    } else {
        capinfo = IEEE80211_CAPINFO_ESS;
    }

    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap))
        capinfo |= IEEE80211_CAPINFO_PRIVACY;

    if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
            IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan))
        capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;

    if (ic->ic_flags & IEEE80211_F_SHSLOT)
        capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;

    if (ieee80211_ic_doth_is_set(ic) &&
            ieee80211_vap_doth_is_set(vap))
        capinfo |= IEEE80211_CAPINFO_SPECTRUM_MGMT;

    if (IEEE80211_VAP_IS_PUREB_ENABLED(vap))
        capinfo &= ~IEEE80211_CAPINFO_SHORT_SLOTTIME;

    /* set rrm capbabilities, if supported */
    if (ieee80211_vap_rrm_is_set(vap))
        capinfo |= IEEE80211_CAPINFO_RADIOMEAS;

    *bo->bo_caps = htole16(capinfo);
}

/*
 * Check if channel change due to CW interference needs to be done.
 * Since this is a drastic channel change, we do not wait for the TBTT
 * interval to expair and do not send Channel change flag in beacon.
 */
static void ieee80211_beacon_check_and_reinit_beacon(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int *len_changed,
        bool *update_beacon_copy)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = vap->iv_ic;

    if ((vap->iv_flags_ext2 & IEEE80211_FEXT2_BR_UPDATE) ||
            vap->iv_update_vendor_ie ||
            vap->channel_change_done ||
            vap->appie_buf_updated   ||
            vap->iv_doth_updated     ||
            (vap->iv_flags_ext2 & IEEE80211_FEXT2_MBO) ||
            vap->iv_remove_csa_ie    ||
            vap->iv_he_bsscolor_remove_ie ||
            vap->iv_mbss.mbssid_add_del_profile ||
            vap->iv_sr_ie_reset ||
            vap->iv_oob_update)
    {

        ieee80211_beacon_reinit(ni, bo, wbuf, len_changed, update_beacon_copy);

        ieee80211vap_clear_flag_ext2(vap, IEEE80211_FEXT2_MBO);
        ieee80211vap_clear_flag_ext2(vap, IEEE80211_FEXT2_BR_UPDATE);
        vap->iv_update_vendor_ie = 0;
        vap->channel_change_done = 0;
        vap->appie_buf_updated   = 0;
        vap->iv_doth_updated     = 0;
        vap->iv_he_bsscolor_remove_ie = false;
        vap->iv_mbss.mbssid_add_del_profile = 0;
        vap->iv_sr_ie_reset = 0;
        vap->iv_oob_update = 0;

        if (!vap->iv_bcn_offload_enable) {
            vap->iv_remove_csa_ie = false;
            vap->channel_switch_state = 0;
        }

        if (ic->cw_inter_found)
            ic->cw_inter_found = 0;
    }
}

static void ieee80211_beacon_add_wme_param(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo,
        bool *update_beacon_copy)
{
    if (ieee80211_vap_wme_is_set(vap) &&
#if ATH_SUPPORT_IBSS_WMM
            (vap->iv_opmode == IEEE80211_M_HOSTAP ||
             vap->iv_opmode == IEEE80211_M_IBSS)
#else
            (vap->iv_opmode == IEEE80211_M_HOSTAP)
#endif
       ) {
        struct ieee80211_wme_state *wme = &vap->iv_wmestate;

        /* XXX multi-bss */
        if ((vap->iv_flags & IEEE80211_F_WMEUPDATE) && (bo->bo_wme)) {
            ieee80211_add_wme_param(bo->bo_wme, wme,
                    IEEE80211_VAP_IS_UAPSD_ENABLED(vap));
            *update_beacon_copy = true;
            ieee80211vap_clear_flag(vap, IEEE80211_F_WMEUPDATE);
        }
    }
}

static void ieee80211_beacon_update_muedca_param(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo,
        bool *update_beacon_copy)
{
    if(ieee80211_vap_wme_is_set(vap) &&
            ieee80211vap_heallowed(vap) &&
            IEEE80211_IS_CHAN_11AX(vap->iv_ic->ic_curchan) &&
            ieee80211vap_muedca_is_enabled(vap) && (bo->bo_muedca)) {
        ieee80211_add_muedca_param(bo->bo_muedca, &vap->iv_muedcastate);
        *update_beacon_copy = true;
    }
}

#if ATH_SUPPORT_UORA
static void ieee80211_beacon_update_uora_param(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo,
        bool *update_beacon_copy)
{
    if( ieee80211vap_heallowed(vap) &&
             IEEE80211_IS_CHAN_11AX(vap->iv_ic->ic_curchan) &&
             ieee80211vap_uora_is_enabled(vap) && (bo->bo_uora_param)) {
        ieee80211_add_uora_param(bo->bo_uora_param, vap->iv_ocw_range);
        *update_beacon_copy = true;
    }
}
#endif

static void  ieee80211_beacon_update_pwrcnstr(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211com *ic = vap->iv_ic;

    if (bo->bo_pwrcnstr &&
            ieee80211_ic_doth_is_set(ic) &&
            ieee80211_vap_doth_is_set(vap)) {
        uint8_t *pwrcnstr = bo->bo_pwrcnstr;

        *pwrcnstr++ = IEEE80211_ELEMID_PWRCNSTR;
        *pwrcnstr++ = 1;
        *pwrcnstr++ = IEEE80211_PWRCONSTRAINT_VAL(vap);
    }
}

static void ieee80211_update_chan_utilization(
        struct ieee80211vap *vap)
{
#if UMAC_SUPPORT_QBSSLOAD
    ieee80211_beacon_chanutil_update(vap);
#elif UMAC_SUPPORT_CHANUTIL_MEASUREMENT
    if (vap->iv_chanutil_enab) {
        ieee80211_beacon_chanutil_update(vap);
    }
#endif
}

static void inline ieee80211_beacon_add_htcap(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    int enable_htrates;

    enable_htrates = ieee80211vap_htallowed(vap);

    /*
     * HT cap. check for vap is done in ieee80211vap_htallowed.
     * TBD: remove iv_bsschan check to support multiple channel operation.
     */
    if (ieee80211_vap_wme_is_set(vap) &&
            (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
            (IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) ||
             IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
             IEEE80211_IS_CHAN_11N(vap->iv_bsschan)) &&
            enable_htrates && (bo->bo_htinfo != NULL) &&
            (bo->bo_htcap != NULL)) {

        struct ieee80211_ie_htinfo_cmn *htinfo;
        struct ieee80211_ie_obss_scan *obss_scan;

#if IEEE80211_BEACON_NOISY
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_11N,
                "%s: AP: updating HT Info IE (ANA) for %s\n",
                __func__, ether_sprintf(ni->ni_macaddr));

        if (bo->bo_htinfo[0] != IEEE80211_ELEMID_HTINFO_ANA) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_11N,
                    "%s: AP: HT Info IE (ANA) beacon offset askew %s "
                    "expected 0x%02x, found 0x%02x\n",
                    __func__, ether_sprintf(ni->ni_macaddr),
                    IEEE80211_ELEMID_HTINFO_ANA, bo->bo_htinfo[0]);
        }
#endif
        htinfo = &((struct ieee80211_ie_htinfo *)bo->bo_htinfo)->hi_ie;
        ieee80211_update_htinfo_cmn(htinfo, ni);

        ieee80211_add_htcap(bo->bo_htcap, ni, IEEE80211_FC0_SUBTYPE_BEACON);

        if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
            obss_scan = (struct ieee80211_ie_obss_scan *)bo->bo_obss_scan;
            if(obss_scan)
                ieee80211_update_obss_scan(obss_scan, ni);
        }

        if (IEEE80211_IS_HTVIE_ENABLED(ic) &&
                bo->bo_htinfo_vendor_specific) {
#if IEEE80211_BEACON_NOISY
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_11N,
                    "%s: AP: updating HT Info IE (Vendor Specific) for %s\n",
                    __func__, ether_sprintf(ni->ni_macaddr));
            if (bo->bo_htinfo_vendor_specific[5] !=
                    IEEE80211_ELEMID_HTINFO_VENDOR) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_11N,
                        "%s: AP: HT Info IE (Vendor Specific) beacon offset askew %s expected 0x%02x, found 0x%02x\n",
                        __func__, ether_sprintf(ni->ni_macaddr),
                        IEEE80211_ELEMID_HTINFO_ANA,
                        bo->bo_htinfo_vendor_specific[5] );
            }
#endif
            htinfo = &((struct vendor_ie_htinfo *)
                    bo->bo_htinfo_vendor_specific)->hi_ie;
            ieee80211_update_htinfo_cmn(htinfo, ni);
        }
    }
}

static void inline ieee80211_beacon_add_vhtcap(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;

    /* Add VHT cap if device is in 11ac operating mode (or)
     * 256QAM is enabled in 2.4G.
     */
    if (ieee80211_vap_wme_is_set(vap) &&
            (IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) ||
             IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
             IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)) &&
            ieee80211vap_vhtallowed(vap) &&
            (bo->bo_vhtcap != NULL) && (bo->bo_vhtop != NULL)) {

        /* Add VHT capabilities IE */
        ieee80211_add_vhtcap(bo->bo_vhtcap, ni, ic,
                IEEE80211_FC0_SUBTYPE_BEACON, NULL, NULL);

        /* Add VHT Operation IE */
        ieee80211_add_vhtop(bo->bo_vhtop, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON,
                NULL);

        /* Add VHT Tx Power Envelope IE */
        if (bo->bo_vhttxpwr && ieee80211_ic_doth_is_set(ic) &&
                ieee80211_vap_doth_is_set(vap)) {
            ieee80211_add_vht_txpwr_envlp(bo->bo_vhttxpwr, ni, ic,
                    IEEE80211_FC0_SUBTYPE_BEACON,
                    !IEEE80211_VHT_TXPWR_IS_SUB_ELEMENT);
        }
    }

    /* Add VHT Vendor specific IE for 256QAM support in 2.4G Interop */
    if (ieee80211_vap_wme_is_set(vap) &&
            (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
            IEEE80211_IS_CHAN_11NG(vap->iv_bsschan) &&
            ieee80211vap_vhtallowed(vap) &&
            ieee80211vap_11ng_vht_interopallowed(vap) &&
            (bo->bo_interop_vhtcap != NULL)) {
        /* Add VHT capabilities IE and VHT OP IE */
        ieee80211_add_interop_vhtcap(bo->bo_interop_vhtcap, ni, ic,
                IEEE80211_FC0_SUBTYPE_BEACON);
    }
}

static void ieee80211_add_he_cap(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic  = ni->ni_ic;

    if (ieee80211_vap_wme_is_set(vap) &&
            IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) &&
            ieee80211vap_heallowed(vap) &&
            (bo->bo_hecap != NULL) &&
            (bo->bo_heop != NULL)) {

        /* Add HE capabilities IE */
        ieee80211_add_hecap(bo->bo_hecap, ni, ic,
                IEEE80211_FC0_SUBTYPE_BEACON);

        /* Add HE Operation IE */
        ieee80211_add_heop(bo->bo_heop, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON,
                NULL);

        if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
            /* Add HE 6GHz Band Capabilities IE */
            ieee80211_add_6g_bandcap(bo->bo_he_6g_bandcap, ni, ic,
                    IEEE80211_FC0_SUBTYPE_BEACON);
        }
    }
}

static void ieee80211_beacon_add_bsscolor_change_ie(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int  *len_changed)
{
    struct ieee80211vap *vap = ni->ni_vap;
    uint8_t vdev_id =
           ((struct ol_ath_vap_net80211 *)OL_ATH_VAP_NET80211(vap))->av_if_id;

    QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
        "%s>> vdev-id: %d iv_he_bsscolor_change_ongoing: %s",  __func__,
        vdev_id, vap->iv_he_bsscolor_change_ongoing ? "true": "false");

    if (IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) &&
                    ieee80211vap_heallowed(vap) &&
                    vap->iv_he_bsscolor_change_ongoing) {
        ieee80211_add_he_bsscolor_change_ie(bo, wbuf, ni,
                IEEE80211_FC0_SUBTYPE_BEACON, len_changed);
        if(vap->iv_bcca_ie_status == BCCA_NA) {
            vap->iv_bcca_ie_status = BCCA_START;
        } else {
            vap->iv_bcca_ie_status = BCCA_ONGOING;
        }
    }
    QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
                                            "%s<<", __func__);
}

static void ieee80211_find_new_chan(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;

    if (ieee80211_ic_doth_is_set(ic) &&
            (ic->ic_flags & IEEE80211_F_CHANSWITCH) &&
            IEEE80211_CHANCHANGE_BY_BEACONUPDATE_IS_SET(ic)) {
        if (!(ic->ic_chanchange_channel)) {
            ic->ic_chanchange_channel =
                ieee80211_doth_findchan(vap, ic->ic_chanchange_chan_freq);
            if(!(ic->ic_chanchange_channel)) {
                /*
                 * Ideally we should not be here, Only reason is that we have
                 * a corrupt chan.
                 */
                QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                        "%s : Error chanchange is NULL: VAP = %d "
                        "chan freq = %d cfreq = %d flags = %llu",
                        __func__, vap->iv_unit, ic->ic_chanchange_chan_freq,
                        vap->iv_des_cfreq2,
                        (vap->iv_bsschan->ic_flags & IEEE80211_CHAN_ALL));
            } else {
                /* Find secondary 20 offset to advertise in beacon */
                ic->ic_chanchange_secoffset =
                    ieee80211_sec_chan_offset(ic->ic_chanchange_channel);
                /* Find destination channel width */
                ic->ic_chanchange_chwidth =
                    ieee80211_get_chan_width(ic->ic_chanchange_channel);
            }
        }
    }
}

static void inline ieee80211_beacon_update_tim(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        struct ieee80211_ath_tim_ie **tie,
        wbuf_t wbuf,
        int *len_changed,
        int mcast,
        int *is_dtim)
{
    struct ieee80211vap *vap = ni->ni_vap;

    if (vap->iv_opmode == IEEE80211_M_HOSTAP ||
            vap->iv_opmode == IEEE80211_M_IBSS) {
        *tie = (struct ieee80211_ath_tim_ie *) bo->bo_tim;

        if (IEEE80211_VAP_IS_TIMUPDATE_ENABLED(vap) &&
                vap->iv_opmode == IEEE80211_M_HOSTAP) {
            u_int timlen = 0;
            u_int timoff = 0;
            u_int i = 0;

            /*
             * ATIM/DTIM needs updating. If it fits in the current space
             * allocated then just copy in the new bits. Otherwise we need to
             * move any trailing data to make room. Note that we know there is
             * contiguous space because ieee80211_beacon_allocate insures there
             * is space in the wbuf to write a maximal-size virtual bitmap
             * (based on ic_max_aid).
             */
            /*
             * Calculate the bitmap size and offset, copy any trailer out of the
             * way, and then copy in the new bitmap and update the information
             * element. Note that the tim bitmap must contain at least one byte
             * and any offset must be even.
             */
            if (vap->iv_ps_pending != 0) {
                timoff = 128;        /* Impossibly large */
                for (i = 0; i < vap->iv_tim_len; i++) {
                    if (vap->iv_tim_bitmap[i]) {
                        timoff = i &~ 1;
                        break;
                    }
                }
                /* Remove the assert and do a recovery */
                /* KASSERT(timoff != 128, ("tim bitmap empty!")); */
                if (timoff == 128) {
                    timoff = 0;
                    timlen = 1;
                    qdf_print("Recover in TIM update");
                } else {
                    for (i = vap->iv_tim_len-1; i >= timoff; i--) {
                        if (vap->iv_tim_bitmap[i])
                            break;
                    }

                    if (i < timoff) {
                        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                                "Corrupted tim ie, recover in TIM update, "
                                "tim_len = %d, i = %d, timoff = %d",
                                vap->iv_tim_len, i, timoff);
                        timoff = 0;
                        timlen = 1;
                    } else {
                        timlen = 1 + (i - timoff);
                        /* Resetting the timlen if it goes beyond 68 limit
                         * (64 + 4 The 64 is to support 512 client 4 is a
                         * gaurd band.
                         */
                        if (timlen > 68) {
                            timoff = 0;
                            timlen = 1;
                            qdf_print("Recover in TIM update Invalid TIM length");
                        }
                    }
                }
            } else {
                timoff = 0;
                timlen = 1;
            }

            (*tie)->tim_bitctl = timoff;
            if (timlen != bo->bo_tim_len) {
                int trailer_adjust =
                    ((*tie)->tim_bitmap+timlen) - bo->bo_tim_trailer;

                /* copy up/down trailer */
                OS_MEMMOVE((*tie)->tim_bitmap+timlen, bo->bo_tim_trailer,
                        bo->bo_tim_trailerlen);
                bo->bo_tim_trailer = (*tie)->tim_bitmap+timlen;

                if (bo->bo_tim)
                    bo->bo_tim += trailer_adjust;

                if (bo->bo_pwrcnstr)
                    bo->bo_pwrcnstr += trailer_adjust;

                if (bo->bo_chanswitch)
                    bo->bo_chanswitch += trailer_adjust;

                if (bo->bo_quiet)
                    bo->bo_quiet += trailer_adjust;

                #if ATH_SUPPORT_IBSS_DFS
                    if (bo->bo_ibssdfs)
                        bo->bo_ibssdfs += trailer_adjust;
                #endif

                if (bo->bo_tpcreport) {
                    bo->bo_tpcreport += trailer_adjust;
                }

                if (bo->bo_erp)
                    bo->bo_erp += trailer_adjust;

                if (bo->bo_xrates)
                    bo->bo_xrates += trailer_adjust;

                if (bo->bo_rsn)
                    bo->bo_rsn += trailer_adjust;

                if (bo->bo_qbssload)
                    bo->bo_qbssload += trailer_adjust;

                if (bo->bo_edca)
                    bo->bo_edca += trailer_adjust;

                if (bo->bo_qos_cap)
                    bo->bo_qos_cap += trailer_adjust;

                if (bo->bo_ap_chan_rpt)
                    bo->bo_ap_chan_rpt += trailer_adjust;

                if (bo->bo_bss_avg_delay)
                    bo->bo_bss_avg_delay += trailer_adjust;

                if (bo->bo_antenna)
                    bo->bo_antenna += trailer_adjust;

                if (bo->bo_bss_adm_cap)
                    bo->bo_bss_adm_cap += trailer_adjust;

#ifndef ATH_SUPPORT_WAPI
                if (bo->bo_bss_ac_acc_delay)
                    bo->bo_bss_ac_acc_delay += trailer_adjust;
#endif

                if (bo->bo_msmt_pilot_tx)
                    bo->bo_msmt_pilot_tx += trailer_adjust;

                if (bo->bo_mob_domain)
                    bo->bo_mob_domain += trailer_adjust;

                if (bo->bo_dse_reg_loc)
                    bo->bo_dse_reg_loc += trailer_adjust;

                if (bo->bo_ecsa)
                    bo->bo_ecsa += trailer_adjust;

                if (bo->bo_opt_class)
                    bo->bo_opt_class += trailer_adjust;

                if (bo->bo_htcap)
                    bo->bo_htcap += trailer_adjust;

                if (bo->bo_htinfo)
                    bo->bo_htinfo += trailer_adjust;

                if (bo->bo_2040_coex)
                    bo->bo_2040_coex += trailer_adjust;

                if (bo->bo_obss_scan)
                    bo->bo_obss_scan += trailer_adjust;

                if (bo->bo_extcap)
                    bo->bo_extcap += trailer_adjust;

                #if UMAC_SUPPORT_WNM
                    if (bo->bo_fms_desc)
                        bo->bo_fms_desc += trailer_adjust;

                    if (bo->bo_fms_trailer)
                        bo->bo_fms_trailer += trailer_adjust;
                #endif

                if (bo->bo_qos_traffic)
                    bo->bo_qos_traffic += trailer_adjust;

                if (bo->bo_time_adv)
                    bo->bo_time_adv += trailer_adjust;

                if (bo->bo_interworking)
                    bo->bo_interworking += trailer_adjust;

                if (bo->bo_adv_proto)
                    bo->bo_adv_proto += trailer_adjust;

                if (bo->bo_roam_consortium)
                    bo->bo_roam_consortium += trailer_adjust;

                if (bo->bo_emergency_id)
                    bo->bo_emergency_id  += trailer_adjust;

                if (bo->bo_mesh_id)
                    bo->bo_mesh_id += trailer_adjust;

                if (bo->bo_mesh_conf)
                    bo->bo_mesh_conf += trailer_adjust;

                if (bo->bo_mesh_awake_win)
                    bo->bo_mesh_awake_win += trailer_adjust;

                if (bo->bo_beacon_time)
                    bo->bo_beacon_time += trailer_adjust;

                if (bo->bo_mccaop_adv_ov)
                    bo->bo_mccaop_adv_ov += trailer_adjust;

                if (bo->bo_mccaop_adv)
                    bo->bo_mccaop_adv += trailer_adjust;

                if (bo->bo_mesh_cs_param)
                    bo->bo_mesh_cs_param += trailer_adjust;

                if (bo->bo_qmf_policy)
                    bo->bo_qmf_policy += trailer_adjust;

                if (bo->bo_qload_rpt)
                    bo->bo_qload_rpt += trailer_adjust;

                if (bo->bo_hcca_upd_cnt)
                    bo->bo_hcca_upd_cnt += trailer_adjust;

                if (bo->bo_multiband)
                    bo->bo_multiband += trailer_adjust;

                if (bo->bo_vhtcap)
                    bo->bo_vhtcap += trailer_adjust;

                if (bo->bo_vhtop)
                    bo->bo_vhtop += trailer_adjust;

                if (bo->bo_vhttxpwr)
                    bo->bo_vhttxpwr += trailer_adjust;

                if (bo->bo_vhtchnsw)
                    bo->bo_vhtchnsw += trailer_adjust;

                if (bo->bo_ext_bssload)
                    bo->bo_ext_bssload += trailer_adjust;

                if (bo->bo_quiet_chan)
                    bo->bo_quiet_chan += trailer_adjust;

                if (bo->bo_opt_mode_note)
                    bo->bo_opt_mode_note += trailer_adjust;

                if (vap->rnr_enable)
                    vap->rnr_enable += trailer_adjust;

                if (bo->bo_tvht)
                    bo->bo_tvht += trailer_adjust;

#if QCN_ESP_IE
                if (bo->bo_esp_ie)
                    bo->bo_esp_ie += trailer_adjust;
#endif

                if (bo->bo_future_chan)
                    bo->bo_future_chan += trailer_adjust;

                if (bo->bo_cag_num)
                    bo->bo_cag_num += trailer_adjust;

                if (bo->bo_fils_ind)
                    bo->bo_fils_ind += trailer_adjust;

                if (bo->bo_ap_csn)
                    bo->bo_ap_csn += trailer_adjust;

                if (bo->bo_diff_init_lnk)
                    bo->bo_diff_init_lnk += trailer_adjust;

                if (bo->bo_service_hint)
                    bo->bo_service_hint += trailer_adjust;

                if (bo->bo_service_hash)
                    bo->bo_service_hash += trailer_adjust;

                if (bo->bo_hecap)
                    bo->bo_hecap += trailer_adjust;

                if (bo->bo_heop)
                    bo->bo_heop += trailer_adjust;

                if (bo->bo_twt)
                    bo->bo_twt += trailer_adjust;

#if ATH_SUPPORT_UORA
                if (bo->bo_uora_param)
                    bo->bo_uora_param += trailer_adjust;
#endif

                if (bo->bo_bcca)
                    bo->bo_bcca += trailer_adjust;

#if OBSS_PD
                if(bo->bo_srp_ie)
                    bo->bo_srp_ie += trailer_adjust;
#endif

                if (bo->bo_muedca)
                    bo->bo_muedca += trailer_adjust;

                if (bo->bo_ess_rpt)
                    bo->bo_ess_rpt += trailer_adjust;

                if (bo->bo_ndp_rpt_param)
                    bo->bo_ndp_rpt_param += trailer_adjust;

                if (bo->bo_he_bss_load)
                    bo->bo_he_bss_load += trailer_adjust;

                if (bo->bo_he_6g_bandcap)
                    bo->bo_he_6g_bandcap += trailer_adjust;

                if (bo->bo_mcst)
                    bo->bo_mcst += trailer_adjust;

                if (bo->bo_secchanoffset)
                    bo->bo_secchanoffset += trailer_adjust;

                if (bo->bo_rsnx)
                    bo->bo_rsnx += trailer_adjust;

                if (bo->bo_ath_caps)
                    bo->bo_ath_caps += trailer_adjust;

                if (bo->bo_extender_ie)
                    bo->bo_extender_ie += trailer_adjust;

                if (bo->bo_htinfo_vendor_specific)
                    bo->bo_htinfo_vendor_specific += trailer_adjust;

                if (bo->bo_mbo_cap )
                    bo->bo_mbo_cap  += trailer_adjust;

                if (bo->bo_apriori_next_channel)
                    bo->bo_apriori_next_channel += trailer_adjust;

                if (bo->bo_bwnss_map)
                    bo->bo_bwnss_map += trailer_adjust;

#if QCN_IE
                if (bo->bo_qcn_ie)
                    bo->bo_qcn_ie += trailer_adjust;
#endif

                if (bo->bo_software_version_ie)
                    bo->bo_software_version_ie += trailer_adjust;

                if (bo->bo_xr)
                    bo->bo_xr += trailer_adjust;

                if (bo->bo_whc_apinfo)
                    bo->bo_whc_apinfo += trailer_adjust;

                if (bo->bo_interop_vhtcap)
                    bo->bo_interop_vhtcap += trailer_adjust;

                if (bo->bo_wme)
                    bo->bo_wme += trailer_adjust;

                if (bo->bo_appie_buf)
                    bo->bo_appie_buf += trailer_adjust;

                if (timlen > bo->bo_tim_len)
                    wbuf_append(wbuf, timlen - bo->bo_tim_len);
                else
                    wbuf_trim(wbuf, bo->bo_tim_len - timlen);

                bo->bo_tim_len = timlen;
                /* Update information element */
                (*tie)->tim_len = 3 + timlen;
                *len_changed = 1;
            }

            OS_MEMCPY((*tie)->tim_bitmap, vap->iv_tim_bitmap + timoff,
                    bo->bo_tim_len);

            IEEE80211_VAP_TIMUPDATE_DISABLE(vap);

            IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni,
                    "%s: TIM updated, pending %u, off %u, len %u\n",
                    __func__, vap->iv_ps_pending, timoff, timlen);
        }

        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            /* Count down DTIM period */
            if ((*tie)->tim_count == 0)
                (*tie)->tim_count = (*tie)->tim_period - 1;
            else
                (*tie)->tim_count--;

            /* Update state for buffered multicast frames on DTIM */
            if (mcast && ((*tie)->tim_count == 0 || (*tie)->tim_period == 1))
                (*tie)->tim_bitctl |= 1;
            else
                (*tie)->tim_bitctl &= ~1;

        }
#if UMAC_SUPPORT_WNM
        *is_dtim = ((*tie)->tim_count == 0 || (*tie)->tim_period == 1);
#endif
    }
}

static void ieee80211_send_chan_switch_action(struct ieee80211_node *ni)
{
        struct ieee80211vap *vap = ni->ni_vap;
        struct ieee80211_action_mgt_args *actionargs;

        actionargs = OS_MALLOC(vap->iv_ic->ic_osdev, sizeof(struct ieee80211_action_mgt_args) , GFP_KERNEL);
        if (actionargs == NULL) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: Unable to alloc arg buf. Size=%d\n",
                     __func__, sizeof(struct ieee80211_action_mgt_args));
        } else {
            OS_MEMZERO(actionargs, sizeof(struct ieee80211_action_mgt_args));

            actionargs->category = IEEE80211_ACTION_CAT_SPECTRUM;
            actionargs->action   = IEEE80211_ACTION_CHAN_SWITCH;
            ieee80211_send_action(ni, actionargs, NULL);
            OS_FREE(actionargs);
        }
}

static void ieee80211_beacon_add_chan_switch_ie(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int *len_changed)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;

    if (vap->iv_opmode == IEEE80211_M_HOSTAP ||
            vap->iv_opmode == IEEE80211_M_IBSS) {

        /* Find the new channel if it's not known already */
        ieee80211_find_new_chan(vap);

        if (ieee80211_ic_doth_is_set(ic) &&
                (ic->ic_flags & IEEE80211_F_CHANSWITCH) &&
                (ic->ic_chanchange_channel) &&
                IEEE80211_CHANCHANGE_BY_BEACONUPDATE_IS_SET(ic)) {
            ieee80211_add_channel_switch_ie(ni, bo, wbuf, len_changed);
            if (*len_changed == 1)
                ieee80211_send_chan_switch_action(ni);
        }
    }
}

#if ATH_SUPPORT_IBSS_DFS
static int ieee80211_beacon_update_ibss_dfs(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int *len_changed)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_ibssdfs_ie *ibss_ie = NULL;

    if (vap->iv_opmode == IEEE80211_M_IBSS &&
            (ic->ic_curchan->ic_flagext & IEEE80211_CHAN_DFS)) {

        /*reset action frames counts for measrep and csa action */
        vap->iv_measrep_action_count_per_tbtt = 0;
        vap->iv_csa_action_count_per_tbtt = 0;

        if(vap->iv_ibssdfs_state == IEEE80211_IBSSDFS_OWNER)
            vap->iv_ibssdfs_ie_data.rec_interval =
                vap->iv_ibss_dfs_enter_recovery_threshold_in_tbtt;

        ibss_ie =(struct ieee80211_ibssdfs_ie *) bo->bo_ibssdfs;
        if(ibss_ie) {
            if (OS_MEMCMP(bo->bo_ibssdfs, &vap->iv_ibssdfs_ie_data,
                        ibss_ie->len + sizeof(struct ieee80211_ie_header))) {
                int trailer_adjust =
                    vap->iv_ibssdfs_ie_data.len - ibss_ie->len;

                /* Copy up/down trailer */
                if(trailer_adjust > 0) {
                    uint8_t *tempbuf;

                    tempbuf = OS_MALLOC(vap->iv_ic->ic_osdev,
                            bo->bo_ibssdfs_trailerlen , GFP_KERNEL);
                    if (tempbuf == NULL) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                                "%s: Unable to alloc ibssdfs copy buf. Size=%d\n",
                                __func__, bo->bo_ibssdfs_trailerlen);
                        return -1;
                    }

                    OS_MEMCPY(tempbuf, (bo->bo_ibssdfs +
                                sizeof(struct ieee80211_ie_header) +
                                ibss_ie->len),
                            bo->bo_ibssdfs_trailerlen);

                    OS_MEMCPY((bo->bo_ibssdfs +
                                sizeof(struct ieee80211_ie_header) +
                                vap->iv_ibssdfs_ie_data.len), tempbuf,
                            bo->bo_ibssdfs_trailerlen);
                    OS_FREE(tempbuf);
                } else {
                    OS_MEMCPY((bo->bo_ibssdfs +
                                sizeof(struct ieee80211_ie_header) +
                                vap->iv_ibssdfs_ie_data.len),
                            (bo->bo_ibssdfs +
                             sizeof(struct ieee80211_ie_header) + ibss_ie->len),
                            bo->bo_ibssdfs_trailerlen);
                }

                bo->bo_tim_trailerlen += trailer_adjust;
                bo->bo_chanswitch_trailerlen += trailer_adjust;
                bo->bo_ecsa_trailerlen += trailer_adjust;
                bo->bo_vhtchnsw_trailerlen += trailer_adjust;
                bo->bo_mcst_trailerlen += trailer_adjust;
                bo->bo_secchanoffset_trailerlen += trailer_adjust;

                if (bo->bo_tpcreport) {
                    bo->bo_tpcreport += trailer_adjust;
                }

                if (bo->bo_erp)
                    bo->bo_erp += trailer_adjust;

                if (bo->bo_xrates)
                    bo->bo_xrates += trailer_adjust;

                if (bo->bo_rsn)
                    bo->bo_rsn += trailer_adjust;

                if (bo->bo_qbssload)
                    bo->bo_qbssload += trailer_adjust;

                if (bo->bo_edca)
                    bo->bo_edca += trailer_adjust;

                if (bo->bo_qos_cap)
                    bo->bo_qos_cap += trailer_adjust;

                if (bo->bo_ap_chan_rpt)
                    bo->bo_ap_chan_rpt += trailer_adjust;

                if (bo->bo_bss_avg_delay)
                    bo->bo_bss_avg_delay += trailer_adjust;

                if (bo->bo_antenna)
                    bo->bo_antenna += trailer_adjust;

                if (bo->bo_bss_adm_cap)
                    bo->bo_bss_adm_cap += trailer_adjust;

#ifndef ATH_SUPPORT_WAPI
                if (bo->bo_bss_ac_acc_delay)
                    bo->bo_bss_ac_acc_delay += trailer_adjust;
#endif

                if (bo->bo_msmt_pilot_tx)
                    bo->bo_msmt_pilot_tx += trailer_adjust;

                if (bo->bo_mob_domain)
                    bo->bo_mob_domain += trailer_adjust;

                if (bo->bo_dse_reg_loc)
                    bo->bo_dse_reg_loc += trailer_adjust;

                if (bo->bo_ecsa)
                    bo->bo_ecsa += trailer_adjust;

                if (bo->bo_opt_class)
                    bo->bo_opt_class += trailer_adjust;

                if (bo->bo_htcap)
                    bo->bo_htcap += trailer_adjust;

                if (bo->bo_htinfo)
                    bo->bo_htinfo += trailer_adjust;

                if (bo->bo_2040_coex)
                    bo->bo_2040_coex += trailer_adjust;

                if (bo->bo_obss_scan)
                    bo->bo_obss_scan += trailer_adjust;

                if (bo->bo_extcap)
                    bo->bo_extcap += trailer_adjust;

                #if UMAC_SUPPORT_WNM
                    if (bo->bo_fms_desc)
                        bo->bo_fms_desc += trailer_adjust;

                    if (bo->bo_fms_trailer)
                        bo->bo_fms_trailer += trailer_adjust;
                #endif

                if (bo->bo_qos_traffic)
                    bo->bo_qos_traffic += trailer_adjust;

                if (bo->bo_time_adv)
                    bo->bo_time_adv += trailer_adjust;

                if (bo->bo_interworking)
                    bo->bo_interworking += trailer_adjust;

                if (bo->bo_adv_proto)
                    bo->bo_adv_proto += trailer_adjust;

                if (bo->bo_roam_consortium)
                    bo->bo_roam_consortium += trailer_adjust;

                if (bo->bo_emergency_id)
                    bo->bo_emergency_id  += trailer_adjust;

                if (bo->bo_mesh_id)
                    bo->bo_mesh_id += trailer_adjust;

                if (bo->bo_mesh_conf)
                    bo->bo_mesh_conf += trailer_adjust;

                if (bo->bo_mesh_awake_win)
                    bo->bo_mesh_awake_win += trailer_adjust;

                if (bo->bo_beacon_time)
                    bo->bo_beacon_time += trailer_adjust;

                if (bo->bo_mccaop_adv_ov)
                    bo->bo_mccaop_adv_ov += trailer_adjust;

                if (bo->bo_mccaop_adv)
                    bo->bo_mccaop_adv += trailer_adjust;

                if (bo->bo_mesh_cs_param)
                    bo->bo_mesh_cs_param += trailer_adjust;

                if (bo->bo_qmf_policy)
                    bo->bo_qmf_policy += trailer_adjust;

                if (bo->bo_qload_rpt)
                    bo->bo_qload_rpt += trailer_adjust;

                if (bo->bo_hcca_upd_cnt)
                    bo->bo_hcca_upd_cnt += trailer_adjust;

                if (bo->bo_multiband)
                    bo->bo_multiband += trailer_adjust;

                if (bo->bo_vhtcap)
                    bo->bo_vhtcap += trailer_adjust;

                if (bo->bo_vhtop)
                    bo->bo_vhtop += trailer_adjust;

                if (bo->bo_vhttxpwr)
                    bo->bo_vhttxpwr += trailer_adjust;

                if (bo->bo_vhtchnsw)
                    bo->bo_vhtchnsw += trailer_adjust;

                if (bo->bo_ext_bssload)
                    bo->bo_ext_bssload += trailer_adjust;

                if (bo->bo_quiet_chan)
                    bo->bo_quiet_chan += trailer_adjust;

                if (bo->bo_opt_mode_note)
                    bo->bo_opt_mode_note += trailer_adjust;

                if (vap->rnr_enable)
                    vap->rnr_enable += trailer_adjust;

                if (bo->bo_tvht)
                    bo->bo_tvht += trailer_adjust;

#if QCN_ESP_IE
                if (bo->bo_esp_ie)
                    bo->bo_esp_ie += trailer_adjust;
#endif

                if (bo->bo_future_chan)
                    bo->bo_future_chan += trailer_adjust;

                if (bo->bo_cag_num)
                    bo->bo_cag_num += trailer_adjust;

                if (bo->bo_fils_ind)
                    bo->bo_fils_ind += trailer_adjust;

                if (bo->bo_ap_csn)
                    bo->bo_ap_csn += trailer_adjust;

                if (bo->bo_diff_init_lnk)
                    bo->bo_diff_init_lnk += trailer_adjust;

                if (bo->bo_service_hint)
                    bo->bo_service_hint += trailer_adjust;

                if (bo->bo_service_hash)
                    bo->bo_service_hash += trailer_adjust;

                if (bo->bo_hecap)
                    bo->bo_hecap += trailer_adjust;

                if (bo->bo_heop)
                    bo->bo_heop += trailer_adjust;

                if (bo->bo_twt)
                    bo->bo_twt += trailer_adjust;

#if ATH_SUPPORT_UORA
                if (bo->bo_uora_param)
                    bo->bo_uora_param += trailer_adjust;
#endif

                if (bo->bo_bcca)
                    bo->bo_bcca += trailer_adjust;

#if OBSS_PD
                if(bo->bo_srp_ie)
                    bo->bo_srp_ie += trailer_adjust;
#endif

                if (bo->bo_muedca)
                    bo->bo_muedca += trailer_adjust;

                if (bo->bo_ess_rpt)
                    bo->bo_ess_rpt += trailer_adjust;

                if (bo->bo_ndp_rpt_param)
                    bo->bo_ndp_rpt_param += trailer_adjust;

                if (bo->bo_he_bss_load)
                    bo->bo_he_bss_load += trailer_adjust;

                if (bo->bo_he_6g_bandcap)
                    bo->bo_he_6g_bandcap += trailer_adjust;

                if (bo->bo_mcst)
                    bo->bo_mcst += trailer_adjust;

                if (bo->bo_secchanoffset)
                    bo->bo_secchanoffset += trailer_adjust;

                if (bo->bo_rsnx)
                    bo->bo_rsnx += trailer_adjust;

                if (bo->bo_ath_caps)
                    bo->bo_ath_caps += trailer_adjust;

                if (bo->bo_extender_ie)
                    bo->bo_extender_ie += trailer_adjust;

                if (bo->bo_htinfo_vendor_specific)
                    bo->bo_htinfo_vendor_specific += trailer_adjust;

                if (bo->bo_mbo_cap )
                    bo->bo_mbo_cap  += trailer_adjust;

                if (bo->bo_apriori_next_channel)
                    bo->bo_apriori_next_channel += trailer_adjust;

                if (bo->bo_bwnss_map)
                    bo->bo_bwnss_map += trailer_adjust;

#if QCN_IE
                if (bo->bo_qcn_ie)
                    bo->bo_qcn_ie += trailer_adjust;
#endif

                if (bo->bo_software_version_ie)
                    bo->bo_software_version_ie += trailer_adjust;

                if (bo->bo_xr)
                    bo->bo_xr += trailer_adjust;

                if (bo->bo_whc_apinfo)
                    bo->bo_whc_apinfo += trailer_adjust;

                if (bo->bo_interop_vhtcap)
                    bo->bo_interop_vhtcap += trailer_adjust;

                if (bo->bo_wme)
                    bo->bo_wme += trailer_adjust;

                if (bo->bo_appie_buf)
                    bo->bo_appie_buf += trailer_adjust;

                if (trailer_adjust >  0)
                    wbuf_append(wbuf, trailer_adjust);
                else
                    wbuf_trim(wbuf, -trailer_adjust);

                OS_MEMCPY(bo->bo_ibssdfs, &vap->iv_ibssdfs_ie_data,
                        (sizeof(struct ieee80211_ie_header) +
                         vap->iv_ibssdfs_ie_data.len));
                *len_changed = 1;
            }
        }
        if (vap->iv_ibssdfs_state == IEEE80211_IBSSDFS_JOINER ||
                vap->iv_ibssdfs_state == IEEE80211_IBSSDFS_OWNER) {
            vap->iv_ibssdfs_recovery_count =
                vap->iv_ibssdfs_ie_data.rec_interval;
        } else if (vap->iv_ibssdfs_state ==
                IEEE80211_IBSSDFS_WAIT_RECOVERY) {
            vap->iv_ibssdfs_recovery_count --;

            if(vap->iv_ibssdfs_recovery_count == 0) {
                IEEE80211_ADDR_COPY(vap->iv_ibssdfs_ie_data.owner,
                        vap->iv_myaddr);
                vap->iv_ibssdfs_state = IEEE80211_IBSSDFS_OWNER;
                vap->iv_ibssdfs_recovery_count =
                    vap->iv_ibssdfs_ie_data.rec_interval;

                if(!vap->iv_ibss_dfs_no_channel_switch) {
                    IEEE80211_RADAR_FOUND_LOCK(ic);
                    ieee80211_dfs_action(vap, NULL, false);
                    IEEE80211_RADAR_FOUND_UNLOCK(ic);
                }

                vap->iv_ibss_dfs_no_channel_switch = false;
            }
        }
    }
    return 0;
}
#endif

static void ieee80211_beacon_erp_update(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211com *ic = vap->iv_ic;

    if (((vap->iv_opmode == IEEE80211_M_HOSTAP) &&
                (IEEE80211_IS_CHAN_ANYG(vap->iv_bsschan) ||
                 IEEE80211_IS_CHAN_11NG(vap->iv_bsschan) ||
                 IEEE80211_IS_CHAN_11AXG(vap->iv_bsschan)) ) ||
            vap->iv_opmode == IEEE80211_M_BTAMP) { /* No IBSS Support */

        if (ieee80211_vap_erpupdate_is_set(vap) && bo->bo_erp) {
            ieee80211_add_erp(bo->bo_erp, ic);
            ieee80211_vap_erpupdate_clear(vap);
        }
    }
}

#if UMAC_SUPPORT_WNM
static int ieee80211_beacon_add_wnm_ie(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        struct ieee80211_ath_tim_ie *tie,
        wbuf_t wbuf,
        int *is_dtim,
        uint32_t nfmsq_mask)
{
    struct ieee80211vap *vap = ni->ni_vap;
    uint32_t fms_counter_mask = 0;
    uint8_t *fmsie = NULL;
    uint8_t fmsie_len = 0;

    /* Add WNM specific IEs (like FMS desc...), if supported */
    if (ieee80211_vap_wnm_is_set(vap) &&
            ieee80211_wnm_fms_is_set(vap->wnm) &&
            vap->iv_opmode == IEEE80211_M_HOSTAP &&
            (bo->bo_fms_desc) && (bo->bo_fms_trailer)) {
        ieee80211_wnm_setup_fmsdesc_ie(ni, *is_dtim, &fmsie, &fmsie_len,
                &fms_counter_mask);

        if (fmsie_len != bo->bo_fms_len) {
            uint8_t *new_fms_trailer = (bo->bo_fms_desc + fmsie_len);
            int trailer_adjust =  new_fms_trailer - bo->bo_fms_trailer;

            /* Copy up/down trailer */
            if(trailer_adjust > 0) {
                uint8_t *tempbuf;

                tempbuf = OS_MALLOC(vap->iv_ic->ic_osdev,
                        bo->bo_fms_trailerlen , GFP_KERNEL);
                if (tempbuf == NULL) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                            "%s: Unable to alloc FMS copy buf. Size=%d\n",
                            __func__, bo->bo_fms_trailerlen);
                    return -1;
                }

                OS_MEMCPY(tempbuf, bo->bo_fms_trailer, bo->bo_fms_trailerlen);
                OS_MEMCPY(new_fms_trailer, tempbuf, bo->bo_fms_trailerlen);
                OS_FREE(tempbuf);
            } else {
                OS_MEMCPY(new_fms_trailer, bo->bo_fms_trailer,
                        bo->bo_fms_trailerlen);
            }

            bo->bo_tim_trailerlen += trailer_adjust;
            bo->bo_chanswitch_trailerlen += trailer_adjust;
            bo->bo_ecsa_trailerlen += trailer_adjust;
            bo->bo_vhtchnsw_trailerlen += trailer_adjust;
            bo->bo_mcst_trailerlen += trailer_adjust;
#if ATH_SUPPORT_IBSS_DFS
            bo->bo_ibssdfs_trailerlen += trailer_adjust;
#endif /* ATH_SUPPORT_IBSS_DFS */

#if UMAC_SUPPORT_WNM
            bo->bo_fms_trailerlen += trailer_adjust;
#endif /* UMAC_SUPPORT_WNM */

            bo->bo_fms_trailer = new_fms_trailer;
            if (bo->bo_qos_traffic)
                bo->bo_qos_traffic += trailer_adjust;

            if (bo->bo_time_adv)
                bo->bo_time_adv += trailer_adjust;

            if (bo->bo_interworking)
                bo->bo_interworking += trailer_adjust;

            if (bo->bo_adv_proto)
                bo->bo_adv_proto += trailer_adjust;

            if (bo->bo_roam_consortium)
                bo->bo_roam_consortium += trailer_adjust;

            if (bo->bo_emergency_id)
                bo->bo_emergency_id  += trailer_adjust;

            if (bo->bo_mesh_id)
                bo->bo_mesh_id += trailer_adjust;

            if (bo->bo_mesh_conf)
                bo->bo_mesh_conf += trailer_adjust;

            if (bo->bo_mesh_awake_win)
                bo->bo_mesh_awake_win += trailer_adjust;

            if (bo->bo_beacon_time)
                bo->bo_beacon_time += trailer_adjust;

            if (bo->bo_mccaop_adv_ov)
                bo->bo_mccaop_adv_ov += trailer_adjust;

            if (bo->bo_mccaop_adv)
                bo->bo_mccaop_adv += trailer_adjust;

            if (bo->bo_mesh_cs_param)
                bo->bo_mesh_cs_param += trailer_adjust;

            if (bo->bo_qmf_policy)
                bo->bo_qmf_policy += trailer_adjust;

            if (bo->bo_qload_rpt)
                bo->bo_qload_rpt += trailer_adjust;

            if (bo->bo_hcca_upd_cnt)
                bo->bo_hcca_upd_cnt += trailer_adjust;

            if (bo->bo_multiband)
                bo->bo_multiband += trailer_adjust;

            if (bo->bo_vhtcap)
                bo->bo_vhtcap += trailer_adjust;

            if (bo->bo_vhtop)
                bo->bo_vhtop += trailer_adjust;

            if (bo->bo_vhttxpwr)
                bo->bo_vhttxpwr += trailer_adjust;

            if (bo->bo_vhtchnsw)
                bo->bo_vhtchnsw += trailer_adjust;

            if (bo->bo_ext_bssload)
                bo->bo_ext_bssload += trailer_adjust;

            if (bo->bo_quiet_chan)
                bo->bo_quiet_chan += trailer_adjust;

            if (bo->bo_opt_mode_note)
                bo->bo_opt_mode_note += trailer_adjust;

            if (vap->rnr_enable)
                vap->rnr_enable += trailer_adjust;

            if (bo->bo_tvht)
                bo->bo_tvht += trailer_adjust;

#if QCN_ESP_IE
            if (bo->bo_esp_ie)
                bo->bo_esp_ie += trailer_adjust;
#endif

            if (bo->bo_future_chan)
                bo->bo_future_chan += trailer_adjust;

            if (bo->bo_cag_num)
                bo->bo_cag_num += trailer_adjust;

            if (bo->bo_fils_ind)
                bo->bo_fils_ind += trailer_adjust;

            if (bo->bo_ap_csn)
                bo->bo_ap_csn += trailer_adjust;

            if (bo->bo_diff_init_lnk)
                bo->bo_diff_init_lnk += trailer_adjust;

            if (bo->bo_service_hint)
                bo->bo_service_hint += trailer_adjust;

            if (bo->bo_service_hash)
                bo->bo_service_hash += trailer_adjust;

            if (bo->bo_hecap)
                bo->bo_hecap += trailer_adjust;

            if (bo->bo_heop)
                bo->bo_heop += trailer_adjust;

            if (bo->bo_twt)
                bo->bo_twt += trailer_adjust;

#if ATH_SUPPORT_UORA
            if (bo->bo_uora_param)
                bo->bo_uora_param += trailer_adjust;
#endif

            if (bo->bo_bcca)
                bo->bo_bcca += trailer_adjust;

#if OBSS_PD
            if(bo->bo_srp_ie)
                bo->bo_srp_ie += trailer_adjust;
#endif

            if (bo->bo_muedca)
                bo->bo_muedca += trailer_adjust;

            if (bo->bo_ess_rpt)
                bo->bo_ess_rpt += trailer_adjust;

            if (bo->bo_ndp_rpt_param)
                bo->bo_ndp_rpt_param += trailer_adjust;

            if (bo->bo_he_bss_load)
                bo->bo_he_bss_load += trailer_adjust;

            if (bo->bo_mcst)
                bo->bo_mcst += trailer_adjust;

            if (bo->bo_secchanoffset)
                bo->bo_secchanoffset += trailer_adjust;

            if (bo->bo_rsnx)
                bo->bo_rsnx += trailer_adjust;

            if (bo->bo_ath_caps)
                bo->bo_ath_caps += trailer_adjust;

            if (bo->bo_extender_ie)
                bo->bo_extender_ie += trailer_adjust;

            if (bo->bo_htinfo_vendor_specific)
                bo->bo_htinfo_vendor_specific += trailer_adjust;

            if (bo->bo_mbo_cap )
                bo->bo_mbo_cap  += trailer_adjust;

            if (bo->bo_apriori_next_channel)
                bo->bo_apriori_next_channel += trailer_adjust;

            if (bo->bo_bwnss_map)
                bo->bo_bwnss_map += trailer_adjust;

#if QCN_IE
            if (bo->bo_qcn_ie)
                bo->bo_qcn_ie += trailer_adjust;
#endif

            if (bo->bo_software_version_ie)
                bo->bo_software_version_ie += trailer_adjust;

            if (bo->bo_xr)
                bo->bo_xr += trailer_adjust;

            if (bo->bo_whc_apinfo)
                bo->bo_whc_apinfo += trailer_adjust;

            if (bo->bo_interop_vhtcap)
                bo->bo_interop_vhtcap += trailer_adjust;

            if (bo->bo_wme)
                bo->bo_wme += trailer_adjust;

            if (bo->bo_appie_buf)
                bo->bo_appie_buf += trailer_adjust;


            if (fmsie_len > bo->bo_fms_len)
                wbuf_append(wbuf, fmsie_len - bo->bo_fms_len);
            else
                wbuf_trim(wbuf, bo->bo_fms_len - fmsie_len);

            bo->bo_fms_len = fmsie_len;
        }

        if (fmsie_len &&  (bo->bo_fms_desc) && (bo->bo_fms_trailer)) {
            OS_MEMCPY(bo->bo_fms_desc, fmsie, fmsie_len);
            bo->bo_fms_trailer = bo->bo_fms_desc + fmsie_len;
            bo->bo_fms_len = fmsie_len;
        }

        if (tie != NULL) {
            /* Update state for buffered multicast frames on DTIM */
            if (nfmsq_mask & fms_counter_mask)
                tie->tim_bitctl |= 1;
        }
    }

    return 0;
}
#endif /* UMAC_SUPPORT_WNM */

static void ieee80211_add_apriori_next_chan(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211com *ic = ni->ni_ic;

    if(IEEE80211_IS_CSH_OPT_APRIORI_NEXT_CHANNEL_ENABLED(ic) &&
            IEEE80211_IS_CHAN_DFS(ic->ic_curchan)) {
        if(bo->bo_apriori_next_channel && ic->ic_tx_next_ch)
            ieee80211_add_next_channel(bo->bo_apriori_next_channel, ni, ic,
                    IEEE80211_FC0_SUBTYPE_BEACON);
    }
}

/* Add APP_IE buffer if app updated it */
static void ieee80211_beacon_add_app_ie(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int *len_changed,
        bool *update_beacon_copy)
{
    uint8_t *frm_buf = NULL, *temp = NULL;
    uint8_t len = 0;

#ifdef ATH_BEACON_DEFERRED_PROC
    IEEE80211_VAP_LOCK(vap);
#endif


    if (IEEE80211_VAP_IS_APPIE_UPDATE_ENABLED(vap)) {
        /* Update RSN IE */
        if (bo->bo_rsn) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_RSN, false,
                &bo->bo_rsn, TYPE_APP_IE_BUF, NULL, true);
            /* Reset bo_rsn to start because the function call has moved it "len" bytes */
            bo->bo_rsn -= len;
        }

        /* Update Mobility Domain IE */
        if (bo->bo_mob_domain) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_MOBILITY_DOMAIN, false,
                &bo->bo_mob_domain, TYPE_APP_IE_BUF, NULL, true);
            /* Reset bo_mob_domain to start because the function call has moved it "len" bytes */
            bo->bo_mob_domain -= len;
        }

        /* Update Interworking IE */
        if (bo->bo_interworking) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_INTERWORKING, false,
                &bo->bo_interworking, TYPE_APP_IE_BUF, NULL, true);
            /* Reset bo_interworking to start because the function call has moved it "len" bytes */
            bo->bo_interworking -= len;
        }

        /* UPdate Advertisement Protocol IE */
        if (bo->bo_adv_proto) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_ADVERTISEMENT_PROTO, false,
                &bo->bo_adv_proto, TYPE_APP_IE_BUF, NULL, true);
            /* Reset bo_adv_proto to start because the function call has moved it "len" bytes */
            bo->bo_adv_proto -= len;
        }

        /* Update Roaming Consortium IE */
        if (bo->bo_roam_consortium) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_ROAMING_CONSORTIUM, false,
                &bo->bo_roam_consortium, TYPE_APP_IE_BUF, NULL, true);
            /* Reset bo_roam_consortium to start because the function call has moved it "len" bytes */
            bo->bo_roam_consortium -= len;
        }

        /* Update CF params IE */
        if (bo->bo_cf_params) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_CFPARMS, -1, &bo->bo_cf_params,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_cf_params to start because the function call has moved it "len" bytes */
            bo->bo_cf_params -=len;
        }

        /* Update EDCA param IE */
        if (bo->bo_edca) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_EDCA, -1, &bo->bo_edca,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_edca to start because the function call has moved it "len" bytes */
            bo->bo_edca -= len;
        }

        /* Update QoS Capability IE */
        if (bo->bo_qos_cap) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_QOS_CAP, -1, &bo->bo_qos_cap,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_qos_cap to start because the function call has moved it "len" bytes */
            bo->bo_qos_cap -= len;
        }

        /* Update BSS Average Access Delay IE */
        if (bo->bo_bss_avg_delay) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_BSS_AVG_ACCESS_DELAY,
                    0, &bo->bo_bss_avg_delay, TYPE_ALL_BUF, NULL, true);
            /* Reset bo_bss_avg_delay to start because the function call has moved it "len" bytes */
            bo->bo_bss_avg_delay -= len;
        }

        /* Update Antenna IE */
        if (bo->bo_antenna) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_ANTENNA, -1, &bo->bo_antenna,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_antenna to start because the function call has moved it "len" bytes */
            bo->bo_antenna -= len;
        }

        /* Update BSS Available Admission Caapcity IE */
        if (bo->bo_bss_adm_cap) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_BSS_ADMISSION_CAP, -1, &bo->bo_bss_adm_cap,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_bss_adm_cap to start because the function call has moved it "len" bytes */
            bo->bo_bss_adm_cap -= len;
        }

#ifndef ATH_SUPPORT_WAPI
        if (bo->bo_bss_ac_acc_delay) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_BSS_AC_ACCESS_DELAY, -1, &bo->bo_bss_ac_acc_delay,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_bss_ac_acc_delay to start because the function call has moved it "len" bytes */
            bo->bo_bss_ac_acc_delay -= len;
        }
#endif

        /* Update Measurement Pilot Transmissions IE */
        if (bo->bo_msmt_pilot_tx) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_MESUREMENT_PILOT_TX, -1, &bo->bo_msmt_pilot_tx,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_msmt_pilot_tx to start because the function call has moved it "len" bytes */
            bo->bo_msmt_pilot_tx -= len;
        }

        /* Update DSE Registered Location IE */
        if (bo->bo_dse_reg_loc) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_DSE_REG_LOCATION, -1, &bo->bo_dse_reg_loc,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_dse_reg_loc to start because the function call has moved it "len" bytes */
            bo->bo_dse_reg_loc -= len;
        }

        /* Update Supported Operating Classes IE */
        if (bo->bo_opt_class) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_SUPP_OP_CLASS, -1, &bo->bo_opt_class,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_opt_class to start because the function call has moved it "len" bytes */
            bo->bo_opt_class -= len;
        }

        /* Update 20/40 BSS Coexistence IE */
        if (bo->bo_2040_coex) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_2040_COEXT, -1, &bo->bo_2040_coex,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_2040_coex to start because the function call has moved it "len" bytes */
            bo->bo_2040_coex -= len;
        }

        /* Update QoS Traffic Capability IE */
        if (bo->bo_qos_traffic) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_QOS_TRAFFIC_CAP, -1, &bo->bo_qos_traffic,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_qos_traffic to start because the function call has moved it "len" bytes */
            bo->bo_qos_traffic -= len;
        }

        /* Update Time Advertisement IE */
        if (bo->bo_time_adv) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_TIME_ADVERTISEMENT, -1, &bo->bo_time_adv,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_time_adv to start because the function call has moved it "len" bytes */
            bo->bo_time_adv -= len;
        }

        /* Update Emergency Alert Identifier IE */
        if (bo->bo_emergency_id) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_EMERGENCY_ALERT_ID, -1, &bo->bo_emergency_id,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_emergency_id to start because the function call has moved it "len" bytes */
            bo->bo_emergency_id -= len;
        }

        /* Update Mesh ID IE */
        if (bo->bo_mesh_id) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_MESH_ID, -1, &bo->bo_mesh_id,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_mesh_id to start because the function call has moved it "len" bytes */
            bo->bo_mesh_id -= len;
        }

        /* Update Mesh Configuration IE */
        if (bo->bo_mesh_conf) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_MESH_CONFIG, -1, &bo->bo_mesh_conf,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_mesh_conf to start because the function call has moved it "len" bytes */
            bo->bo_mesh_conf -= len;
        }

        /* Update Mesh Awake window IE */
        if (bo->bo_mesh_awake_win) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_MESH_AWAKE_WINDOW, -1, &bo->bo_mesh_awake_win,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_mesh_awake_win to start because the function call has moved it "len" bytes */
            bo->bo_mesh_awake_win -= len;
        }

        /* Update Beacon Timing IE */
        if (bo->bo_beacon_time) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_BEACON_TIMING, -1, &bo->bo_beacon_time,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_beacon_time to start because the function call has moved it "len" bytes */
            bo->bo_beacon_time -= len;
        }

        /* Update MCCAOP Advertisement Overview IE */
        if (bo->bo_mccaop_adv_ov) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_MCCAOP_ADV_OVERVIEW, -1, &bo->bo_mccaop_adv_ov,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_mccaop_adv_ov to start because the function call has moved it "len" bytes */
            bo->bo_mccaop_adv_ov -= len;
        }

        /* Update MCCAOP Advertisement IE */
        if (bo->bo_mccaop_adv) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_MCCAOP_ADV, -1, &bo->bo_mccaop_adv,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_mccaop_adv to start because the function call has moved it "len" bytes */
            bo->bo_mccaop_adv -= len;
        }

        /* Update Mesh Channel Switch Parameters IE */
        if (bo->bo_mesh_cs_param) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_MESH_CHANSWITCH_PARAM, -1, &bo->bo_mesh_cs_param,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_mesh_cs_param to start because the function call has moved it "len" bytes */
            bo->bo_mesh_cs_param -= len;
        }

        /* Update QMF Policy IE */
        if (bo->bo_qmf_policy) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_QMF_POLICY, -1, &bo->bo_qmf_policy,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_qmf_policy to start because the function call has moved it "len" bytes */
            bo->bo_qmf_policy -= len;
        }

        /* Update QLoad Report IE */
        if (bo->bo_qload_rpt) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_QLOAD_REPORT, -1, &bo->bo_qload_rpt,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_qload_rpt to start because the function call has moved it "len" bytes */
            bo->bo_qload_rpt -= len;
        }

        /* Update HCCA TXOP Update Count IE */
        if (bo->bo_hcca_upd_cnt) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_HCCA_TXOP_UPD_CNT, -1, &bo->bo_hcca_upd_cnt,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_hcca_upd_cnt to start because the function call has moved it "len" bytes */
            bo->bo_hcca_upd_cnt -= len;
        }

        /* Update Multi-band IE */
        if (bo->bo_multiband) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_MULTIBAND, -1, &bo->bo_multiband,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_multiband to start because the function call has moved it "len" bytes */
            bo->bo_multiband -= len;
        }

        /* Update Quiet Channel IE */
        if (bo->bo_quiet_chan) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_QUIET_CHANNEL, -1, &bo->bo_quiet_chan,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_quiet_chan to start because the function call has moved it "len" bytes */
            bo->bo_quiet_chan -= len;
        }

        /* Update Operating Mode Notification IE */
        if (bo->bo_opt_mode_note) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_OP_MODE_NOTIFY, -1, &bo->bo_opt_mode_note,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_opt_mode_note to start because the function call has moved it "len" bytes */
            bo->bo_opt_mode_note -= len;
        }

        /* Update TVHT IE */
        if (bo->bo_tvht) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_TVHT_OP, -1, &bo->bo_tvht,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_tvht to start because the function call has moved it "len" bytes */
            bo->bo_tvht -= len;
        }

        /* Update Future Channel Guidance IE */
        if (bo->bo_future_chan) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_EXTN,
                    IEEE80211_ELEMID_EXT_FUTURE_CHANNEL_GUIDE, &bo->bo_future_chan, TYPE_ALL_BUF, NULL, true);
            /* Reset bo_future_chan to start because the function call has moved it "len" bytes */
            bo->bo_future_chan -= len;
        }

        /* Update Common Advertisement Group (CAG) Number IE */
        if (bo->bo_cag_num) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_CAG_NUMBER, -1, &bo->bo_cag_num,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_cag_num to start because the function call has moved it "len" bytes */
            bo->bo_cag_num -= len;
        }

        /* Update FILS Indication IE */
        if (bo->bo_fils_ind) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_FILS_INDICATION, -1, &bo->bo_fils_ind,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_fils_ind to start because the function call has moved it "len" bytes */
            bo->bo_fils_ind -= len;
        }

        /* Update AP-CSN IE */
        if (bo->bo_ap_csn) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_AP_CSN, -1, &bo->bo_ap_csn,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_ap_csn to start because the function call has moved it "len" bytes */
            bo->bo_ap_csn -= len;
        }

        /* Update Differentiated Initial Link Setup IE */
        if (bo->bo_diff_init_lnk) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_DIFF_INIT_LNK_SETUP, -1, &bo->bo_diff_init_lnk,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_diff_init_lnk to start because the function call has moved it "len" bytes */
            bo->bo_diff_init_lnk -= len;
        }

        /* Update Service Hint IE */
        if (bo->bo_service_hint) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_SERVICE_HINT, &bo->bo_service_hint,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_service_hint to start because the function call has moved it "len" bytes */
            bo->bo_service_hint -= len;
        }

        /* Update Service Hash IE */
        if (bo->bo_service_hash) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_SERVICE_HASH, &bo->bo_service_hash,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_service_hash to start because the function call has moved it "len" bytes */
            bo->bo_service_hash -= len;
        }

        /* Update TWT IE */
        if (bo->bo_twt) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_TWT, -1, &bo->bo_twt,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_twt to start because the function call has moved it "len" bytes */
            bo->bo_twt -= len;
        }

#if ATH_SUPPORT_UORA
        /* Update UORA Parameter Set IE */
        if (bo->bo_uora_param) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_UORA_PARAM, &bo->bo_uora_param,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_uora_param to start because the function call has moved it "len" bytes */
            bo->bo_uora_param -= len;
        }
#endif

        /* Update ESS Report IE */
        if (bo->bo_ess_rpt) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_ESS_REPORT, &bo->bo_ess_rpt,
                    TYPE_ALL_BUF, NULL, true);
            /* Reset bo_ess_rpt to start because the function call has moved it "len" bytes */
            bo->bo_ess_rpt -= len;
        }

        /* Update NDP Feedback Report Parameter IE */
        if (bo->bo_ndp_rpt_param) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_NDP_FEEDBACK_REPORT_PARAM,
                    &bo->bo_ndp_rpt_param, TYPE_ALL_BUF, NULL, true);
            /* Reset bo_ndp_rpt_param to start because the function call has moved it "len" bytes */
            bo->bo_ndp_rpt_param -= len;
        }

        /* Update HE BSS Load IE */
        if (bo->bo_he_bss_load) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_HE_BSS_LOAD,
                    &bo->bo_he_bss_load, TYPE_ALL_BUF, NULL, true);
            /* Reset bo_he_bss_load to start because the function call has moved it "len" bytes */
            bo->bo_he_bss_load -= len;
        }

        /* Update RSNX IE */
        if (bo->bo_rsnx) {
            len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_RSNX, -1, &bo->bo_rsnx, TYPE_ALL_BUF, NULL, true);
            /* Reset bo_rsnx to start because the function call has moved it "len" bytes */
            bo->bo_rsnx -= len;
        }

        frm_buf = (uint8_t *)qdf_mem_malloc(IEEE80211_APPIE_MAX);
        if (!frm_buf) {
            IEEE80211_VAP_APPIE_UPDATE_DISABLE(vap);
#ifdef ATH_BEACON_DEFERRED_PROC
            IEEE80211_VAP_UNLOCK(vap);
#endif
            return;
        }

        temp = frm_buf;
        /* Add the IEs in new memory location */
        len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_VENDOR, false,
                &temp, TYPE_APP_IE_BUF, NULL, false);
        if (len != bo->bo_appie_buf_len) {
            int diff_len;

            diff_len = len - bo->bo_appie_buf_len;
            bo->bo_appie_buf_len = (u_int16_t) len;

            /* update the trailer lens */
            bo->bo_chanswitch_trailerlen += diff_len;
            bo->bo_tim_trailerlen += diff_len;
            bo->bo_ecsa_trailerlen += diff_len;
            bo->bo_mcst_trailerlen += diff_len;
            bo->bo_vhtchnsw_trailerlen += diff_len;
            bo->bo_secchanoffset_trailerlen += diff_len;

#if ATH_SUPPORT_IBSS_DFS
            bo->bo_ibssdfs_trailerlen += diff_len;
#endif
#if UMAC_SUPPORT_WNM
            bo->bo_fms_trailerlen += diff_len;
#endif

            /* Append or trim based on diff_len
             * If append, update size, shift extension IEs last to first, copy frm_buf
             * If trim, shift extension IEs first to last, update size, copy frm_buf
             */
            if (diff_len > 0)
                wbuf_append(wbuf, diff_len);
            else
                wbuf_trim(wbuf, -(diff_len));

            *len_changed = 1;
        }

        /* Copy the newly added IEs to frm (bo_appie_buf) */
        qdf_mem_copy(bo->bo_appie_buf, temp-len, len);
        qdf_mem_free(frm_buf);
        IEEE80211_VAP_APPIE_UPDATE_DISABLE(vap);

        *update_beacon_copy = true;
    }

#ifdef ATH_BEACON_DEFERRED_PROC
    IEEE80211_VAP_UNLOCK(vap);
#endif
}

#if QCA_SUPPORT_SON
static int ieee80211_beacon_add_son_ie(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int *len_changed,
        bool *update_beacon_copy)
{
    uint8_t *frm = NULL;

    if (IEEE80211_VAP_IS_WDS_ENABLED(vap) &&
            son_vdev_fext_capablity(vap->vdev_obj,SON_CAP_GET,
                WLAN_VDEV_FEXT_SON_INFO_UPDATE) &&
            !son_vdev_map_capability_get(vap->vdev_obj, SON_MAP_CAPABILITY)) {
        uint16_t whcCaps = QCA_OUI_WHC_AP_INFO_CAP_WDS;
        uint16_t newlen;
        uint8_t *tempbuf = NULL;

        tempbuf = OS_MALLOC(vap->iv_ic->ic_osdev,
                sizeof(struct ieee80211_ie_whc_apinfo),
                GFP_KERNEL);
        if(tempbuf == NULL)
            return -1;

        /* SON mode requires WDS as a prereq */
        if (son_vdev_feat_capablity(vap->vdev_obj, SON_CAP_GET,
                    WLAN_VDEV_F_SON))
            whcCaps |= QCA_OUI_WHC_AP_INFO_CAP_SON;

        son_add_ap_info_ie(tempbuf, whcCaps, vap->vdev_obj, &newlen);

        if(newlen != bo->bo_whc_apinfo_len) {
            int diff_len = newlen - bo->bo_whc_apinfo_len;

            bo->bo_whc_apinfo_len = newlen;

            /* update the trailer lens */
            bo->bo_tim_trailerlen += diff_len;
            bo->bo_chanswitch_trailerlen += diff_len;
            bo->bo_secchanoffset_trailerlen += diff_len;
            bo->bo_ecsa_trailerlen += diff_len;
            bo->bo_mcst_trailerlen += diff_len;
            bo->bo_vhtchnsw_trailerlen += diff_len;
            bo->bo_bcca_trailerlen += diff_len;

#if ATH_SUPPORT_IBSS_DFS
            bo->bo_ibssdfs_trailerlen += diff_len;
#endif

#if UMAC_SUPPORT_WNM
            bo->bo_fms_trailerlen += diff_len;
#endif

            if (diff_len > 0)
                wbuf_append(wbuf, diff_len);
            else
                wbuf_trim(wbuf, -(diff_len));

            *len_changed = 1;
        }

        if (bo->bo_whc_apinfo) {
            OS_MEMCPY(bo->bo_whc_apinfo, tempbuf, bo->bo_whc_apinfo_len);
            frm = bo->bo_whc_apinfo + bo->bo_whc_apinfo_len;
            son_vdev_fext_capablity(vap->vdev_obj,SON_CAP_CLEAR,
                    WLAN_VDEV_FEXT_SON_INFO_UPDATE);
        }

        OS_FREE(tempbuf);
        *update_beacon_copy = true;
    }

    return 0;
}
#endif

#if DBDC_REPEATER_SUPPORT
/* Add Extender IE */
static void ieee80211_beacon_add_extender_ie(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int *len_changed,
        bool *update_beacon_copy)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct global_ic_list *ic_list = ic->ic_global_list;

    if (ic_list->same_ssid_support) {
       if (bo->bo_extender_ie) {
            /* Add the Extender IE */
           ieee80211_add_extender_ie(vap, IEEE80211_FRAME_TYPE_BEACON, bo->bo_extender_ie);
       } else {
           ieee80211_beacon_reinit(ni, bo, wbuf, len_changed, update_beacon_copy);
       }
    } else {
        bo->bo_extender_ie = NULL;
    }
}
#endif

void
ieee80211_adjust_bos_for_bsscolor_change_ie(
        struct ieee80211_beacon_offsets *bo,
        uint8_t offset) {

    QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_INFO, "%s>>", __func__);

    /* Update the pointers following this element and also trailer
     * length.
     */
    bo->bo_tim_trailerlen             += offset;
    bo->bo_chanswitch_trailerlen      += offset;
    bo->bo_vhtchnsw_trailerlen        += offset;
    bo->bo_secchanoffset_trailerlen   += offset;
    bo->bo_mcst_trailerlen            += offset;
    bo->bo_ecsa_trailerlen            += offset;
#if ATH_SUPPORT_IBSS_DFS
    bo->bo_ibssdfs_trailerlen         += offset;
#endif
#if UMAC_SUPPORT_WNM
    bo->bo_fms_trailerlen             += offset;
#endif
#if OBSS_PD
    if(bo->bo_srp_ie)
        bo->bo_srp_ie += offset;
#endif

    if(bo->bo_muedca)
        bo->bo_muedca += offset;

    if (bo->bo_ess_rpt)
        bo->bo_ess_rpt += offset;

    if (bo->bo_ndp_rpt_param)
        bo->bo_ndp_rpt_param += offset;

    if (bo->bo_he_bss_load)
        bo->bo_he_bss_load += offset;

    if (bo->bo_he_6g_bandcap) {
        bo->bo_he_6g_bandcap += offset;
    }

    if (bo->bo_mcst)
        bo->bo_mcst += offset;

    if (bo->bo_secchanoffset)
        bo->bo_secchanoffset += offset;

    if (bo->bo_rsnx)
        bo->bo_rsnx += offset;

    if (bo->bo_ath_caps)
        bo->bo_ath_caps += offset;

    if (bo->bo_extender_ie)
        bo->bo_extender_ie += offset;

    if (bo->bo_htinfo_vendor_specific)
        bo->bo_htinfo_vendor_specific += offset;

    if (bo->bo_mbo_cap )
        bo->bo_mbo_cap  += offset;

    if (bo->bo_apriori_next_channel)
        bo->bo_apriori_next_channel += offset;

    if (bo->bo_bwnss_map)
        bo->bo_bwnss_map += offset;

#if QCN_IE
    if (bo->bo_qcn_ie)
        bo->bo_qcn_ie += offset;
#endif

    if (bo->bo_software_version_ie)
        bo->bo_software_version_ie += offset;

    if (bo->bo_xr)
        bo->bo_xr += offset;

    if (bo->bo_whc_apinfo)
        bo->bo_whc_apinfo += offset;

    if (bo->bo_interop_vhtcap)
        bo->bo_interop_vhtcap += offset;

    if (bo->bo_wme)
        bo->bo_wme += offset;

    if (bo->bo_appie_buf)
        bo->bo_appie_buf += offset;

#if ATH_SUPPORT_UORA
    if(bo->bo_uora_param)
        bo->bo_uora_param += offset;
#endif

    QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_INFO, "%s<<", __func__);
}

static int ieee80211_csa_interop_bss_is_desired(struct ieee80211vap *vap)
{
    struct ieee80211com *ic;
    int desired = 0;

    ic = vap->iv_ic;

    if (ic->ic_flags & IEEE80211_F_CHANSWITCH) {
        desired = 1;
        if (!vap->iv_csa_interop_bss)
            desired = 0;
    }

    return desired;
}

/*
 * Update the dynamic parts of a beacon frame based on the current state.
 */
#if UMAC_SUPPORT_WNM
int ieee80211_beacon_update(struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int mcast,
        u_int32_t nfmsq_mask)
#else
int ieee80211_beacon_update(struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int mcast)
#endif
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    int len_changed = 0;
    struct ieee80211_frame *wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    bool update_beacon_copy = false;
    struct ieee80211_ath_tim_ie *tie = NULL;
    systime_t curr_time = OS_GET_TIMESTAMP();
    static systime_t prev_store_beacon_time;
    int retval;
#if UMAC_SUPPORT_WNM
    int is_dtim = 0;
#endif
    int interop_bss_desired;

    if((curr_time - prev_store_beacon_time) >=
            INTERVAL_STORE_BEACON * NUM_MILLISEC_PER_SEC){
        update_beacon_copy = true;
        prev_store_beacon_time = curr_time;
    }

#if QCN_IE
    /* If broadcast probe response feature is enabled and beacon offload is not enabled
     * then flag the current beacon as sent and calculate the next beacon timestamp.
     */
    if (vap->iv_bpr_enable && (!vap->iv_bcn_offload_enable)) {
       ieee80211_flag_beacon_sent(vap);
    }
#endif
    vap->iv_estimate_tbtt = ktime_to_ms(ktime_get());

    /* Update neighbor APs informations for AP Channel Report IE, RNR IE and MBO_OCE IE */
    if ((CONVERT_SYSTEM_TIME_TO_MS(curr_time) - vap->nbr_scan_ts) >=
        (vap->nbr_scan_period * NUM_MILLISEC_PER_SEC)) {

        if (vap->ap_chan_rpt_enable && !ieee80211_bg_scan_enabled(vap))
            ieee80211_update_ap_chan_rpt(vap);

        if (vap->rnr_enable && !ieee80211_bg_scan_enabled(vap))
            ieee80211_update_rnr(vap);
#if ATH_SUPPORT_MBO
        if (ieee80211_vap_oce_check(vap)) {
            ieee80211_update_non_oce_ap_presence (vap);
            if (IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan))
                ieee80211_update_11b_ap_presence (vap);
        }
#endif
        vap->nbr_scan_ts = CONVERT_SYSTEM_TIME_TO_MS(curr_time);
    }
#if QCN_ESP_IE
    if(ic->ic_esp_flag == 1){
        vap->iv_update_vendor_ie = 1;
        ic->ic_esp_flag = 0;
    }
#endif

    /* If Beacon Tx is suspended, then don't send this beacon */
    if (ieee80211_mlme_beacon_suspend_state(vap)) {
        qdf_err("[%s] skip Tx beacon during to suspend.\n", vap->iv_netdev_name);
        return -1;
    }

    /*
     * If vap is paused do not send any beacons to prevent transmitting
     * beacons on wrong channel.
     */
#if UMAC_SUPPORT_VAP_PAUSE
    if (ieee80211_vap_is_paused(vap))
        return -1;
#endif

    /*
     * Use the non-QoS sequence number space for BSS node
     * to avoid sw generated frame sequence the same as H/W generated frame,
     * the value lower than min_sw_seq is reserved for HW generated frame.
     */
    if ((ni->ni_txseqs[IEEE80211_NON_QOS_SEQ] & IEEE80211_SEQ_MASK) <
            MIN_SW_SEQ)
        ni->ni_txseqs[IEEE80211_NON_QOS_SEQ] = MIN_SW_SEQ;

    *(uint16_t *)&wh->i_seq[0] = htole16(
            ni->ni_txseqs[IEEE80211_NON_QOS_SEQ] << IEEE80211_SEQ_SEQ_SHIFT);
    ni->ni_txseqs[IEEE80211_NON_QOS_SEQ]++;

    interop_bss_desired = ieee80211_csa_interop_bss_is_desired(vap);

    vap->beacon_reinit_done = false;

    if (interop_bss_desired != vap->iv_csa_interop_bss_active) {
        qdf_info("csa interop bss %hhu -> %hhu",
                 vap->iv_csa_interop_bss_active, interop_bss_desired);

        vap->iv_csa_interop_bss_active = interop_bss_desired;
        ieee80211_beacon_reinit(ni, bo, wbuf, &len_changed, &update_beacon_copy);
    }

    ieee80211_beacon_check_and_reinit_beacon(ni, bo, wbuf, &len_changed,
            &update_beacon_copy);

    IEEE80211_CHAN_CHANGE_LOCK(ic);
    if (!IEEE80211_CHANCHANGE_STARTED_IS_SET(ic) &&
            (ic->ic_flags & IEEE80211_F_CHANSWITCH)) {
        IEEE80211_CHANCHANGE_STARTED_SET(ic);
        IEEE80211_CHANCHANGE_BY_BEACONUPDATE_SET(ic);
    }
    IEEE80211_CHAN_CHANGE_UNLOCK(ic);
    retval = ieee80211_change_channel(ni, &update_beacon_copy,
            &len_changed, wbuf, bo);
    if (!retval) {
        qdf_err("%s: channel change failed", vap->iv_netdev_name);
        IEEE80211_CHANCHANGE_STARTED_CLEAR(ic);
        IEEE80211_CHANCHANGE_BY_BEACONUPDATE_CLEAR(ic);
        return -1;
    }

    /* Update cap info */
    ieee80211_update_capinfo(vap, bo);

    /* Update TIM */
    ieee80211_beacon_update_tim(ni, bo, &tie, wbuf, &len_changed, mcast,
            &is_dtim);

    /* Update power constraints */
    ieee80211_beacon_update_pwrcnstr(vap, bo);

    /* Update CSA, ECSA, CSA Wrapper, Secondary Channel Offset and MCST */
    ieee80211_beacon_add_chan_switch_ie(ni, bo, wbuf, &len_changed);

    /* Update quiet param */
    ieee80211_quiet_beacon_update(vap, ic, bo);

    /* Update channel utilization information */
    ieee80211_update_chan_utilization(vap);

#if ATH_SUPPORT_IBSS_DFS
    retval = ieee80211_beacon_update_ibss_dfs(vap, bo, wbuf, &len_changed);
    if (retval == -1)
        return -1;
#endif

    /* Add the TPC Report IE in the beacon */
    if (bo->bo_tpcreport) {
        ieee80211_add_tpc_ie(bo->bo_tpcreport, vap);
    }

    /* Update ERP IE */
    ieee80211_beacon_erp_update(vap, bo);

    /* Update bssload*/
    ieee80211_qbssload_beacon_update(vap, ni, bo);

    /* Add HT capability */
    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        ieee80211_beacon_add_htcap(ni, bo);
    }

    /* Add VHT capability */
    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        ieee80211_beacon_add_vhtcap(ni, bo);
    }

    /* Increment the TIM update beacon count to indicate inclusion of BCCA IE */
    if(vap->iv_bcca_ie_status == BCCA_START) {
        update_beacon_copy = true;
    }
    /* Increment the TIM update beacon count to indicate change in HEOP param */
    if(ic->ic_is_heop_param_updated) {
        update_beacon_copy = true;

    }
    /* Add HE BSS Color Change IE */
    ieee80211_beacon_add_bsscolor_change_ie(ni, bo, wbuf, &len_changed);

    /* Add HE capability */
    ieee80211_add_he_cap(ni, bo);

#if OBSS_PD
    if(ic->ic_is_spatial_reuse_updated) {
        ieee80211_add_srp_ie(ic, bo->bo_srp_ie);
        update_beacon_copy = true;
    }
#endif /* OBSS PD */

#if ATH_SUPPORT_UORA
    /* Update UORA param */
    ieee80211_beacon_update_uora_param(vap, bo, &update_beacon_copy);
#endif

    /* Update MU-EDCA param */
    ieee80211_beacon_update_muedca_param(vap, bo, &update_beacon_copy);

    /* Add WME param */
    ieee80211_beacon_add_wme_param(vap, bo, &update_beacon_copy);

    /* Update WNM IE */
#if UMAC_SUPPORT_WNM
    retval = ieee80211_beacon_add_wnm_ie(ni, bo, tie, wbuf,
            &is_dtim, nfmsq_mask) ;
    if (retval == -1)
        return -1;
#endif

    /* Update APRIORI next channel */
    ieee80211_add_apriori_next_chan(ni, bo);

    /* Add SON IE */
#if QCA_SUPPORT_SON
    retval = ieee80211_beacon_add_son_ie(vap, bo, wbuf, &len_changed,
            &update_beacon_copy);
    if (retval == -1)
        return -1;
#endif

#if DBDC_REPEATER_SUPPORT
    /* Update Extender IE */
    ieee80211_beacon_add_extender_ie(ni, bo, wbuf, &len_changed,
            &update_beacon_copy);
#endif
    /* Add application IE */
    ieee80211_beacon_add_app_ie(vap, bo, wbuf, &len_changed,
            &update_beacon_copy);

#if UMAC_SUPPORT_WNM
    if (update_beacon_copy) {
        ieee80211_wnm_tim_incr_checkbeacon(vap);
    }
#endif

    if (update_beacon_copy && ieee80211_vap_copy_beacon_is_set(vap)) {
        store_beacon_frame(vap, (uint8_t *)wbuf_header(wbuf),
                wbuf_get_pktlen(wbuf));
    }

    return len_changed;
}

#if UMAC_SUPPORT_WNM
int ieee80211_prb_rsp_update(struct ieee80211_node *ni,
                    struct ieee80211_beacon_offsets *bo, wbuf_t wbuf,
                    int mcast, u_int32_t nfmsq_mask)
#else
int ieee80211_prb_rsp_update(struct ieee80211_node *ni,
                    struct ieee80211_beacon_offsets *bo, wbuf_t wbuf, int mcast)
#endif
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    bool update_beacon_copy = false;
    int len_changed = 0;

    /* Update cap info */
    ieee80211_update_capinfo(vap, bo);

    /* Update power constraints */
    ieee80211_beacon_update_pwrcnstr(vap, bo);

    /* Update quiet param */
    ieee80211_quiet_beacon_update(vap, ic, bo);

    /* Add the TPC Report IE in the beacon */
    if (bo->bo_tpcreport) {
        ieee80211_add_tpc_ie(bo->bo_tpcreport, vap);
    }

    /* Update ERP IE */
    ieee80211_beacon_erp_update(vap, bo);

    /* Update bssload*/
    ieee80211_qbssload_beacon_update(vap, ni, bo);

   /* Add HE capability */
    ieee80211_add_he_cap(ni, bo);

#if OBSS_PD
    if(ic->ic_is_spatial_reuse_updated)
        ieee80211_add_srp_ie(ic, bo->bo_srp_ie);

#endif /* OBSS PD */

    /* Update MU-EDCA param */
    ieee80211_beacon_update_muedca_param(vap, bo, &update_beacon_copy);

/* Add WME param */
    ieee80211_beacon_add_wme_param(vap, bo, &update_beacon_copy);

    /* Add application IE */
    ieee80211_beacon_add_app_ie(vap, bo, wbuf, &len_changed,
            &update_beacon_copy);

    return 0;

}

int
wlan_copy_ap_beacon_frame(wlan_if_t vaphandle,
                          u_int32_t in_buf_size,
                          u_int32_t *required_buf_size,
                          void *buffer)
{
    struct ieee80211vap *vap = vaphandle;
    void *beacon_buf;

    *required_buf_size = 0;

    /* Make sure that this VAP is SoftAP */
    if (vap->iv_opmode != IEEE80211_M_HOSTAP) {
        return EPERM ;
    }

    if (!vap->iv_beacon_copy_buf) {
        /* Error: no beacon buffer */
        return EPERM ;
    }

    if (in_buf_size < vap->iv_beacon_copy_len) {
        /* Input buffer too small */
        *required_buf_size = vap->iv_beacon_copy_len;
        return ENOMEM ;
    }
    *required_buf_size = vap->iv_beacon_copy_len;

    beacon_buf = (void *)vap->iv_beacon_copy_buf;

    OS_MEMCPY(buffer, beacon_buf, vap->iv_beacon_copy_len);

    return EOK;
}

void wlan_vdev_beacon_update(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;

    if (vap->iv_bcn_offload_enable &&
            ieee80211_is_vap_state_running(vap) &&
            (vap->iv_opmode == IEEE80211_M_HOSTAP) &&
            ic->ic_vdev_beacon_template_update) {
        ic->ic_vdev_beacon_template_update(vap);
        if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan))
            ic->ic_vdev_prb_rsp_tmpl_update(vap);
        }

    return;
}
qdf_export_symbol(wlan_vdev_beacon_update);

void wlan_pdev_beacon_update(struct ieee80211com *ic)
{
    struct ieee80211vap *vap;

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next)
        if (vap)
            wlan_vdev_beacon_update(vap);

    return;

}

void ieee80211_csa_interop_phy_update(struct ieee80211_node *ni, int rx_bw)
{
    struct ieee80211vap *vap;
    struct ieee80211com *ic;
    int chan_bw;

    if (!ni) {
        return;
    }

    vap = ni->ni_vap;
    ic = vap->iv_ic;

    switch (rx_bw) {
        case IEEE80211_CWM_WIDTH20:
        case IEEE80211_CWM_WIDTH40:
        case IEEE80211_CWM_WIDTH80:
        case IEEE80211_CWM_WIDTH160:
            switch (ieee80211_get_chan_width(vap->iv_bsschan)) {
                case 5:
                case 10:
                case 20:
                    chan_bw = IEEE80211_CWM_WIDTH20;
                    break;
                case 40:
                    chan_bw = IEEE80211_CWM_WIDTH40;
                    break;
                case 80:
                    chan_bw = IEEE80211_CWM_WIDTH80;
                    break;
                case 160:
                    chan_bw = IEEE80211_CWM_WIDTH160;
                    break;
                default:
                    chan_bw = IEEE80211_CWM_WIDTH20;
                    break;
            }

            if (rx_bw <= ni->ni_chwidth)
                break;

            if (rx_bw > chan_bw)
                break;

            if (unlikely(WARN_ONCE((unlikely(!(ni->ni_flags & IEEE80211_NODE_HT)) &&
                                    unlikely(rx_bw >= IEEE80211_CWM_WIDTH40)),
                                   "%s: [%s, %pM] ignoring %d -> %d, !ht && cw>=40",
                                   __func__, vap->iv_netdev_name, ni->ni_macaddr,
                                   ni->ni_chwidth, rx_bw)))
                break;

            if (unlikely(WARN_ONCE((unlikely(!(ni->ni_flags & IEEE80211_NODE_VHT)) &&
                                    unlikely(rx_bw >= IEEE80211_CWM_WIDTH80)),
                                   "%s: [%s, %pM] ignoring %d -> %d, !vht && cw>=80",
                                   __func__, vap->iv_netdev_name, ni->ni_macaddr,
                                   ni->ni_chwidth, rx_bw)))
                break;

            if (unlikely(WARN_ONCE((unlikely(!ni->ni_160bw_requested) &&
                                    unlikely(rx_bw >= IEEE80211_CWM_WIDTH160)),
                                   "%s: [%s, %pM] ignoring %d -> %d, !160assoc && cw>=160",
                                   __func__, vap->iv_netdev_name, ni->ni_macaddr,
                                   ni->ni_chwidth, rx_bw)))
                break;

            qdf_debug("[%s, %pM] upgrading CW %d -> %d (chan_bw=%d)",
                     vap->iv_netdev_name, ni->ni_macaddr,
                     ni->ni_chwidth, rx_bw, chan_bw);

            ni->ni_chwidth = rx_bw;
            ic->ic_chwidth_change(ni);
            break;
        case -1:
            qdf_debug("[%s, %pM] downgrading CW %d -> %d",
                     vap->iv_netdev_name, ni->ni_macaddr, ni->ni_chwidth,
                     IEEE80211_CWM_WIDTH20);

            ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
            ic->ic_chwidth_change(ni);
            break;
        default:
            qdf_debug("[%s, %pM] unsupported CW %d -> %d, ignoring",
                     vap->iv_netdev_name, ni->ni_macaddr,
                     ni->ni_chwidth, rx_bw);
            break;
    }
}

void ieee80211_csa_interop_update(void *ctrl_pdev, enum WDI_EVENT event,
                                  void *buf, uint16_t id, uint32_t type)
{
    qdf_nbuf_t nbuf;
    struct wlan_objmgr_pdev *pdev;
    struct ieee80211com *ic;
    struct cdp_rx_indication_ppdu *cdp_rx_ppdu;
    uint32_t bw;
    struct ieee80211_node *ni;

    nbuf = buf;
    if (!nbuf) {
        qdf_err("nbuf is null");
        return;
    }

    pdev = (struct wlan_objmgr_pdev *)ctrl_pdev;
    if (!pdev) {
        qdf_err("pdev is null");
        return;
    }

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    cdp_rx_ppdu = (struct cdp_rx_indication_ppdu *)qdf_nbuf_data(nbuf);
    bw = cdp_rx_ppdu->u.bw;

    ni = ieee80211_find_node(&ic->ic_sta, cdp_rx_ppdu->mac_addr, WLAN_MLME_HANDLER_ID);
    if (!ni) {
        qdf_err("ni is null");
        return;
    }

    ieee80211_csa_interop_phy_update(ni, bw);
    ieee80211_free_node(ni, WLAN_MLME_HANDLER_ID);
}
qdf_export_symbol(ieee80211_csa_interop_update);
