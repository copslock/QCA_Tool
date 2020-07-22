/*
 * Copyright (c) 2011,2018-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 * Qualcomm Innovation Center,Inc. has chosen to take madwifi subject to the BSD license and terms.
 *
 * 2011 Qualcomm Atheros, Inc.
 * Qualcomm Atheros, Inc. has chosen to take madwifi subject to the BSD license and terms.
 *
 * Copyright (c) 2008, Atheros Communications Inc.
 */

#include "ieee80211_mlme_priv.h"
#include "ieee80211_bssload.h"
#include "ieee80211_quiet_priv.h"
#include "osif_private.h"

#include "ol_if_athvar.h"
#include "cfg_ucfg_api.h"
#include <wlan_utility.h>

#include <wlan_son_pub.h>
/* This macro is copied from FW headers*/
#define HTT_TX_EXT_TID_NONPAUSE_PRIVATE 19

/*
 * ieee80211_add_rsn_ie: Add RSN IE in the frame
 *
 * @vap   : VAP handle
 * @frm   : frm pointer to add the IE
 * @optie : Optional IE buffer (local buffer)
 *
 * Return: frm pointer after adding, if RSN IE is added,
 *         NULL elsewhere
 */
static inline uint8_t *ieee80211_add_rsn_ie(struct ieee80211vap *vap,
        uint8_t *frm, struct ieee80211_app_ie_t *optie)
{
    if (!vap->iv_rsn_override) {
        IEEE80211_VAP_LOCK(vap);
        if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_RSN, -1, &frm,
                TYPE_ALL_BUF, optie, true)) {

            /* Add RSN IE if not present */
#if ATH_SUPPORT_HS20
            if (!vap->iv_osen) {
#endif

#ifdef WLAN_CONV_CRYPTO_SUPPORTED
                if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj,
                            (1 << WLAN_CRYPTO_AUTH_RSNA))) {
                    frm = wlan_crypto_build_rsnie(vap->vdev_obj, frm, NULL);
                    if(!frm) {
                        IEEE80211_VAP_UNLOCK(vap);
                        return NULL;
                    }
                }
#else
                if (RSN_AUTH_IS_RSNA(&vap->iv_rsn))
                    frm = ieee80211_setup_rsn_ie(vap, frm);
#endif

#if ATH_SUPPORT_HS20
            }
#endif
        }
        IEEE80211_VAP_UNLOCK(vap);
    }

    return frm;
}

/*
 * ieee80211_add_vht_ies: Add VHT cap, op, power envelope, CS Wrapper
 *                        and EBSS load IEs in the frame
 *
 * @ni       : Node information handle
 * @ic       : State handle
 * @vap      : VAP handle
 * @frm      : frm pointer to add IEs
 * @macaddr  : MAC address of the STA
 * @extractx : Extra Context information
 *
 * Return: frm pointer after adding IEs
 */
static inline uint8_t *ieee80211_add_vht_ies(struct ieee80211_node *ni,
        struct ieee80211com *ic, struct ieee80211vap *vap, uint8_t *frm,
        uint8_t *macaddr, struct ieee80211_framing_extractx *extractx)
{
    if (ieee80211_vap_wme_is_set(vap) &&
        (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
        (IEEE80211_IS_CHAN_11AX(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11NG(ic->ic_curchan)) &&
        ieee80211vap_vhtallowed(vap)) {

        /* 59. VHT Capabilities */
        if (ASSOCWAR160_IS_VHT_CAP_CHANGE(vap->iv_cfg_assoc_war_160w))
            frm = ieee80211_add_vhtcap(frm, ni, ic,
                    IEEE80211_FC0_SUBTYPE_PROBE_RESP, extractx, macaddr);
        else
            frm = ieee80211_add_vhtcap(frm, ni, ic,
                    IEEE80211_FC0_SUBTYPE_PROBE_RESP, NULL, macaddr);

        /* 60. VHT Operation */
        frm = ieee80211_add_vhtop(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP, extractx);

        /* 61. Transmit Power Envelope element */
        if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
            frm = ieee80211_add_vht_txpwr_envlp(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP,
                                                         !IEEE80211_VHT_TXPWR_IS_SUB_ELEMENT);
        }

        /* 62. Channel Switch Wrapper */
        if(vap->iv_chanchange_count && (ic->ic_chanchange_channel != NULL)
                && (IEEE80211_IS_CHAN_11AC(vap->iv_bsschan)
                    || IEEE80211_IS_CHAN_11AXA(vap->iv_bsschan))
                && ieee80211vap_vhtallowed(vap)
                && (ic->ic_chanchange_channel != NULL)) {

            /* channel switch wrapper element */
            frm = ieee80211_add_chan_switch_wrp(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP,
                    /* When switching to new country by sending ECSA IE,
                     * new country IE should be also be added.
                     * As of now we dont support switching to new country
                     * without bringing down vaps so new country IE is not
                     * required.
                     */
                    (/*ecsa_ie ? IEEE80211_VHT_EXTCH_SWITCH :*/
                     !IEEE80211_VHT_EXTCH_SWITCH));
        }

        /* 63. Extended BSS Load */
        frm = ieee80211_add_ext_bssload(frm, ni);
    }

    return frm;
}

/*
 * Send a probe response frame.
 * NB: for probe response, the node may not represent the peer STA.
 * We could use BSS node to reduce the memory usage from temporary node.
 */
int
ieee80211_send_proberesp(struct ieee80211_node *ni, u_int8_t *macaddr,
                         const void *optie, const size_t  optielen,
                         struct ieee80211_framing_extractx *extractx)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    u_int8_t *frm;
    u_int16_t capinfo;
    int enable_htrates;
    struct ieee80211_bwnss_map nssmap;
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);
#ifndef WLAN_CONV_CRYPTO_SUPPORTED
    struct ieee80211_rsnparms *rsn = &vap->iv_rsn;
#endif
#if QCN_IE
    u_int16_t ie_len;
#endif
#if DBDC_REPEATER_SUPPORT
    struct global_ic_list *ic_list = ic->ic_global_list;
#endif

#if QCN_ESP_IE
    u_int16_t esp_ie_len;
#endif
    struct ieee80211vap *tmpvap = NULL;
    uint8_t num_non_trans_profiles;
    uint8_t *new;

    uint8_t len = 0;
    uint8_t chanchange_tbtt = 0;
    uint8_t csmode = IEEE80211_CSA_MODE_STA_TX_ALLOWED;
    bool global_look_up = false;
    uint16_t behav_lim = 0;
    uint16_t chan_width;

    qdf_mem_zero(&nssmap, sizeof(nssmap));

    ASSERT(vap->iv_opmode == IEEE80211_M_HOSTAP || vap->iv_opmode == IEEE80211_M_IBSS ||
           vap->iv_opmode == IEEE80211_M_BTAMP);

    /*
     * XXX : This section needs more testing with P2P
     */
    if (!vap->iv_bss) {
        return 0;
    }

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                          "%s: Error: unable to alloc wbuf of type WBUF_TX_MGMT.\n",
                          __func__);
        return -ENOMEM;
    }

    if(extractx->is_6ghz_bcast_prbreq) {
        IEEE80211_ADDR_COPY(macaddr, IEEE80211_GET_BCAST_ADDR(ni->ni_ic));
    }

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_RESP,
                         vap->iv_myaddr, macaddr,
                         ieee80211_node_get_bssid(ni));
    frm = (u_int8_t *)&wh[1];

    /* ------------- Fixed Fields ------------- */
    /* 1. Timestamp */
    qdf_mem_zero(frm, 8); /* Skip this field, it will be filled later */
    frm += 8;

    /* 2. Beacon interval */
    *(u_int16_t *)frm = htole16(vap->iv_bss->ni_intval);
    frm += 2;

    /* 3. Capability Information */
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
    frm += 2;

    /* ------------- Regular and Extension IEs ------------- */
    /* 4. SSID */
    frm = ieee80211_add_ssid(frm, vap->iv_bss->ni_essid,
                             vap->iv_bss->ni_esslen);

    /* 5. Supported Rates and BSS Membership Selectors */
    frm = ieee80211_add_rates(frm, &vap->iv_bss->ni_rates);

    /* 6. DS Parameter Set */
    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) &&
            !IEEE80211_IS_CHAN_FHSS(vap->iv_bsschan)) {
        *frm++ = IEEE80211_ELEMID_DSPARMS;
        *frm++ = 1;
        *frm++ = ieee80211_chan2ieee(ic, ic->ic_curchan);
    }

    /* 7. CF Parameter Set */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_CFPARMS, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 8. IBSS Parameter Set */
    if (vap->iv_opmode == IEEE80211_M_IBSS) {
        *frm++ = IEEE80211_ELEMID_IBSSPARMS;
        *frm++ = 2;
        *frm++ = 0; *frm++ = 0;     /* TODO: ATIM window */
    }

    /* 9. Country */
    if (IEEE80211_IS_COUNTRYIE_ENABLED(ic) && ieee80211_vap_country_ie_is_set(vap)) {
        frm = ieee80211_add_country(frm, vap);
    }

    /* 10. Power Constraint */
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
        *frm++ = IEEE80211_ELEMID_PWRCNSTR;
        *frm++ = 1;
        *frm++ = IEEE80211_PWRCONSTRAINT_VAL(vap);
    }

    if (vap->iv_csmode == IEEE80211_CSA_MODE_AUTO) {

        /* No user preference for csmode. Use default behavior.
         * If chan swith is triggered because of radar found
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
         * Use user preference
         */
        csmode = vap->iv_csmode;
    }

    /* 11. Channel Switch Announcement */
    if(vap->iv_chanchange_count && (ic->ic_chanchange_channel != NULL)) {
        struct ieee80211_ath_channelswitch_ie *csaie = NULL;
        chanchange_tbtt = ic->ic_chanchange_tbtt - vap->iv_chanchange_count;
        csaie = (struct ieee80211_ath_channelswitch_ie *)frm;
        csaie->ie = IEEE80211_ELEMID_CHANSWITCHANN;
        csaie->len = 3; /* fixed len */
        csaie->switchmode = csmode;
        csaie->newchannel = wlan_reg_freq_to_chan(ic->ic_pdev_obj, ic->ic_chanchange_chan_freq);
        csaie->tbttcount = chanchange_tbtt;
        frm += IEEE80211_CHANSWITCHANN_BYTES;
    }

    /* 12. Quiet */
    frm = ieee80211_add_quiet(vap, ic, frm);

#if ATH_SUPPORT_IBSS_DFS
    /* 13. IBSS DFS */
    if (vap->iv_opmode == IEEE80211_M_IBSS) {
        frm =  ieee80211_add_ibss_dfs(frm,vap);
    }
#endif

    /* 14. TPC Report
     * Add the TPC Report IE in the probe response for 5GHz if 802.11h or RRM capability
     * is set.
     */
    if ((ieee80211_ic_doth_is_set(ic) &&
         ieee80211_vap_doth_is_set(vap)) ||
         ieee80211_vap_rrm_is_set(vap)) {
        frm = ieee80211_add_tpc_ie(frm, vap);
    }

    /* 15. ERP */
    if (IEEE80211_IS_CHAN_ANYG(ic->ic_curchan) ||
        IEEE80211_IS_CHAN_11NG(ic->ic_curchan) ||
        IEEE80211_IS_CHAN_11AXG(ic->ic_curchan)) {
        frm = ieee80211_add_erp(frm, ic);
    }

    /* 16. Extended Support Rates and BSS Membership Selectors */
    frm = ieee80211_add_xrates(vap, frm, &vap->iv_bss->ni_rates);

    /* 17. RSN */
    frm = ieee80211_add_rsn_ie(vap, frm, (struct ieee80211_app_ie_t *)optie);
    if (!frm) {
        wbuf_release(ic->ic_osdev, wbuf);
        return -EINVAL;
    }

    /* 18. QBSS Load */
    frm = ieee80211_add_qbssload(frm, ni);

    /* 19. EDCA Parameter Set */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EDCA, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 20. Measurement Pilot Transmissions */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MESUREMENT_PILOT_TX, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);


    /* 21. Multiple BSSID */
    if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE)) {
        num_non_trans_profiles = 0;
        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(tmpvap) &&
                tmpvap->iv_is_up && tmpvap->iv_mbss.mbssid_send_bcast_probe_resp) {
                ni = tmpvap->iv_bss;
                new = ieee80211_mbss_add_profile(frm,
                       ni, &num_non_trans_profiles,
                       IEEE80211_FRAME_TYPE_PROBERESP);
                if (!new) {
                    wbuf_release(ic->ic_osdev, wbuf);
                    return -EINVAL;
                }
            }
        } /* TAILQ_FOREACH */

        if (num_non_trans_profiles != 0)
            frm = new;
    }

    /* 22. RM Enabled Capbabilities, if supported */
    frm = ieee80211_add_rrm_cap_ie(frm, ni);

    /* 23. AP Channel Report */
    if (vap->ap_chan_rpt_enable) {
        frm = ieee80211_add_ap_chan_rpt_ie (frm, vap);
    }

    /* 24. BSS Average Access Delay */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_BSS_AVG_ACCESS_DELAY, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 25. Antenna */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_ANTENNA, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 26. BSS Available Admission Capacity */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_BSS_ADMISSION_CAP, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

#ifndef ATH_SUPPORT_WAPI
    /* 27. BSS AC Access Delay IE */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_BSS_AC_ACCESS_DELAY, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);
#endif

    /* 28. Mobility Domain */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MOBILITY_DOMAIN, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 29. DSE registered location */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_DSE_REG_LOCATION, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);


    /* 30. Extended Channel Switch Announcement */
    if(vap->iv_chanchange_count && (ic->ic_chanchange_channel != NULL)
            && vap->iv_enable_ecsaie) {
        struct ieee80211_extendedchannelswitch_ie *ecsa_ie = NULL;
        ecsa_ie = (struct ieee80211_extendedchannelswitch_ie *)frm;
        ecsa_ie->ie = IEEE80211_ELEMID_EXTCHANSWITCHANN;
        ecsa_ie->len = 4; /* fixed len */
        ecsa_ie->switchmode = csmode;

        /* If user configured opClass is set, use it else
         * *              * calculate new opClass from destination channel.
         * *                           */
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
               return -EINVAL;
            }
            /* Get new OpClass and Channel number from regulatory */
            wlan_reg_freq_width_to_chan_op_class_auto(ic->ic_pdev_obj,
                                                      ic->ic_chanchange_chan_freq,
                                                      chan_width,
                                                      global_look_up, behav_lim,
                                                      &ecsa_ie->newClass,
                                                      &ecsa_ie->newchannel);
        }
        ecsa_ie->tbttcount = chanchange_tbtt;
        frm += IEEE80211_EXTCHANSWITCHANN_BYTES;
    }

    /* 31. Supported Operating Classes */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_SUPP_OP_CLASS, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);


    /* HT capable */
    enable_htrates = ieee80211vap_htallowed(vap);
    if (ieee80211_vap_wme_is_set(vap) &&
        (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
        (IEEE80211_IS_CHAN_11AX(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
        enable_htrates) {
        /* 32. HT Capabilities */
        frm = ieee80211_add_htcap(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);

        /* 33. HT Operation */
        frm = ieee80211_add_htinfo(frm, ni);

        /* 34. 20/40 BSS Coexistence */
        ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_2040_COEXT, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

        /* 35. OBSS Scan */
        if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
            frm = ieee80211_add_obss_scan(frm, ni);
        }
    }

    /* 36. Extended Capbabilities, if applicable */
    frm = ieee80211_add_extcap(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);

    /* 37. QoS Traffic Capability */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_QOS_TRAFFIC_CAP, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 38. Channel Usage */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_CHANNEL_USAGE, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 39. Time Advertisement */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_TIME_ADVERTISEMENT, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 40. Time Zone */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_TIME_ZONE, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 41. Interworking IE (Hotspot 2.0) */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_INTERWORKING, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 42. Advertisement Protocol IE (Hotspot 2.0) */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_ADVERTISEMENT_PROTO, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 43. Roaming Consortium IE (Hotspot 2.0) */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_ROAMING_CONSORTIUM, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 44. Emergency Alert Identifier */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EMERGENCY_ALERT_ID, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 45. Mesh ID */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MESH_ID, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 46. Mesh Configuration */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MESH_CONFIG, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 47. Mesh Awake Window */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MESH_AWAKE_WINDOW, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 48. Beacon Timing */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_BEACON_TIMING, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 49. MCCAOP Advertisement Overview */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MCCAOP_ADV_OVERVIEW, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 50. MCCAOP Advertisement */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MCCAOP_ADV, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 51. Mesh Channel Switch Parameters */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MESH_CHANSWITCH_PARAM, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 52. QMF Policy */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_QMF_POLICY, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 53. QLoad Report */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_QLOAD_REPORT, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 54. Multi-band */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MULTIBAND, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 55. DMG Capabilities */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_DMG_CAP, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 56. DMG Operation */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_DMG_OPERATION, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 57. Multiple MAC Sublayers */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MULTIPLE_MAC_SUB, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 58. Antenna Sector ID Pattern */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_ANTENNA_SECT_ID_PAT, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);


    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        /* VHT capable
         * Add VHT capabilities (59), operation (60), Tx Power envelope (61),
         * Channel Switch Wrapper (62) and Extended BSS Load (63) elements
         * for 2.4G mode, if 256QAM is enabled
         */
        frm = ieee80211_add_vht_ies(ni, ic, vap, frm, macaddr, extractx);
    } else {
        /*
         * Add Channel switch wrapper IE and Tx power envelope for 6G band
         * ieee80211_add_vht_ies adds these IEs for 5G band, but not for 6G.
         */
        if (ieee80211_vap_wme_is_set(vap) && vap->iv_chanchange_count &&
                (ic->ic_chanchange_channel != NULL)) {
            frm = ieee80211_add_chan_switch_wrp(frm, ni, ic,
                    IEEE80211_FC0_SUBTYPE_PROBE_RESP,
                    (!IEEE80211_VHT_EXTCH_SWITCH));
        }
    }

    /* 64. Quiet Channel */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_QUIET_CHANNEL, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 65. Operating Mode Notification */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_OP_MODE_NOTIFY, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);


    /* 66. Reduced Neighbor Report */
    if (vap->rnr_enable) {
        if (IEEE80211_IS_BROADCAST(macaddr) || (extractx->oce_sta) || (extractx->fils_sta)) {
            frm = ieee80211_add_rnr_ie(frm, vap, extractx->ssid, extractx->ssid_len);
        }
    }
    if (!vap->rnr_enable && ic->ic_oob_enable && !IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        frm = ieee80211_add_oob_rnr_ie(frm, vap, extractx->ssid,
                  extractx->ssid_len, IEEE80211_FC0_SUBTYPE_PROBE_RESP);
    }

    /* 67. TVHT Operation */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_TVHT_OP, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);


#if QCN_ESP_IE
    /* 68. Estimated Service Parameters */
    if (ic->ic_esp_periodicity){
        frm = ieee80211_add_esp_info_ie(frm, ic, &esp_ie_len);
    }
#endif

    /* 69. Relay Capabilities */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_RELAY_CAP, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 70. Common Advertisement Group (CAG) Number */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_CAG_NUMBER, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 71. FILS Indication */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_FILS_INDICATION, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 72. AP-CSN */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_AP_CSN, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 73. Differentiated Initial Link Setup */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_DIFF_INIT_LNK_SETUP, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 74. RPS */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_RPS, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 75. Page Slice */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_PAGE_SLICE, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 76. Change Sequence */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_CHANGE_SEQ, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 77. TSF Timer Accuracy */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_TSF_TIMER_ACC, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 78. S1G Relay Discovery */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_S1G_RELAY_DISCOVREY, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 79. S1G Capabilities */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_S1G_CAP, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 80. S1G Operation */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_S1G_OP, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 81. MAD */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MAD, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 82. Short Beacon Interval */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_SHORT_BEACON_INTVAL, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 83. S1G Open-Loop Link Margin Index */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_S1G_OPENLOOP_LINK_MARGIN,
            -1, &frm, TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 84. S1G Relay element */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_S1G_RELAY, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 85. CDMG Capaiblities */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
            IEEE80211_ELEMID_EXT_CDMG_CAP, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 86. Extended Cluster Report */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
            IEEE80211_ELEMID_EXT_EXTENDED_CLUSTER_RPT, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 87. CMMG Capabilities */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
            IEEE80211_ELEMID_EXT_CMMG_CAP, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 88. CMMG Operation */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
            IEEE80211_ELEMID_EXT_CMMG_OP, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 89. Service Hint */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
            IEEE80211_ELEMID_EXT_SERVICE_HINT, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 90. Service Hash */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
            IEEE80211_ELEMID_EXT_SERVICE_HASH, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);


    if (ieee80211_vap_wme_is_set(vap) &&  IEEE80211_IS_CHAN_11AX(ic->ic_curchan)
         && ieee80211vap_heallowed(vap)) {
        /* 93. HE Capabilities */
        frm = ieee80211_add_hecap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP);

        /* 94. HE Operation */
        frm = ieee80211_add_heop(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP, extractx);

    }

    /* 95. TWT */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_TWT, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

#if ATH_SUPPORT_UORA
    /* 96. UORA Parameter Set */
    if(ieee80211_vap_wme_is_set(vap) &&
           ieee80211vap_heallowed(vap) &&
           IEEE80211_IS_CHAN_11AX(ic->ic_curchan) &&
           ieee80211vap_uora_is_enabled(vap)) {
        frm = ieee80211_add_uora_param(frm, vap->iv_ocw_range);
    }
#endif

    /* 97. BSS Color Change Announcement */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
            IEEE80211_ELEMID_EXT_BSSCOLOR_CHG, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);


#if OBSS_PD
    /* 98. Spatial Reuse Parameters */
    if (ic->ic_he_sr_enable &&
        IEEE80211_IS_CHAN_11AX(ic->ic_curchan) && ieee80211vap_heallowed(vap)) {
        frm = ieee80211_add_srp_ie(ic, frm);
    }
#endif

    /* 99. MU EDCA Parameter Set*/
    if(ieee80211_vap_wme_is_set(vap) &&
            ieee80211vap_heallowed(vap) &&
            IEEE80211_IS_CHAN_11AX(ic->ic_curchan) &&
            ieee80211vap_muedca_is_enabled(vap)) {
        frm = ieee80211_add_muedca_param(frm, &vap->iv_muedcastate);
    }

    /* 100. ESS Report */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
            IEEE80211_ELEMID_EXT_ESS_REPORT, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 101. NDP Feedback Report Parameter */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
            IEEE80211_ELEMID_EXT_NDP_FEEDBACK_REPORT_PARAM, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 102. HE BSS Load */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
            IEEE80211_ELEMID_EXT_HE_BSS_LOAD, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

    /* 104. HE 6GHz Band Capabilities */
    if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        frm = ieee80211_add_6g_bandcap(frm, ni, ic,
                        IEEE80211_FC0_SUBTYPE_PROBE_RESP);
    }

    /* Adding RSNX element here since no order is mentioned in
     * the specification
     */
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_RSNX,
            -1, &frm, TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);

#if ATH_SUPPORT_WAPI
    /* WAPI IE
     * Added here since no order is mentioned in the specififcation */
#ifdef WLAN_CONV_CRYPTO_SUPPORTED
    if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj, (1 << WLAN_CRYPTO_AUTH_WAPI)))
#else
    if (RSN_AUTH_IS_WAI(rsn))
#endif
    {
        frm = ieee80211_setup_wapi_ie(vap, frm);
        if (!frm) {
            wbuf_release(ic->ic_osdev, wbuf);
            return -EINVAL;
        }
    }
#endif

    /* Maximum channel Switch Time (MCST)
     * Added here since no order is mentioned in the specification*/
    if(vap->iv_chanchange_count && (ic->ic_chanchange_channel != NULL)
            && vap->iv_enable_max_ch_sw_time_ie) {
        struct ieee80211_max_chan_switch_time_ie *mcst_ie = NULL;
        mcst_ie = (struct ieee80211_max_chan_switch_time_ie *)frm;
        ieee80211_add_max_chan_switch_time(vap, (uint8_t *)mcst_ie);
        frm += IEEE80211_MAXCHANSWITCHTIME_BYTES;
    }

    /* Secondary Channel Offset
     * Addedhere since no order is mentioned in
     * the specififcation
     */
    if(vap->iv_chanchange_count && (ic->ic_chanchange_channel != NULL)
            && (((IEEE80211_IS_CHAN_11N(vap->iv_bsschan)
                        || IEEE80211_IS_CHAN_11AC(vap->iv_bsschan)
                        || IEEE80211_IS_CHAN_11AX(vap->iv_bsschan))
                    && (ic->ic_chanchange_secoffset)) && ic->ic_sec_offsetie)) {
        struct ieee80211_ie_sec_chan_offset *sec_chan_offset_ie = NULL;

        sec_chan_offset_ie = (struct ieee80211_ie_sec_chan_offset *)frm;
        sec_chan_offset_ie->elem_id = IEEE80211_ELEMID_SECCHANOFFSET;

        /* Element has only one octet of info */
        sec_chan_offset_ie->len = 1;
        sec_chan_offset_ie->sec_chan_offset = ic->ic_chanchange_secoffset;
        frm += IEEE80211_SEC_CHAN_OFFSET_BYTES;
    }

    /* ------------- LAST. Vendor IEs ------------- */
    /* Ath Advanced Capabilities */
    if (vap->iv_ena_vendor_ie == 1) {
        if (vap->iv_bss->ni_ath_flags) {
            frm = ieee80211_add_athAdvCap(frm, vap->iv_bss->ni_ath_flags,
                    vap->iv_bss->ni_ath_defkeyindex);
        } else {
            frm = ieee80211_add_athAdvCap(frm, 0, IEEE80211_INVAL_DEFKEY);
        }
    }

    /* Ath Extended Capabilities */
    if (ic->ic_ath_extcap)
        frm = ieee80211_add_athextcap(frm, ic->ic_ath_extcap, ic->ic_weptkipaggr_rxdelim);

#if DBDC_REPEATER_SUPPORT
    /* Extender */
    if (ic_list->same_ssid_support) {
        frm = ieee80211_add_extender_ie(vap, IEEE80211_FRAME_TYPE_PROBERESP, frm);
    }
#endif

    /* HT Capabilities and HT Info/Operation vendor IEs */
    if (ieee80211_vap_wme_is_set(vap) &&
        (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
        (IEEE80211_IS_CHAN_11AX(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
        (IEEE80211_IS_HTVIE_ENABLED(ic)) && enable_htrates) {
        frm = ieee80211_add_htcap_vendor_specific(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);
        frm = ieee80211_add_htinfo_vendor_specific(frm, ni);
    }

    /* MBO */
    if (ieee80211_vap_mbo_check(vap) || ieee80211_vap_oce_check(vap)) {
        frm = ieee80211_setup_mbo_ie(IEEE80211_FC0_SUBTYPE_PROBE_RESP, vap, frm, ni);
    }

    /* Prop NSS IE if external NSS is not supported */
    if (!(vap->iv_ext_nss_support) && !(ic->ic_disable_bwnss_adv)
            && !ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask))  {
        frm = ieee80211_add_bw_nss_maping(frm, &nssmap);
    }

#if QCN_IE
    /* QCN IE for the feature set */
    frm = ieee80211_add_qcn_info_ie(frm, vap, &ie_len,
                                    QCN_MAC_PHY_PARAM_IE_TYPE, NULL);
#endif

    /* SON Mode */
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

    /* WME Param */
    if (ieee80211_vap_wme_is_set(vap) &&
        (vap->iv_opmode == IEEE80211_M_HOSTAP || vap->iv_opmode == IEEE80211_M_BTAMP)) /* don't support WMM in ad-hoc for now */
        frm = ieee80211_add_wme_param(frm, &vap->iv_wmestate, IEEE80211_VAP_IS_UAPSD_ENABLED(vap));

	/* Check if os shim has setup WPA IE itself */
    if (!vap->iv_rsn_override) {
        IEEE80211_VAP_LOCK(vap);
        len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP,IEEE80211_ELEMID_VENDOR, 1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);
        if (len) {
            /* Remove WPA from frame so that it will be added
             * when other vendor IEs are added
             */
            frm -= len;
            qdf_mem_zero(frm, len);
        } else {

            /* WPA IE if not present in buffers*/
#ifdef WLAN_CONV_CRYPTO_SUPPORTED
            if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj,
                        (1 << WLAN_CRYPTO_AUTH_WPA))) {
                frm = wlan_crypto_build_wpaie(vap->vdev_obj, frm);
                if(!frm) {
                    IEEE80211_VAP_UNLOCK(vap);
                    wbuf_release(ic->ic_osdev, wbuf);
                    return -EINVAL;
                }
            }
#else
            if (RSN_AUTH_IS_WPA(rsn))
                frm = ieee80211_setup_wpa_ie(vap, frm);
#endif
        }
        IEEE80211_VAP_UNLOCK(vap);
    }

    /* Hardware and Software version */
    frm = ieee80211_add_sw_version_ie(frm, ic);

    frm = ieee80211_add_generic_vendor_capabilities_ie(frm, ic);
    if(!frm)
        return -EINVAL;

    /* ------------- App IE Buffer or list, and Optional IEs ------------- */
    IEEE80211_VAP_LOCK(vap);
    len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_VENDOR, 0, &frm, TYPE_ALL_BUF,
            (struct ieee80211_app_ie_t *)optie, false);
    IEEE80211_VAP_UNLOCK(vap);

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));
    if (extractx->datarate) {
        if (extractx->datarate == 6000)       /* 6 Mbps */
            wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_OFDM, 3, ic->ic_he_target);
        else if (extractx->datarate == 5500)  /* 5.5 Mbps */
            wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_CCK, 1, ic->ic_he_target);
        else if (extractx->datarate == 2000)  /* 2 Mbps */
            wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_CCK, 2, ic->ic_he_target);
        else                                  /* 1 Mbps */
            wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_CCK, 3, ic->ic_he_target);

		/* tid should be set to HTT_TX_EXT_TID_NONPAUSE to apply tx_rate */
        wbuf_set_tid(wbuf, HTT_TX_EXT_TID_NONPAUSE_PRIVATE);
    }

    return ieee80211_send_mgmt(vap,ni, wbuf,true);
}

/* Determine whether probe response needs modification towards 160 MHz width
   association WAR.
 */
static bool
is_assocwar160_reqd_proberesp(struct ieee80211vap *vap,
        struct ieee80211_ie_ssid *probereq_ssid_ie,
        struct ieee80211_ie_vhtcap *sta_vhtcap)
{
    int is_sta_any160cap = 0;

    qdf_assert_always(vap != NULL);
    qdf_assert_always(probereq_ssid_ie != NULL);

    /* Since this WAR is deprecated, it will not be made available for 11ax. */

    if (((vap->iv_cur_mode != IEEE80211_MODE_11AC_VHT160) &&
                (vap->iv_cur_mode != IEEE80211_MODE_11AC_VHT80_80)) ||
        !vap->iv_cfg_assoc_war_160w) {
        return false;
    }

    /* The WAR is required only for STAs not having any 160/80+80 MHz
     * capability. */
    if (sta_vhtcap == NULL) {
        return true;
    }

    is_sta_any160cap =
        ((sta_vhtcap->vht_cap_info &
            (IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160 |
             IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160 |
             IEEE80211_VHTCAP_SHORTGI_160)) != 0);

    if (is_sta_any160cap) {
        return false;
    }

    return true;
}

/* ieee80211_6ghz_is_ssid_match: Find a vap in 6Ghz
 * radio that matches the ssid/short_ssid in probe request.
 */
void ieee80211_6ghz_is_ssid_match(struct wlan_objmgr_psoc *psoc,
               void *arg, uint8_t index)
{
    struct wlan_objmgr_psoc_objmgr *objmgr;
    struct wlan_objmgr_pdev *pdev = NULL;
    int id = 0;
    wlan_dev_t ic;
    struct ieee80211vap *tmpvap = NULL;
    struct oob_prb_rsp *oob_prbrsp = (struct oob_prb_rsp*)arg;
    uint32_t self_shortssid;

    objmgr = &psoc->soc_objmgr;
    for (id=0;id<WLAN_UMAC_MAX_PDEVS;id++) {
        pdev = objmgr->wlan_pdev_list[id];
        if (pdev) {
            ic = wlan_pdev_get_mlme_ext_obj(pdev);
            if (ic && IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
                TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                    if (tmpvap->iv_opmode == IEEE80211_M_HOSTAP &&
                        tmpvap->iv_is_up) {
                        if (!oob_prbrsp->is_shortssid) {
                            oob_prbrsp->ssid_match = IEEE80211_MATCH_SSID(tmpvap->iv_bss,
                                                     oob_prbrsp->ssid_info);
                        if (!oob_prbrsp->ssid_match)
                            break;
                        } else {
                            self_shortssid = ieee80211_construct_shortssid((tmpvap->iv_bss)->ni_essid,
                                                        (tmpvap->iv_bss)->ni_esslen);
                            oob_prbrsp->ssid_match = IEEE80211_MATCH_SHORT_SSID(tmpvap->iv_bss,
                                            (uint8_t *)&self_shortssid, oob_prbrsp->ssid_info);
                            if (!oob_prbrsp->ssid_match)
                                break;
                        }
                    }
                }
            }
        }
    }
}

/* ieee80211_6ghz_is_ssid_match: Iterate through
 * all psocs and find a 6Ghz pdev to get vaps in
 * 6Ghz band
 */
QDF_STATUS ieee80211_check_6ghz_ssid_match (struct wlan_objmgr_psoc *psoc,
        struct oob_prb_rsp *oob_prbrsp)
{
    wlan_objmgr_iterate_psoc_list(ieee80211_6ghz_is_ssid_match,
                                  oob_prbrsp, WLAN_MLME_NB_ID);
    return QDF_STATUS_SUCCESS;
}

int
ieee80211_recv_probereq(struct ieee80211_node *ni, wbuf_t wbuf, int subtype,
                        struct ieee80211_rx_status *rs)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_frame *wh;
    unsigned int found_vap  = 0;
    unsigned int found_null_bssid = 0;
    int ret = -EINVAL;
    u_int8_t *frm, *efrm;
    u_int8_t *ssid, *rates, *ven , *short_ssid;
    u_int8_t *ssid_info;
#if ATH_SUPPORT_HS20 || QCN_IE
    u_int8_t *xcaps = NULL;
#endif
#if ATH_SUPPORT_HS20
    u_int8_t *iw = NULL;
    uint8_t empty[QDF_MAC_ADDR_SIZE] = {0x00,0x00,0x00,0x00,0x00,0x00};
#endif
#if QCA_SUPPORT_SON
    bool blocked;
    bool ssid_null;
#endif
#if QCN_IE
    u_int8_t *qcn = NULL;

    /*
     * Max-ChannelTime parameter represented in units of TUs
     * 255 used to indicate any duration of more than 254 TUs, or an
     * unspecified or unknown duration.
     */
    u_int8_t channel_time = 0;
    /* Index 0 has version and index 1 has subversion of QCN IE*/
    u_int8_t data[2] = {0};
    qdf_ktime_t eff_chan_time, bpr_delay;
    qdf_hrtimer_data_t *bpr_gen_timer = &vap->bpr_timer;
#endif
    u_int8_t *mbo = NULL;
    bool suppress_resp = false;
    u_int8_t nullbssid[QDF_MAC_ADDR_SIZE] = {0x00,0x00,0x00,0x00,0x00,0x00};
    int snd_prb_resp = 0;
    struct ieee80211_ie_vhtcap *vhtcap = NULL;
    struct ieee80211_ie_hecap  *hecap  = NULL;
    struct ieee80211_ie_heop   *heop   = NULL;
    struct ieee80211_framing_extractx extractx;
    bool shortssid_flag = false;
    uint32_t self_shortssid;
    uint8_t ssid_match;
    bool special_ssid_case = false;
    u_int8_t dedicated_oui_present = 0;

    OS_MEMZERO(&extractx, sizeof(extractx));
#if ATH_SUPPORT_AP_WDS_COMBO
    if (vap->iv_opmode == IEEE80211_M_STA ||
        (wlan_vdev_is_up(vap->vdev_obj) != QDF_STATUS_SUCCESS) ||
        vap->iv_no_beacon) {
#else
    if (vap->iv_opmode == IEEE80211_M_STA ||
        (wlan_vdev_is_up(vap->vdev_obj) != QDF_STATUS_SUCCESS)) {
#endif
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif
        return -EINVAL;
    }

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    frm = (u_int8_t *)&wh[1];
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);

    if (IEEE80211_IS_MULTICAST(wh->i_addr2)) {
        /* frame must be directed */
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif
        return -EINVAL;
    }

    /* AP should respond with a Probe response with Addr1 set to Bcast address,
     * for any valid Probe Request received on the 6GHz band.
	 */
    if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        extractx.is_6ghz_bcast_prbreq = true;
    }
#if UMAC_SUPPORT_NAWDS
    /* Skip probe request if configured as NAWDS bridge */
    if(vap->iv_nawds.mode == IEEE80211_NAWDS_STATIC_BRIDGE
		  || vap->iv_nawds.mode == IEEE80211_NAWDS_LEARNING_BRIDGE) {
        return -EINVAL;
    }
#endif
    /*Update node if ni->bssid is NULL*/
    if(!OS_MEMCMP(ni->ni_bssid,nullbssid,QDF_MAC_ADDR_SIZE))
    {
        ni = ieee80211_try_ref_bss_node(vap, WLAN_MGMT_HANDLER_ID);
        if(ni == NULL) {
            return -EINVAL;
        }

        found_null_bssid = 1;
    }
#if ATH_PARAMETER_API
    ieee80211_papi_send_probe_req_event(vap, ni, wbuf, rs);
#endif
    /*
     * prreq frame format
     *  [tlv] ssid
     *  [tlv] supported rates
     *  [tlv] extended supported rates
     *  [tlv] Atheros Advanced Capabilities
     */
    ssid = rates = short_ssid =NULL;
    while (((frm+1) < efrm) && (frm + frm[1] + 1 < efrm)) {
        switch (*frm) {
        case IEEE80211_ELEMID_SSID:
            ssid = frm;
            break;
        case IEEE80211_ELEMID_RATES:
            rates = frm;
            break;
#if ATH_SUPPORT_HS20
        case IEEE80211_ELEMID_XCAPS:
            xcaps = frm;
            break;
        case IEEE80211_ELEMID_INTERWORKING:
            iw = frm;
            break;
#endif
        case IEEE80211_ELEMID_VENDOR:
            if (vap->iv_venie && vap->iv_venie->ven_oui_set) {
                ven = frm;
                if (ven[2] == vap->iv_venie->ven_oui[0] &&
                    ven[3] == vap->iv_venie->ven_oui[1] &&
                    ven[4] == vap->iv_venie->ven_oui[2]) {
                    vap->iv_venie->ven_ie_len = MIN(ven[1] + 2, IEEE80211_MAX_IE_LEN);
                    OS_MEMCPY(vap->iv_venie->ven_ie, ven, vap->iv_venie->ven_ie_len);
                }
            }
            if (isdedicated_cap_oui(frm)) {
                dedicated_oui_present = 1;
            }
            else if ((vhtcap == NULL) &&
                    /*
                     * Standalone-VHT CAP IE outside
                     * of Interop IE
                     * will obviously supercede
                     * VHT CAP inside interop IE
                     */
                    ieee80211vap_11ng_vht_interopallowed(vap) &&
                    isinterop_vht(frm)) {
                /* frm+7 is the location , where 2.4G Interop VHT IE starts */
                vhtcap = (struct ieee80211_ie_vhtcap *) (frm + 7);
            }
#if QCN_IE
            else if(isqcn_oui(frm)) {
                qcn = frm;
            }
#endif
            else if (ismbooui(frm)) {
                mbo = frm;
            }

            if ( snd_prb_resp == 0 ) {
                snd_prb_resp = isorbi_ie(vap, frm);
              }
            break;
        case IEEE80211_ELEMID_VHTCAP:
            vhtcap = (struct ieee80211_ie_vhtcap *)frm;
            break;

        case WLAN_ELEMID_EXTN_ELEM:
            if (((frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT) < efrm) &&
                (*(frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT)
                     == IEEE80211_ELEMID_EXT_HECAP)) {
                hecap = (struct ieee80211_ie_hecap *)frm;
            } else if (((frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT) < efrm) &&
                    (*(frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT)
                         == IEEE80211_ELEMID_EXT_HEOP)) {
                heop = (struct ieee80211_ie_heop *)frm;
            } else if (((frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT) < efrm) &&
                    (*(frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT)
                        == IEEE80211_ELEMID_EXT_SHORT_SSID)) {
                short_ssid = frm;
            }
#if QCN_IE
            else if(isfils_req_parm(frm)) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,"FILS STA found mac[%s] \n",ether_sprintf(wh->i_addr2));
                /* Get the Channel time |IE|LEN|EXT|BITMAP|CHANNEL TIME|..| skip Parameter Control Bitmap */
                if(frm[4]) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,"FILS Max channel time : %uTU\n",frm[4]);
                    channel_time = frm[4];
                    eff_chan_time = qdf_ns_to_ktime(QDF_NSEC_PER_MSEC *
                                EFF_CHAN_TIME((channel_time * 1024)/1000, ic->ic_bpr_latency_comp));
                }
                else {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,"FILS STA with invalid IE Ignoring \n");
                }
            }
#endif
            break;
        }

        /* elem id + len = 2 bytes */
        frm += frm[1] + 2;
    }

    if (frm > efrm) {
        ret = -EINVAL;
        goto exit;
    }
#ifdef MU_CAP_WAR_ENABLED
    if (dedicated_oui_present &&
        (vhtcap != NULL) &&
        (le32toh(vhtcap->vht_cap_info) & IEEE80211_VHTCAP_MU_BFORMEE)) {

        ni->dedicated_client = 1;
    }
#endif

    IEEE80211_VERIFY_ELEMENT(rates, rates[1], IEEE80211_RATE_MAXSIZE);

    if(ssid) {
        IEEE80211_VERIFY_ELEMENT(ssid, ssid[1], IEEE80211_NWID_LEN);
        ssid_info = ssid;
        if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
            special_ssid_case = IEEE80211_IS_SPECIAL_SSID(ssid_info,
                                                IEEE80211_6GHZ_SPECIAL_SSID);
        }
    } else {
        qdf_err("SSID element not found in probe request!");
        return -EINVAL;
    }

    if (short_ssid) {
        IEEE80211_VERIFY_ELEMENT(short_ssid, (short_ssid[1] - 1), IEEE80211_SHORT_SSID_LEN);
        self_shortssid = ieee80211_construct_shortssid((vap->iv_bss)->ni_essid,
                                                    (vap->iv_bss)->ni_esslen);
        shortssid_flag = true;
    }

    /* update rate and rssi information */
#ifdef QCA_SUPPORT_CP_STATS
    WLAN_PEER_CP_STAT_SET(ni, rx_mgmt_rate, rs->rs_datarate);
    WLAN_PEER_CP_STAT_SET(ni, rx_mgmt_rssi, rs->rs_rssi);
#endif

    IEEE80211_DELIVER_EVENT_RECV_PROBE_REQ(vap, wh->i_addr2, ssid_info);

    if(special_ssid_case && shortssid_flag) {
        /* Process the short SSID information from probe request in case
		 * the client uses Special SSID.
		 */
        ssid_match = IEEE80211_MATCH_SHORT_SSID(vap->iv_bss,
                                (uint8_t *)&self_shortssid, short_ssid);
    } else {
        ssid_match = IEEE80211_MATCH_SSID(vap->iv_bss, ssid_info);
    }

    /* In 5/2Ghz AP case, if no ssid match, find a vap in 6Ghz radio that
     * has ssid/shortssid match
     */
    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        if (ssid_match) //ssid not match
        {
            struct oob_prb_rsp oob_prbrsp;
            qdf_mem_zero(&oob_prbrsp, sizeof(struct oob_prb_rsp));
            if(special_ssid_case && shortssid_flag) {
                oob_prbrsp.is_shortssid = shortssid_flag;
                oob_prbrsp.ssid_info = short_ssid;
            } else {
                oob_prbrsp.ssid_info = ssid_info;
            }
            ieee80211_check_6ghz_ssid_match(wlan_pdev_get_psoc(ic->ic_pdev_obj), &oob_prbrsp);
            ssid_match = oob_prbrsp.ssid_match;
        }
    }

    /*
     * XXX bug fix 107944: STA Entry exists in the node table,
     * But the STA want to associate with the other vap,  vap should
     * send the correct proble response to Station.
     *
     */

    if(ssid_match)  //ssid not match
    {
        struct ieee80211vap *tmpvap = NULL;
        if(ni != vap->iv_bss)
        {
            TAILQ_FOREACH(tmpvap, &(ic)->ic_vaps, iv_next)
            {
                if(special_ssid_case && shortssid_flag) {
                    self_shortssid =
                        ieee80211_construct_shortssid((tmpvap->iv_bss)->ni_essid,
                                                    (tmpvap->iv_bss)->ni_esslen);
                    ssid_match = IEEE80211_MATCH_SHORT_SSID(tmpvap->iv_bss,
                                       (uint8_t *)&self_shortssid, short_ssid);
                } else {
                    ssid_match = IEEE80211_MATCH_SSID(tmpvap->iv_bss, ssid_info);
                }
                if((tmpvap->iv_opmode == IEEE80211_M_HOSTAP) && (!ssid_match))
                {
                        found_vap = 1;
                        break;
                }
            }
        }
        if(found_vap  == 1)
        {
            ni = ieee80211_ref_bss_node(tmpvap, WLAN_MGMT_HANDLER_ID);
            if ( ni ) {
                vap = ni->ni_vap;
            }
        }
        else
        {
#ifdef QCA_SUPPORT_CP_STATS
            vdev_cp_stats_rx_ssid_mismatch_inc(vap->vdev_obj, 1);
#endif
            goto exit;
        }

    }

#if ATH_ACL_SOFTBLOCKING
    if (ssid_info[1] != 0) { // directed probe request.
        if (!wlan_acl_check_softblocking(vap, wh->i_addr2)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACL,
                    "Directed Probe Req Frames from %s are softblocked\n",
                    ether_sprintf(wh->i_addr2));
#ifdef QCA_SUPPORT_CP_STATS
            vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif
            goto exit;
        }
    }
#endif

    if (IEEE80211_VAP_IS_HIDESSID_ENABLED(vap) && (ssid_info[1] == 0) && !(IEEE80211_VAP_IS_BACKHAUL_ENABLED(vap))) {
        IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
                          wh, ieee80211_mgt_subtype_name[
                              subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
                          "%s", "no ssid with ssid suppression enabled");
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_rx_ssid_mismatch_inc(vap->vdev_obj, 1);
#endif
        goto exit;
    }

#if DYNAMIC_BEACON_SUPPORT
    /*
     * If probe req received from non associated STA,
     * check the rssi and send probe resp.
     */
    if (vap->iv_dbeacon == 1 && vap->iv_dbeacon_runtime == 1) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "node(%s): rs_rssi %d, iv_dbeacon_rssi_thr: %d \n",
                ether_sprintf(wh->i_addr2),rs->rs_rssi, vap->iv_dbeacon_rssi_thr);
        if (rs->rs_rssi < vap->iv_dbeacon_rssi_thr) {
            /* don't send probe resp if rssi is low. */
#ifdef QCA_SUPPORT_CP_STATS
            vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif
            goto exit;
        }
    }
#endif

#if ATH_SUPPORT_HS20
    if (!IEEE80211_ADDR_EQ(vap->iv_hessid, &empty)) {
        if (iw && !xcaps)
            goto exit;
        if (iw && (xcaps[5] & 0x80)) {
            /* hessid match ? */
            if (iw[1] == 9 && !IEEE80211_ADDR_EQ(iw+5, vap->iv_hessid) && !IEEE80211_ADDR_EQ(iw+5, IEEE80211_GET_BCAST_ADDR(ic)))
                goto exit;
            if (iw[1] == 7 && !IEEE80211_ADDR_EQ(iw+3, vap->iv_hessid) && !IEEE80211_ADDR_EQ(iw+3, IEEE80211_GET_BCAST_ADDR(ic)))
                goto exit;
            /* access_network_type match ? */
            if ((iw[2] & 0xF) != vap->iv_access_network_type && (iw[2] & 0xF) != 0xF)
                goto exit;
        }
    }
#endif

#if QCN_IE
    if (xcaps) {
        struct ieee80211_ie_ext_cap *extcaps = (struct ieee80211_ie_ext_cap *) xcaps;

        if ((extcaps->elem_len > 9) && (extcaps->ext_capflags4 & IEEE80211_EXTCAPIE_FILS)) {
            extractx.fils_sta = true;
        }
    }

    if (ssid) {
        extractx.ssid_len = *(ssid + 1);
        OS_MEMCPY(extractx.ssid, ssid + 2, extractx.ssid_len);
    }

    if (qcn && ni) {
        /*
         * Record qcn parameters for station, mark
         * node as using qcn and record information element
         * for applications that require it.
         */
          ieee80211_parse_qcnie(qcn, wh, ni,data);
    }
#endif
    if (mbo && ieee80211_vap_oce_check(vap)) {
        extractx.oce_sta = ieee80211_oce_capable(mbo);
        suppress_resp = ieee80211_oce_suppress_ap(mbo, vap);

        if (suppress_resp) {
            /* Drop the probe response */
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Suppress probe response: %d for vap %pK\n", suppress_resp, vap);
            goto exit;
        }
    }

#if QCA_SUPPORT_SON
    /* If band steering is withholding probes (due to steering being in
     * progress), return here so that the response is not sent.
     */
    if(ssid_info) {
        ssid_null = (ssid_info[1] == 0) ? true : false;
        blocked = son_is_probe_resp_wh(vap->vdev_obj, wh->i_addr2, rs->rs_rssi);
        son_send_probereq_event(vap->vdev_obj, wh->i_addr2, rs->rs_rssi, blocked,
                                ssid_null);

        if (IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan) &&
            son_is_probe_resp_wh_2G(vap->vdev_obj, wh->i_addr2,
                                    rs->rs_rssi)) {
            ret = 0;
            goto exit;
        }

        if (blocked) {
            ret = 0;
            goto exit;
        }
    }
#else
    // To silence compiler warning about unused variable.
    (void) rs;
#endif

    /*
     * Skip Probe Requests received while the scan algorithm is setting a new
     * channel, or while in a foreign channel.
     * Trying to transmit a frame (Probe Response) during a channel change
     * (which includes a channel reset) can cause a NMI due to invalid HW
     * addresses.
     * Trying to transmit the Probe Response while in a foreign channel
     * wouldn't do us any good either.
     */
    if (wlan_scan_can_transmit(wlan_vdev_get_pdev(vap->vdev_obj)) && !vap->iv_special_vap_mode) {
        if (likely(ic->ic_curchan == vap->iv_bsschan)) {
            snd_prb_resp = 1;
        }
#if MESH_MODE_SUPPORT
        if (vap->iv_mesh_vap_mode) {
            snd_prb_resp = 0;
        }
#endif
    }
    if (snd_prb_resp) {
        extractx.fectx_assocwar160_reqd = is_assocwar160_reqd_proberesp(vap,
                (struct ieee80211_ie_ssid *)ssid_info, vhtcap);

        if (extractx.fectx_assocwar160_reqd) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                              "%s: Applying 160MHz assoc WAR: probe resp to "
                              "STA %s\n",
                              __func__, ether_sprintf(wh->i_addr2));
        }

        if (ni) {
#if QCN_IE
            /* If channel time is not present then send the unicast response immediately */
            if ((extractx.fils_sta || extractx.oce_sta) && channel_time && vap->iv_bpr_enable &&
                    IEEE80211_IS_BROADCAST(wh->i_addr1) && IEEE80211_IS_BROADCAST(wh->i_addr3)) {

                /* If channel time is bigger than beancon interval, slightly discard the probe-req
                   as beacon will be sent instead */
                if (channel_time > ic->ic_intval) {
                    goto exit;
                }

                if (!qdf_hrtimer_active(bpr_gen_timer)) {
                    /* If its the first STA sending broadcast probe request, start the timer with
                     * the minimum of user configured delay and the channel time.
                     */
                    bpr_delay = qdf_ns_to_ktime(QDF_NSEC_PER_MSEC * vap->iv_bpr_delay);

                    /* Set the bpr_delay to be the minimum of channel time and user configured value */
                    if (qdf_ktime_to_ns(eff_chan_time) < qdf_ktime_to_ns(bpr_delay)) {
                        bpr_delay = eff_chan_time;
                    }

                    qdf_hrtimer_start(bpr_gen_timer, bpr_delay, QDF_HRTIMER_MODE_REL);
                    vap->iv_bpr_timer_start_count++;

                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                        "Start timer: %s | %d | Sequence: %d | Delay: %d | Current time: %lld | Beacon: %lld | effchantime: %lld | "
                        " Timer expires: %lld | Timer cb: %d | Enqueued: %d \n", \
                        __func__, __LINE__, ((le16toh(*(u_int16_t *)wh->i_seq)) & IEEE80211_SEQ_SEQ_MASK) >> IEEE80211_SEQ_SEQ_SHIFT,
                        vap->iv_bpr_delay, qdf_ktime_to_ns(qdf_ktime_get()), qdf_ktime_to_ns(vap->iv_next_beacon_tstamp),
                        eff_chan_time, qdf_ktime_to_ns(qdf_ktime_add(qdf_ktime_get(),
                        qdf_hrtimer_get_remaining(bpr_gen_timer))),
                        qdf_hrtimer_callback_running(bpr_gen_timer), qdf_hrtimer_is_queued(bpr_gen_timer));
                } else {

                    /* For rest of the STA sending broadcast probe requests, if the
                     * timer callback is not running and channel time is less than the remaining
                     * time in the timer, resize the timer to the channel time. Ignore if timer callback
                     * is running as it will be served by the broadcast probe response.
                     */
                    if(!qdf_hrtimer_callback_running(bpr_gen_timer) &&
                        qdf_ktime_to_ns(qdf_hrtimer_get_remaining(bpr_gen_timer)) > qdf_ktime_to_ns(eff_chan_time)) {

                        qdf_hrtimer_forward(bpr_gen_timer, qdf_hrtimer_cb_get_time(bpr_gen_timer), eff_chan_time);
                        vap->iv_bpr_timer_resize_count++;

                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                            "Resize timer: %s| %d | Sequence: %d | Delay: %d | Current time: %lld | Next beacon tstamp: %lld | effchantime: %lld | "
                            "Timer expires in: %lld | Timer cb: %d | Enqueued: %d\n", \
                            __func__, __LINE__, ((le16toh(*(u_int16_t *)wh->i_seq)) & IEEE80211_SEQ_SEQ_MASK) >> IEEE80211_SEQ_SEQ_SHIFT,
                            vap->iv_bpr_delay, qdf_ktime_to_ns(qdf_ktime_get()), qdf_ktime_to_ns(vap->iv_next_beacon_tstamp),
                            eff_chan_time, qdf_ktime_to_ns(qdf_ktime_add(qdf_ktime_get(),qdf_hrtimer_get_remaining(bpr_gen_timer))),
                            qdf_hrtimer_callback_running(bpr_gen_timer), qdf_hrtimer_is_queued(bpr_gen_timer));
                    }

                }

            } else if ((extractx.fils_sta || extractx.oce_sta) && channel_time && vap->iv_bpr_enable &&
                       (IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_myaddr) || IEEE80211_ADDR_EQ(wh->i_addr3, vap->iv_myaddr))) {

                /* If channel time is bigger than beancon interval, slightly discard the probe-req
                    as beacon will be sent instead */
                if (channel_time > ic->ic_intval) {
                    goto exit;
                }

                /* If STA sends a probe request to the VAP with some channel time, then send unicast
                 * response only if there is no beacon to be scheduled before the channel time expires.
                 * Otherwise, the beacon will be sent.
                 */
                if ((qdf_ktime_to_ns(vap->iv_next_beacon_tstamp) - QDF_NSEC_PER_MSEC * ic->ic_bcn_latency_comp) >  ktime_to_ns(eff_chan_time)) {
                    if (IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan) &&
                        ieee80211_vap_oce_check(vap)) {
                        if (rs->rs_datarate < vap->iv_prb_rate)
                            extractx.datarate = rs->rs_datarate;
                        else
                            extractx.datarate = vap->iv_prb_rate;
                    }
                    ieee80211_send_proberesp(ni, wh->i_addr2, NULL, 0, &extractx);
                    vap->iv_bpr_unicast_resp_count++;

                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                        "Unicast response sent: %s | %d | Sequence: %d | Delay: %d | Current time: %lld | Next beacon tstamp: %lld | effchantime: %lld | "
                        "beacon interval: %d ms | Timer expires in: %lld | Timer cb running: %d\n", \
                        __func__, __LINE__, ((le16toh(*(u_int16_t *)wh->i_seq)) & IEEE80211_SEQ_SEQ_MASK) >> IEEE80211_SEQ_SEQ_SHIFT,
                        vap->iv_bpr_delay, qdf_ktime_to_ns(qdf_ktime_get()), qdf_ktime_to_ns(vap->iv_next_beacon_tstamp),
                        eff_chan_time, ic->ic_intval, qdf_ktime_to_ns(qdf_ktime_add(qdf_ktime_get(),qdf_hrtimer_get_remaining(bpr_gen_timer))),
                        qdf_hrtimer_callback_running(bpr_gen_timer));

                }
            } else
#endif
            {
                /*
                 * When MBSS IE feature is enabled, we send one probe response for a broadcast
                 * probe request, so we skip sending here. Response is sent from ieee80211_input_all().
                 * It is sent here in 2 cases:
                 * 1. Non-MBSS and unicast/broadcast probe req
                 * 2. MBSS and unicast probe req
                 */
                if (!wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE) ||
                    !IEEE80211_IS_BROADCAST(wh->i_addr3)) {

                    if (IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan) &&
                        ieee80211_vap_oce_check(vap)) {
                        if (rs->rs_datarate < vap->iv_prb_rate)
                            extractx.datarate = rs->rs_datarate;
                        else
                            extractx.datarate = vap->iv_prb_rate;
                    }
                    ieee80211_send_proberesp(ni, wh->i_addr2, NULL, 0, &extractx);
                }

            }
        }
    }
    else {
        goto exit;
    }

    ret = 0;
exit:
    if(found_vap == 1 || found_null_bssid == 1)
        ieee80211_free_node(ni, WLAN_MGMT_HANDLER_ID);

    return ret;
}

