/*
* Copyright (c) 2016, 2018-2019 Qualcomm Innovation Center, Inc.
* All Rights Reserved.
* Confidential and Proprietary - Qualcomm Innovation Center, Inc.
*
*/

/*
 * 2016 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <net/genetlink.h>
#include <linux/netlink.h>
#include <ieee80211_var.h>
#include <qdf_types.h> /* qdf_print */

#if ATH_SUPPORT_LOWI
#include "ol_if_athvar.h"
#include "ieee80211_rtt.h"
#include "ath_lowi_if.h"
#include "wifi_pos_api.h"

#define LOWI_MESSAGE_SUBIE_AND_LEN_OCTETS  2

/* Send Where are you action frame */
/* Function     : ieee80211_lowi_send_wru_frame
 * Arguments    : Pointer to data for WRU frame
 * Functionality: Creates and sends Where are you action frame
 * Return       : Void
 */
void ieee80211_lowi_send_wru_frame (struct wlan_objmgr_psoc *psoc, u_int8_t *data)
{
    struct ieee80211_node *ni = NULL;
    struct ieee80211vap * vap = NULL;
    wbuf_t wbuf = NULL;
    u_int8_t *frm = NULL;
    struct ieee80211com *ic = NULL;
    struct wru_lci_request *wru = (struct wru_lci_request *)data;
    struct ieee80211_ftmrrreq *actionbuf;
    struct wlan_objmgr_peer *peer;

    peer = wlan_objmgr_get_peer_by_mac(psoc, &wru->sta_mac[0], WLAN_RTT_ID);
    if(peer == NULL) {
        qdf_err("%s: Could not find node[%s] in associated nodes table.", __func__, ether_sprintf(&wru->sta_mac[0]));
        return;
    }
    ni = wlan_peer_get_mlme_ext_obj(peer);
    if (!ni)
    {
        qdf_err("Unable to get ni");
        wlan_objmgr_peer_release_ref(peer, WLAN_RTT_ID);
        return;
    }
    ic = ni->ni_ic;
    /* Get VAP where this node is associated */
    vap = ni->ni_vap;
    /* Make sure this VAP is active and in AP mode */
    if ((wlan_vdev_chan_config_valid(vap->vdev_obj) != QDF_STATUS_SUCCESS) ||
        (IEEE80211_M_HOSTAP != vap->iv_opmode)) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_WIFIPOS,
             "%s: ERROR: VAP is either not active or not in AP mode. Not sending WRU frame\n", __func__);
        wlan_objmgr_peer_release_ref(peer, WLAN_RTT_ID);
        return;
    }
    wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
    if (wbuf == NULL) {
        ieee80211_free_node(ni, WLAN_RTT_ID);
        return;
    }
    actionbuf = (struct ieee80211_ftmrrreq *)frm;
    actionbuf->header.ia_category = IEEE80211_ACTION_CAT_RADIO;
    actionbuf->header.ia_action = IEEE80211_ACTION_MEAS_REQUEST;
    actionbuf->dialogtoken = wru->dialogtoken;
    actionbuf->num_repetitions = htole16(wru->num_repetitions);
    frm = &actionbuf->elem[0];

    OS_MEMCPY(frm, &(wru->id), wru->len + LOWI_MESSAGE_SUBIE_AND_LEN_OCTETS); //include id and len fields while copying
    frm += wru->len + LOWI_MESSAGE_SUBIE_AND_LEN_OCTETS;
    wbuf_set_pktlen(wbuf, (frm - (u_int8_t*)wbuf_header(wbuf)));
    /* If Managment Frame protection is enabled (PMF or Cisco CCX), set Privacy bit */
    if ((vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_is_mfp &&
        vap->iv_ccx_evtable->wlan_ccx_is_mfp(vap->iv_ifp)) ||
        ((ieee80211_vap_mfp_test_is_set(vap) ||
#ifdef WLAN_CONV_CRYPTO_SUPPORTED
              (wlan_crypto_is_pmf_enabled(vap->vdev_obj, ni->peer_obj))))) {
#else
              ieee80211_is_pmf_enabled(vap, ni)) && ni->ni_ucastkey.wk_valid)){
#endif
        /* MFP is enabled, so we need to set Privacy bit */
        struct ieee80211_frame *wh;
        wh = (struct ieee80211_frame*)wbuf_header(wbuf);
        wh->i_fc[1] |= IEEE80211_FC1_WEP;
    }
    ieee80211_send_mgmt(vap, ni, wbuf, false);
    qdf_print("Where Are you frame successfully sent for %s", ether_sprintf(&wru->sta_mac[0]));
    ieee80211_free_node(ni, WLAN_RTT_ID);    /* reclaim node */
    return;
}

/* Send FTMRR action frame */
/* Function     : ieee80211_lowi_send_ftmrr_frame
 * Arguments    : Pointer to data for FTMRR frame
 * Functionality: Creates and sends FTMRR action frame
 * Return       : Void
 */
void ieee80211_lowi_send_ftmrr_frame(struct wlan_objmgr_psoc *psoc, u_int8_t *data)
{
    struct ieee80211_node *ni = NULL;
    struct ieee80211vap * vap = NULL;
    wbuf_t wbuf = NULL;
    u_int8_t *frm = NULL;
    struct ieee80211com *ic = NULL;
    struct ftmrr_request *ftmrr = (struct ftmrr_request *)data;
    struct ieee80211_ftmrrreq *actionbuf;
    struct wlan_objmgr_peer *peer;

    peer = wlan_objmgr_get_peer_by_mac(psoc, &ftmrr->sta_mac[0], WLAN_RTT_ID);
    if(peer == NULL) {
        qdf_err("%s: Could not find node[%s] in associated nodes table.", __func__, ether_sprintf(&ftmrr->sta_mac[0]));
        return;
    }
    ni = wlan_peer_get_mlme_ext_obj(peer);
    if (!ni)
    {
        qdf_err("Unable to get ni");
        wlan_objmgr_peer_release_ref(peer, WLAN_RTT_ID);
        return;
    }
    ic = ni->ni_ic;
    /* Get VAP where this node is associated */
    vap = ni->ni_vap;
    /* Make sure vap is active and  in AP mode, else do not FTMRR frame */
    if ((wlan_vdev_chan_config_valid(vap->vdev_obj) != QDF_STATUS_SUCCESS) ||
        (IEEE80211_M_HOSTAP != vap->iv_opmode)) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_WIFIPOS,
            "%s: ERROR: Vap is either not active or not in AP mode. Not sending FTMRR frame\n", __func__);
        wlan_objmgr_peer_release_ref(peer, WLAN_RTT_ID);
        return;
    }
    wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
    if (wbuf == NULL) {
        ieee80211_free_node(ni, WLAN_RTT_ID);
        return;
    }
    actionbuf = (struct ieee80211_ftmrrreq *)frm;
    actionbuf->header.ia_category = IEEE80211_ACTION_CAT_RADIO;
    actionbuf->header.ia_action = IEEE80211_ACTION_MEAS_REQUEST;
    actionbuf->dialogtoken = ftmrr->dialogtoken;
    actionbuf->num_repetitions = htole16(ftmrr->num_repetitions);
    frm = &actionbuf->elem[0];

    OS_MEMCPY(frm, &(ftmrr->id), ftmrr->len + LOWI_MESSAGE_SUBIE_AND_LEN_OCTETS); //include id and len fields while copying
    frm += ftmrr->len + LOWI_MESSAGE_SUBIE_AND_LEN_OCTETS;
    wbuf_set_pktlen(wbuf, (frm - (u_int8_t*)wbuf_header(wbuf)));
    /* If Managment Frame protection is enabled (PMF or Cisco CCX), set Privacy bit */
    if ((vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_is_mfp &&
        vap->iv_ccx_evtable->wlan_ccx_is_mfp(vap->iv_ifp)) ||
        ((ieee80211_vap_mfp_test_is_set(vap) ||
#ifdef WLAN_CONV_CRYPTO_SUPPORTED
              (wlan_crypto_is_pmf_enabled(vap->vdev_obj, ni->peer_obj))))) {
#else
              ieee80211_is_pmf_enabled(vap, ni)) && ni->ni_ucastkey.wk_valid)){
#endif
        /* MFP is enabled, so we need to set Privacy bit */
        struct ieee80211_frame *wh;
        wh = (struct ieee80211_frame*)wbuf_header(wbuf);
        wh->i_fc[1] |= IEEE80211_FC1_WEP;
    }
    ieee80211_send_mgmt(vap, ni, wbuf, false);
    qdf_print("FTMRR frame successfully sent for %s", ether_sprintf(&ftmrr->sta_mac[0]));
    ieee80211_free_node(ni, WLAN_RTT_ID);    /* reclaim node */
    return;
}

void wifi_pos_send_action_cb(struct wlan_objmgr_psoc *psoc,
                             uint32_t oem_sub_type, uint8_t *req, uint32_t len)
{
    int req_id;

    switch (oem_sub_type) {
    case TARGET_OEM_CONFIGURE_WRU:
        qdf_info("%s: Received Where Are You frame request from LOWI ", __func__);
        ieee80211_lowi_send_wru_frame(psoc, req + LOWI_MESSAGE_WRU_POSITION); //remove subtype(4),req_id(4)
        req_id = *((u_int8_t *)req+LOWI_MESSAGE_REQ_ID_POSITION);
        wifi_pos_send_report_resp(psoc, req_id, req+LOWI_MESSAGE_WRU_POSITION, LOWI_LCI_REQ_WRU_OK);
        return;

    case TARGET_OEM_CONFIGURE_FTMRR:
        qdf_info("%s: Received FTMRR frame request from LOWI ", __func__);
        ieee80211_lowi_send_ftmrr_frame(psoc, req + LOWI_MESSAGE_FTMRR_POSITION); //remove subtype(4),req_id(4)
        req_id = *((u_int8_t *)req+LOWI_MESSAGE_REQ_ID_POSITION);
        wifi_pos_send_report_resp(psoc, req_id, req+LOWI_MESSAGE_FTMRR_POSITION, LOWI_FTMRR_OK);
        return;
    }
}

void wifi_pos_register_cbs(struct wlan_objmgr_psoc *psoc)
{
    wifi_pos_register_send_action(psoc, wifi_pos_send_action_cb);
}
qdf_export_symbol(wifi_pos_register_cbs);
#endif /* ATH_SUPPORT_LOWI */
