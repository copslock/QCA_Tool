#ifndef _SPIRENT_NG_H_
#define _SPIRENT_NG_H_
#include "wlan_scan_cache_db.h"
#include <wlan_objmgr_pdev_obj.h>
#include <ieee80211_var.h>
#include <ieee80211.h>
#include <ieee80211_channel.h>

#define NG_AP_RX_PARAM_SNR      24
#define NG_AP_RX_PARAM_RSSI     3072

bool ng_check_bssid_matched(struct wlan_objmgr_psoc *psoc, struct scan_cache_node *node);
void util_scan_parse_ng_beacon_frame(struct wlan_objmgr_pdev *pdev, 
   				qdf_list_t *scan_list);
wlan_chan_t ng_wlan_scan_cache_update_callback(struct wlan_objmgr_pdev *pdev,
        struct scan_cache_entry* scan_entry);

#endif