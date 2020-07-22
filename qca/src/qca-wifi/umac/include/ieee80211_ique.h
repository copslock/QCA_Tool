/*
 * Copyright (c) 2011,2017,2020 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 *  Copyright (c) 2009 Atheros Communications Inc.
 *  All Rights Reserved.
 *
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 *
 *  Header file for IQUE feature.
 */

#ifndef _IEEE80211_IQUE_H_
#define _IEEE80211_IQUE_H_

#include "osdep.h"
#include "wbuf.h"
#include "ieee80211.h"

struct ieee80211_node;
struct ieee80211vap;

/*
 * mcast enhancement ops
 */
struct ieee80211_ique_ops {
    /*
     * functions for headline block removal (HBR)
     */
    void    (*hbr_detach)(struct ieee80211vap *);
    void    (*hbr_nodejoin)(struct ieee80211vap *, struct ieee80211_node *);
    void    (*hbr_nodeleave)(struct ieee80211vap *, struct ieee80211_node *);
    int     (*hbr_dropblocked)(struct ieee80211vap *, struct ieee80211_node *, wbuf_t);
    void    (*hbr_set_probing)(struct ieee80211vap *, struct ieee80211_node *, wbuf_t, u_int8_t);
    void    (*hbr_sendevent)(struct ieee80211vap *, u_int8_t *, int);
    void    (*hbr_dump)(struct ieee80211vap *);
    void    (*hbr_settimer)(struct ieee80211vap *, u_int32_t);
};

#if ATH_SUPPORT_IQUE
/*
 * For HBR (headline block removal)
 */

typedef enum {
    IEEE80211_HBR_STATE_ACTIVE,
    IEEE80211_HBR_STATE_BLOCKING,
    IEEE80211_HBR_STATE_PROBING,
} ieee80211_hbr_state;

typedef enum {
    IEEE80211_HBR_EVENT_BACK,
    IEEE80211_HBR_EVENT_FORWARD,
    IEEE80211_HBR_EVENT_STALE,
}ieee80211_hbr_event;

struct ieee80211_hbr_list;

int ieee80211_hbr_attach(struct ieee80211vap * vap);

#if ATH_SUPPORT_HBR
#define ieee80211_ique_attach(ret, _vap) do {\
                                              ret = ieee80211_hbr_attach(_vap);\
                                            } while(0)
#else
#define ieee80211_ique_attach(ret, _vap) do {\
                                            } while(0)
#endif

#else

#define ieee80211_ique_attach(ret, _vap) do { OS_MEMZERO(&((_vap)->iv_ique_ops), sizeof(struct ieee80211_ique_ops)); ret = 0;} while(0)

#endif /*ATH_SUPPORT_IQUE*/

#endif /* _IEEE80211_IQUE_H_ */
