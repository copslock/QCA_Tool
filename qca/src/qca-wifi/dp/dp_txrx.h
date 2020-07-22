/*
 * Copyright (c) 2017, 2018, 2020 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */

#ifndef _DP_TXRX_H
#define _DP_TXRX_H

#include "dp_extap_mitbl.h"
#include "dp_link_aggr.h"
#include "dp_me.h"
#include <wlan_objmgr_psoc_obj.h>
#include <wlan_objmgr_pdev_obj.h>
#include <wlan_objmgr_vdev_obj.h>

typedef struct dp_pdev_extap {
	mi_node_t *miroot;    /* EXTAP MAC - IP table Root */
} dp_pdev_extap_t;

typedef struct dp_txrx_pdev_handle {
	dp_pdev_extap_t extap_hdl; /* Extap handler */
	dp_pdev_link_aggr_t lag_hdl; /* Link Aggregation handle */
	dp_pdev_me_t pdev_me_hdl; /* Pdev ME Handle */
} dp_txrx_pdev_handle_t;

typedef struct dp_vdev_txrx_handle {
	dp_vdev_me_t vdev_me;
} dp_vdev_txrx_handle_t;

typedef struct dp_soc_txrx_handle {
	dp_soc_link_aggr_t lag_hdl; /* Link Aggregation handle */
} dp_soc_txrx_handle_t;

static inline QDF_STATUS dp_vdev_ext_attach(ol_txrx_soc_handle soc, uint8_t vdev_id, uint8_t *macaddr)
{
    return dp_me_attach(soc, vdev_id, macaddr);
}

static inline dp_pdev_link_aggr_t *dp_pdev_get_lag_handle(struct wlan_objmgr_pdev *pdev)
{
    ol_txrx_soc_handle soc;
    dp_txrx_pdev_handle_t *dp_hdl;

    soc = wlan_psoc_get_dp_handle(wlan_pdev_get_psoc(pdev));

    if (!soc)
        return NULL;

    dp_hdl = cdp_pdev_get_dp_txrx_handle(soc, wlan_objmgr_pdev_get_pdev_id(pdev));

    if (!dp_hdl)
        return NULL;

    return &dp_hdl->lag_hdl;
}

static inline dp_soc_link_aggr_t *dp_soc_get_lag_handle(struct wlan_objmgr_psoc *soc)
{
    dp_soc_txrx_handle_t *dp_hdl;

    if (!soc)
        return NULL;

    dp_hdl = cdp_soc_get_dp_txrx_handle(wlan_psoc_get_dp_handle(soc));

    if (!dp_hdl)
        return NULL;

    return &dp_hdl->lag_hdl;
}


/**
 * dp_get_lag_handle() - get link aggregation handle from vdev
 * @vdev: vdev object pointer
 *
 * Return: pdev Link Aggregation handle
 */
static inline dp_pdev_link_aggr_t *dp_get_lag_handle(struct wlan_objmgr_vdev *vdev)
{
    struct wlan_objmgr_pdev *pdev;

    pdev = wlan_vdev_get_pdev(vdev);

    return dp_pdev_get_lag_handle(pdev);
}

/**
 *dp_get_vdev_me_handle() - get ME handle from vdev
 *@soc: Datapath soc handle
 *@vdev_id: vdev id
 *
 *Return: ME handle
 */
static inline dp_vdev_me_t *dp_get_vdev_me_handle(ol_txrx_soc_handle soc,
                                                  uint8_t vdev_id)
{
    dp_vdev_txrx_handle_t *dp_hdl;

    if (!soc)
        return NULL;

    dp_hdl = cdp_vdev_get_dp_ext_txrx_handle(soc, vdev_id);
    if (!dp_hdl)
        return NULL;

    return &dp_hdl->vdev_me;
}

/**
 * dp_get_pdev_me_handle() - get pdev ME handle
 * @soc: soc txrx handle
 * @pdev_id: pdev id
 *
 * Return: pdev ME handle
 */
static inline dp_pdev_me_t *dp_get_pdev_me_handle(ol_txrx_soc_handle soc,
                                                  uint8_t pdev_id)
{
    dp_txrx_pdev_handle_t *dp_hdl;

    if (!soc)
        return NULL;

    dp_hdl = cdp_pdev_get_dp_txrx_handle(soc, pdev_id);

    if (!dp_hdl)
        return NULL;

    return &dp_hdl->pdev_me_hdl;
}

/**
 * dp_get_me_mcast_table() - get ME mcast_table
 * @soc: soc txrx handle
 * @vdev_id: vdev id
 *
 * Return: ME mcast table handle
 */
static inline
struct dp_me_mcast_table *dp_get_me_mcast_table(ol_txrx_soc_handle soc,
                                                uint8_t vdev_id)
{
    dp_vdev_txrx_handle_t *dp_hdl;

    dp_hdl = cdp_vdev_get_dp_ext_txrx_handle(soc, vdev_id);

    if (!dp_hdl)
        return NULL;

    return &dp_hdl->vdev_me.me_mcast_table;
}

/**
 * dp_set_me_mode() - set if ME mode
 * @soc: soc txrx handle
 * @vdev_id : vdev_id
 * @mode : ME mode
 *
 * Return: void
 */

static inline void dp_set_me_mode(ol_txrx_soc_handle soc, uint8_t vdev_id, uint8_t mode)
{
   dp_vdev_me_t *vdev_me;

   vdev_me = dp_get_vdev_me_handle(soc, vdev_id);

   if (!vdev_me)
       return;

   vdev_me->me_mcast_mode = mode;
}

/**
 * dp_get_me_mode() - get if ME mode
 * @soc: soc txrx handle
 * @vdev_id : vdev_id
 *
 * Return: ME mode
 */

static inline uint8_t dp_get_me_mode(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
   dp_vdev_me_t *vdev_me;

   vdev_me = dp_get_vdev_me_handle(soc, vdev_id);

   if (!vdev_me)
       return MC_ME_DISABLE;

   return vdev_me->me_mcast_mode;
}

/**
 * dp_get_me_mcast_lock() - get ME lock
 * @soc: soc txrx handle
 * @vdev_id : vdev_id
 *
 * Return: me lock pointer
 */
static inline
rwlock_t *dp_get_me_mcast_lock(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
   dp_vdev_me_t *vdev_me;

   vdev_me = dp_get_vdev_me_handle(soc, vdev_id);

   if (!vdev_me)
       return NULL;

   return &vdev_me->me_mcast_lock;
}

#endif /* _DP_TXRX_H */
