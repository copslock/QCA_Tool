/*
 * Copyright (c) 2019-2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef __NLCFG_FAMILY_H
#define __NLCFG_FAMILY_H

#include "nlcfg_ipv4.h"
#include "nlcfg_ipv6.h"
#include "nlcfg_ipsec.h"
#include "nlcfg_gre_redir.h"
#include "nlcfg_capwap.h"
#include "nlcfg_dtls.h"

/*
 * Family match params
 */
extern struct nlcfg_param nlcfg_ipv4_params[NLCFG_IPV4_CMD_MAX];
extern struct nlcfg_param nlcfg_ipv6_params[NLCFG_IPV6_CMD_MAX];
extern struct nlcfg_param nlcfg_ipsec_params[NLCFG_IPSEC_CMD_MAX];
extern struct nlcfg_param nlcfg_gre_redir_params[NLCFG_GRE_REDIR_CMD_TYPE_MAX];
extern struct nlcfg_param nlcfg_capwap_params[NLCFG_CAPWAP_CMD_TYPE_MAX];
extern struct nlcfg_param nlcfg_dtls_params[NLCFG_DTLS_CMD_TYPE_MAX];

#endif /* __NLCFG_FAMILY_H*/
