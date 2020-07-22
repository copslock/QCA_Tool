/*
 * Copyright (c) 2019-2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef __NSS_NLBASE_H__
#define __NSS_NLBASE_H__

/*
 * TODO: Remove inter-dependencies between the header files.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <linux/socket.h>
#include <net/if.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/if_ether.h>

/* Generic Netlink header */
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>

#if !defined (likely) || !defined (unlikely)
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* NSS headers */
#include <nss_arch.h>
#include <nss_def.h>
#include <nss_cmn.h>
#include <nss_ipsecmgr.h>
#include <nss_ipv4.h>
#include <nss_ipv6.h>
#include <nss_nlcmn_if.h>
#include <nss_dtls_cmn.h>
#include <nss_dtlsmgr.h>
#include <nss_capwap.h>
#include <nss_nl_if.h>
#include <nss_nlsock_api.h>
#include <nss_nlcapwap_if.h>
#include <nss_nlcapwap_api.h>
#include <nss_nldtls_if.h>
#include <nss_nldtls_api.h>
#include <nss_nlist_api.h>
#include <nss_nlipsec_if.h>
#include <nss_nlipsec_api.h>
#include <nss_nlipv4_if.h>
#include <nss_nlipv4_api.h>
#include <nss_nlipv6_if.h>
#include <nss_nlipv6_api.h>
#include <nss_nlgre_redir_if.h>
#include <nss_nlgre_redir_api.h>
#include <nss_nlmcast_api.h>
#endif /* !__NSS_NLBASE_H__*/
