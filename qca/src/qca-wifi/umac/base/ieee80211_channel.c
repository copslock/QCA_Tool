/*
 * Copyright (c) 2011-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 */

#include <ieee80211_var.h>
#include <ieee80211_channel.h>
#include <ieee80211_api.h>
#include <ieee80211_rateset.h>
#if UNIFIED_SMARTANTENNA
#include <wlan_sa_api_utils_api.h>
#endif
#include <qdf_lock.h>
#include <ieee80211_mlme_dfs_dispatcher.h>
#include <wlan_objmgr_psoc_obj.h>
#include <wlan_objmgr_pdev_obj.h>
#include <wlan_lmac_if_api.h>
#include <osif_private.h>
#include <wlan_reg_services_api.h>
#include <ieee80211_regdmn_dispatcher.h>
#include <wlan_mlme_dispatcher.h>
#include <wlan_vdev_mlme_api.h>
#include <wlan_utility.h>
#include <ieee80211_objmgr_priv.h>

int ieee80211_ucfg_set_chanswitch(wlan_if_t vaphandle, uint16_t chan_freq, u_int8_t tbtt, u_int16_t ch_width);

const char *ieee80211_phymode_name[] = {
    "auto",             /* IEEE80211_MODE_AUTO */
    "11a",              /* IEEE80211_MODE_11A */
    "11b",              /* IEEE80211_MODE_11B */
    "11g",              /* IEEE80211_MODE_11G */
    "FH",               /* IEEE80211_MODE_FH */
    "turboA",           /* IEEE80211_MODE_TURBO_A */
    "turboG",           /* IEEE80211_MODE_TURBO_G */
    "11naht20",         /* IEEE80211_MODE_11NA_HT20 */
    "11nght20",         /* IEEE80211_MODE_11NG_HT20 */
    "11naht40plus",     /* IEEE80211_MODE_11NA_HT40PLUS */
    "11naht40minus",    /* IEEE80211_MODE_11NA_HT40MINUS */
    "11nght40plus",     /* IEEE80211_MODE_11NG_HT40PLUS */
    "11nght40minus",    /* IEEE80211_MODE_11NG_HT40MINUS */
    "11nght40",         /* IEEE80211_MODE_11NG_HT40 */
    "11naht40",         /* IEEE80211_MODE_11NA_HT40 */
    "11acvht20",        /* IEEE80211_MODE_11AC_VHT20 */
    "11acvht40plus",    /* IEEE80211_MODE_11AC_VHT40PLUS */
    "11acvht40minus",   /* IEEE80211_MODE_11AC_VHT40MINUS */
    "11acvht40",        /* IEEE80211_MODE_11AC_VHT40 */
    "11acvht80",        /* IEEE80211_MODE_11AC_VHT80 */
    "11acvht160",       /* IEEE80211_MODE_11AC_VHT160 */
    "11acvht80_80",     /* IEEE80211_MODE_11AC_VHT80_80 */
    "11axahe20",        /* IEEE80211_MODE_11AXA_HE20 */
    "11axghe20",        /* IEEE80211_MODE_11AXG_HE20 */
    "11axahe40plus",    /* IEEE80211_MODE_11AXA_HE40PLUS */
    "11axahe40minus",   /* IEEE80211_MODE_11AXA_HE40MINUS */
    "11axghe40plus",    /* IEEE80211_MODE_11AXG_HE40PLUS */
    "11axghe40minus",   /* IEEE80211_MODE_11AXG_HE40MINUS */
    "11axahe40",        /* IEEE80211_MODE_11AXA_HE40 */
    "11axghe40",        /* IEEE80211_MODE_11AXG_HE40 */
    "11axahe80",        /* IEEE80211_MODE_11AXA_HE80 */
    "11axahe160",       /* IEEE80211_MODE_11AXA_HE160 */
    "11axahe80_80",     /* IEEE80211_MODE_11AXA_HE80_80 */
};

/*
 * Return the phy mode for with the specified channel.
 */
enum ieee80211_phymode
ieee80211_chan2mode(const struct ieee80211_ath_channel *chan)
{
    if (IEEE80211_IS_CHAN_108G(chan))
        return IEEE80211_MODE_TURBO_G;
    else if (IEEE80211_IS_CHAN_TURBO(chan))
        return IEEE80211_MODE_TURBO_A;
    else if (IEEE80211_IS_CHAN_A(chan))
        return IEEE80211_MODE_11A;
    else if (IEEE80211_IS_CHAN_ANYG(chan))
        return IEEE80211_MODE_11G;
    else if (IEEE80211_IS_CHAN_B(chan))
        return IEEE80211_MODE_11B;
    else if (IEEE80211_IS_CHAN_FHSS(chan))
        return IEEE80211_MODE_FH;
    else if (IEEE80211_IS_CHAN_11NA_HT20(chan))
        return IEEE80211_MODE_11NA_HT20;
    else if (IEEE80211_IS_CHAN_11NG_HT20(chan))
        return IEEE80211_MODE_11NG_HT20;
    else if (IEEE80211_IS_CHAN_11NA_HT40PLUS(chan))
        return IEEE80211_MODE_11NA_HT40PLUS;
    else if (IEEE80211_IS_CHAN_11NA_HT40MINUS(chan))
        return IEEE80211_MODE_11NA_HT40MINUS;
    else if (IEEE80211_IS_CHAN_11NG_HT40PLUS(chan))
        return IEEE80211_MODE_11NG_HT40PLUS;
    else if (IEEE80211_IS_CHAN_11NG_HT40MINUS(chan))
        return IEEE80211_MODE_11NG_HT40MINUS;
    else if (IEEE80211_IS_CHAN_11AC_VHT20(chan))
        return IEEE80211_MODE_11AC_VHT20;
    else if (IEEE80211_IS_CHAN_11AC_VHT40PLUS(chan))
        return IEEE80211_MODE_11AC_VHT40PLUS;
    else if (IEEE80211_IS_CHAN_11AC_VHT40MINUS(chan))
        return IEEE80211_MODE_11AC_VHT40MINUS;
    else if (IEEE80211_IS_CHAN_11AC_VHT80(chan))
        return IEEE80211_MODE_11AC_VHT80;
    else if (IEEE80211_IS_CHAN_11AC_VHT160(chan))
        return IEEE80211_MODE_11AC_VHT160;
    else if (IEEE80211_IS_CHAN_11AC_VHT80_80(chan))
        return IEEE80211_MODE_11AC_VHT80_80;
     else if (IEEE80211_IS_CHAN_11AXA_HE20(chan))
         return IEEE80211_MODE_11AXA_HE20;
     else if (IEEE80211_IS_CHAN_11AXG_HE20(chan))
         return IEEE80211_MODE_11AXG_HE20;
     else if (IEEE80211_IS_CHAN_11AXA_HE40PLUS(chan))
         return IEEE80211_MODE_11AXA_HE40PLUS;
     else if (IEEE80211_IS_CHAN_11AXA_HE40MINUS(chan))
         return IEEE80211_MODE_11AXA_HE40MINUS;
     else if (IEEE80211_IS_CHAN_11AXG_HE40PLUS(chan))
         return IEEE80211_MODE_11AXG_HE40PLUS;
     else if (IEEE80211_IS_CHAN_11AXG_HE40MINUS(chan))
         return IEEE80211_MODE_11AXG_HE40MINUS;
     else if (IEEE80211_IS_CHAN_11AXA_HE80(chan))
         return IEEE80211_MODE_11AXA_HE80;
     else if (IEEE80211_IS_CHAN_11AXA_HE160(chan))
         return IEEE80211_MODE_11AXA_HE160;
     else if (IEEE80211_IS_CHAN_11AXA_HE80_80(chan))
         return IEEE80211_MODE_11AXA_HE80_80;

    /* NB: should not get here */
     if (printk_ratelimit()) {
         qdf_info("%s: cannot map channel to mode; freq %u flags 0x%llx",
                 __func__, chan->ic_freq, chan->ic_flags);
     }
    return IEEE80211_MODE_11B;
}

char
ieee80211_get_vap_mode(wlan_if_t vaphandle)
{
    /* 11AX TODO - Add 11ax processing here if required in the future. Currently,
     * 11ac too is not processed.
     */
    int mode = vaphandle->iv_cur_mode;
    switch (mode) {
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NA_HT40:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NA_HT40PLUS:
            return 'n';
        case IEEE80211_MODE_11A:
            return 'a';
        case IEEE80211_MODE_11G:
            return 'g';
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40PLUS:
            return 'n';
        case IEEE80211_MODE_11B:
            return 'b';
        default:
            return 'f';
    }
}

/*
 * Check for Channel and Mode consistency. If channel and mode mismatches, return error.
 */
#define IEEE80211_MODE_TURBO_STATIC_A   IEEE80211_MODE_MAX
int
ieee80211_check_chan_mode_consistency(struct ieee80211com *ic,int mode,struct ieee80211_ath_channel *c)
{
    if (c == IEEE80211_CHAN_ANYC) return 0;

    switch (mode)
    {
    case IEEE80211_MODE_11B:
        if(IEEE80211_IS_CHAN_B(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11G:
        if(IEEE80211_IS_CHAN_ANYG(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11A:
        if(IEEE80211_IS_CHAN_A(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_TURBO_STATIC_A:
        if(IEEE80211_IS_CHAN_A(c) && IEEE80211_IS_CHAN_STURBO(c) )
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_AUTO:
        return 0;
        break;

    case IEEE80211_MODE_11NG_HT20:
        if(IEEE80211_IS_CHAN_11NG_HT20(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11NG_HT40PLUS:
        if(IEEE80211_IS_CHAN_11NG_HT40PLUS(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11NG_HT40MINUS:
        if(IEEE80211_IS_CHAN_11NG_HT40MINUS(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11NG_HT40:
        if(IEEE80211_IS_CHAN_11NG_HT40MINUS(c) || IEEE80211_IS_CHAN_11NG_HT40PLUS(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11NA_HT20:
        if(IEEE80211_IS_CHAN_11NA_HT20(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11NA_HT40PLUS:
        if(IEEE80211_IS_CHAN_11NA_HT40PLUS(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11NA_HT40MINUS:
        if(IEEE80211_IS_CHAN_11NA_HT40MINUS(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11NA_HT40:
        if(IEEE80211_IS_CHAN_11NA_HT40MINUS(c) || IEEE80211_IS_CHAN_11NA_HT40PLUS(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AC_VHT20:
        if(IEEE80211_IS_CHAN_11AC_VHT20(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AC_VHT40PLUS:
        if(IEEE80211_IS_CHAN_11AC_VHT40PLUS(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AC_VHT40MINUS:
        if(IEEE80211_IS_CHAN_11AC_VHT40MINUS(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AC_VHT40:
        if(IEEE80211_IS_CHAN_11AC_VHT40(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AC_VHT80:
        if(IEEE80211_IS_CHAN_11AC_VHT80(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AC_VHT160:
        if(IEEE80211_IS_CHAN_11AC_VHT160(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AC_VHT80_80:
        if(IEEE80211_IS_CHAN_11AC_VHT80_80(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AXA_HE20:
        if(IEEE80211_IS_CHAN_11AXA_HE20(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AXG_HE20:
        if(IEEE80211_IS_CHAN_11AXG_HE20(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AXA_HE40PLUS:
        if(IEEE80211_IS_CHAN_11AXA_HE40PLUS(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AXA_HE40MINUS:
        if(IEEE80211_IS_CHAN_11AXA_HE40MINUS(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AXG_HE40PLUS:
        if(IEEE80211_IS_CHAN_11AXG_HE40PLUS(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AXG_HE40MINUS:
        if(IEEE80211_IS_CHAN_11AXG_HE40MINUS(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AXA_HE40:
        if(IEEE80211_IS_CHAN_11AXA_HE40(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AXG_HE40:
        if(IEEE80211_IS_CHAN_11AXG_HE40(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AXA_HE80:
        if(IEEE80211_IS_CHAN_11AXA_HE80(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AXA_HE160:
        if(IEEE80211_IS_CHAN_11AXA_HE160(c))
            return 0;
        else
            return -EINVAL;
        break;

    case IEEE80211_MODE_11AXA_HE80_80:
        if(IEEE80211_IS_CHAN_11AXA_HE80_80(c))
            return 0;
        else
            return -EINVAL;
        break;
    }

    return -EINVAL;
}
#undef  IEEE80211_MODE_TURBO_STATIC_A

void
ieee80211_channel_notify_to_app(struct ieee80211com *ic)
{
    char buf[128];

    snprintf(buf, sizeof(buf),
            "DFS_UPDATE: Radar found, is_chan_available = %u", !ic->no_chans_available);

    osif_update_dfs_info_to_app(ic, buf);
}

/*
 * Locate a channel given a frequency+flags.  We cache
 * the previous lookup to optimize swithing between two
 * channels--as happens with dynamic turbo.
 * This verifies that found channels have not been excluded because of 11d.
 */
struct ieee80211_ath_channel *
ieee80211_find_channel(struct ieee80211com *ic, int freq, uint16_t des_cfreq2, u_int64_t flags)
{
    struct ieee80211_ath_channel *c;
    int i;

    flags &= IEEE80211_CHAN_ALLTURBO;
    c = ic->ic_prevchan;
    if ((c != NULL) &&
            (! IEEE80211_IS_CHAN_11D_EXCLUDED(c)) &&
            (c->ic_freq == freq) &&
            ((c->ic_flags & IEEE80211_CHAN_ALLTURBO) == flags)) {
        if (IEEE80211_IS_CHAN_BW_80_80(c)) {
            if (c->ic_vhtop_freq_seg2 == des_cfreq2) {
                return c;
            }
        }
        else {
            return c;
        }
    }

    /* brute force search */
    for (i = 0; i < ic->ic_nchans; i++) {
        c = &ic->ic_channels[i];

        if ((! IEEE80211_IS_CHAN_11D_EXCLUDED(c)) &&
                (c->ic_freq == freq) &&
                ((c->ic_flags & IEEE80211_CHAN_ALLTURBO) == flags)) {
            if (IEEE80211_IS_CHAN_BW_80_80(c)) {
                if (des_cfreq2 == 0 || c->ic_vhtop_freq_seg2 == des_cfreq2) {
                    return c;
                }
            }
            else {
                return c;
            }
        }
    }

    return NULL;
}
#ifdef __linux__
//#ifndef ATH_WLAN_COMBINE
#endif
struct ieee80211_ath_channel *
ieee80211_doth_findchan(struct ieee80211vap *vap, uint16_t chan_freq)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_ath_channel *c;
    u_int64_t flags;

    /* NB: try first to preserve turbo */
    flags = vap->iv_bsschan->ic_flags & IEEE80211_CHAN_ALL;
    c = ieee80211_find_channel(ic, chan_freq, vap->iv_des_cfreq2, flags);
    if (c == NULL)
        c = ieee80211_find_channel(ic, chan_freq, 0, 0);
    return c;
}

uint64_t ieee80211_get_band_flag(uint16_t freq)
{
    uint64_t band_flag = 0;

    if (WLAN_REG_IS_24GHZ_CH_FREQ(freq)) {
        band_flag = IEEE80211_CHAN_2GHZ;
    } else if (WLAN_REG_IS_5GHZ_CH_FREQ(freq)) {
        band_flag = IEEE80211_CHAN_5GHZ;
    } else if (WLAN_REG_IS_6GHZ_CHAN_FREQ(freq)) {
        band_flag = IEEE80211_CHAN_6GHZ;
    } else if (WLAN_REG_IS_49GHZ_FREQ (freq)) {
        band_flag = IEEE80211_CHAN_5GHZ;
    }

    return band_flag;
}

/*
 * Locate the channel given channel number and mode
 */
struct ieee80211_ath_channel *
ieee80211_find_dot11_channel(struct ieee80211com *ic, uint16_t freq, uint16_t freq2, enum ieee80211_phymode mode)
{
    /* TODO: When making regulatory changes for 11AC please, please optimize this function */

    static const u_int64_t chanflags[] = {
        0,                              /* IEEE80211_MODE_AUTO */
        IEEE80211_CHAN_A,               /* IEEE80211_MODE_11A */
        IEEE80211_CHAN_B,               /* IEEE80211_MODE_11B */
        IEEE80211_CHAN_PUREG,           /* IEEE80211_MODE_11G */
        IEEE80211_CHAN_FHSS,            /* IEEE80211_MODE_FH */
        IEEE80211_CHAN_108A,            /* IEEE80211_MODE_TURBO_A */
        IEEE80211_CHAN_108G,            /* IEEE80211_MODE_TURBO_G */
        IEEE80211_CHAN_HT20,       /* IEEE80211_MODE_11NA_HT20 */
        IEEE80211_CHAN_HT20,       /* IEEE80211_MODE_11NG_HT20 */
        IEEE80211_CHAN_HT40PLUS,   /* IEEE80211_MODE_11NA_HT40PLUS */
        IEEE80211_CHAN_HT40MINUS,  /* IEEE80211_MODE_11NA_HT40MINUS */
        IEEE80211_CHAN_HT40PLUS,   /* IEEE80211_MODE_11NG_HT40PLUS */
        IEEE80211_CHAN_HT40MINUS,  /* IEEE80211_MODE_11NG_HT40MINUS */
        0,                              /* IEEE80211_MODE_11NG_HT40 */
        0,                              /* IEEE80211_MODE_11NA_HT40 */
        IEEE80211_CHAN_VHT20,      /* IEEE80211_MODE_11AC_VHT20 */
        IEEE80211_CHAN_VHT40PLUS,  /* IEEE80211_MODE_11AC_VHT40PLUS */
        IEEE80211_CHAN_VHT40MINUS, /* IEEE80211_MODE_11AC_VHT40MINUS */
        0,                              /* IEEE80211_MODE_11AC_VHT40 */
        IEEE80211_CHAN_VHT80,      /* IEEE80211_MODE_11AC_VHT80 */
        IEEE80211_CHAN_VHT160,     /* IEEE80211_MODE_11AC_VHT160 */
        IEEE80211_CHAN_VHT80_80,   /* IEEE80211_MODE_11AC_VHT80_80 */
        IEEE80211_CHAN_HE20,      /* IEEE80211_MODE_11AXA_HE20 */
        IEEE80211_CHAN_HE20,      /* IEEE80211_MODE_11AXG_HE20 */
        IEEE80211_CHAN_HE40PLUS,  /* IEEE80211_MODE_11AXA_HE40PLUS */
        IEEE80211_CHAN_HE40MINUS, /* IEEE80211_MODE_11AXA_HE40MINUS */
        IEEE80211_CHAN_HE40PLUS,  /* IEEE80211_MODE_11AXG_HE40PLUS */
        IEEE80211_CHAN_HE40MINUS, /* IEEE80211_MODE_11AXG_HE40MINUS */
        0,                              /* IEEE80211_MODE_11AXA_HE40 */
        0,                              /* IEEE80211_MODE_11AXG_HE40 */
        IEEE80211_CHAN_HE80,      /* IEEE80211_MODE_11AXA_HE80 */
        IEEE80211_CHAN_HE160,     /* IEEE80211_MODE_11AXA_HE160 */
        IEEE80211_CHAN_HE80_80,   /* IEEE80211_MODE_11AXA_HE80_80 */
        IEEE80211_CHAN_ST,              /* IEEE80211_MODE_TURBO_STATIC_A */
    };
    uint64_t modeflags;
    uint64_t band_flag = ieee80211_get_band_flag(freq);
    int i;

    modeflags = mode & (IEEE80211_CHAN_HALF | IEEE80211_CHAN_QUARTER);
    mode &= ~modeflags;
    modeflags |= chanflags[mode] | band_flag;

    for (i = 0; i < ic->ic_nchans; i++) {
        struct ieee80211_ath_channel *c = &ic->ic_channels[i];
        struct ieee80211_ath_channel *nc;

        band_flag = ieee80211_get_band_flag(c->ic_freq);;
        if (freq && (c->ic_freq != freq))
            continue;

        if (mode == IEEE80211_MODE_AUTO) {
            wlan_if_t vap;
            uint32_t des_hw_mode = 0;

            if (!TAILQ_EMPTY(&ic->ic_vaps)) {
                vap =  TAILQ_FIRST(&(ic)->ic_vaps);
            } else {
                qdf_err("%s: ic_vaps is NULL, Returning\n",__func__);
                return NULL;
            }

            if (IEEE80211_IS_CHAN_TURBO(c)) {
                /* ignore turbo channels for autoselect */
                continue;
            }

            if (IEEE80211_IS_CHAN_2GHZ(c)) {
                /*
                 * In IEEE80211_MODE_AUTO mode we make the desired hw mode as
                 * 11AXG to maintain the same precedence as above.
                 */
                if(vap->iv_des_hw_mode == IEEE80211_MODE_AUTO) {
                    des_hw_mode = IEEE80211_MODE_11AXG_HE40;
                }
                else {
                    des_hw_mode = vap->iv_des_hw_mode;
                }

               /*
                 * Check if ic supports the mode
                 * Check if des_hw_mode is greater or at lest equal to the mode.
                 * Check if the mode should be allowed for IBSS operation mode.
                 * Try to find the channel in the present mode, if found return the channel,
                 * otherwise, procede to next lower mode.
                 */

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11AXG_HE40)) &&
                   ((des_hw_mode >= IEEE80211_MODE_11AXG_HE40)) &&
                    ((ic->ic_opmode != IEEE80211_M_IBSS) || ieee80211_ic_ht40Adhoc_is_set(ic)) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_HE20)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11AXG_HE20)) &&
                   ((des_hw_mode >= IEEE80211_MODE_11AXG_HE20)) &&
                    ((ic->ic_opmode != IEEE80211_M_IBSS) || ieee80211_ic_ht20Adhoc_is_set(ic)) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_HE20)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11NG_HT40)) &&
                          ((des_hw_mode >= IEEE80211_MODE_11NG_HT40)) &&
                    ((ic->ic_opmode != IEEE80211_M_IBSS) || ieee80211_ic_ht40Adhoc_is_set(ic)) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_HT40PLUS)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11NG_HT40)) &&
                          ((des_hw_mode >= IEEE80211_MODE_11NG_HT40)) &&
                    ((ic->ic_opmode != IEEE80211_M_IBSS) || ieee80211_ic_ht40Adhoc_is_set(ic)) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_HT40MINUS)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11NG_HT20)) &&
                   ((des_hw_mode >= IEEE80211_MODE_11NG_HT20)) &&
                    ((ic->ic_opmode != IEEE80211_M_IBSS) || ieee80211_ic_ht20Adhoc_is_set(ic)) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_HT20)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11G)) &&
                          ((des_hw_mode >= IEEE80211_MODE_11G)) &&
                           ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, IEEE80211_CHAN_PUREG)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11G)) &&
                          ((des_hw_mode >= IEEE80211_MODE_11G)) &&
                           ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, IEEE80211_CHAN_G)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11B)) &&
                           ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, IEEE80211_CHAN_B)) != NULL)) {
                    return nc;
                }

            } else {
                /* Precedence is 11AXA,11AC,11NA then 11A
                 * In IEEE80211_MODE_AUTO mode we make the desired hw mode as
                 * 11AXA to maintain the same precedence as above.
                 */
                if(vap->iv_des_hw_mode == IEEE80211_MODE_AUTO) {
                    des_hw_mode = IEEE80211_MODE_11AXA_HE160;
                }
                else {
                    des_hw_mode = vap->iv_des_hw_mode;
                }

                /*
                 * Check if ic supports the mode
                 * Check if des_hw_mode is greater or at lest equal to the mode.
                 * Check if the mode should be allowed for IBSS operation mode.
                 * Try to find the channel in the present mode, if found return the channel,
                 * otherwise, procede to next lower mode.
                 */
                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11AXA_HE160)) &&
                    ((des_hw_mode >= IEEE80211_MODE_11AXA_HE160)) &&
                    (ic->ic_opmode != IEEE80211_M_IBSS) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_HE160)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11AXA_HE80)) &&
                    ((des_hw_mode >= IEEE80211_MODE_11AXA_HE80)) &&
                    (ic->ic_opmode != IEEE80211_M_IBSS) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_HE80)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11AXA_HE40)) &&
                    ((des_hw_mode >= IEEE80211_MODE_11AXA_HE40)) &&
                    (ic->ic_opmode != IEEE80211_M_IBSS) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_HE40PLUS)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11AXA_HE40)) &&
                    ((des_hw_mode >= IEEE80211_MODE_11AXA_HE40)) &&
                    (ic->ic_opmode != IEEE80211_M_IBSS) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_HE40MINUS)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11AXA_HE20)) &&
                    ((des_hw_mode >= IEEE80211_MODE_11AXA_HE20)) &&
                    (ic->ic_opmode != IEEE80211_M_IBSS) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_HE20)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11AC_VHT160)) &&
                    ((des_hw_mode >= IEEE80211_MODE_11AC_VHT160)) &&
                    (ic->ic_opmode != IEEE80211_M_IBSS) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_VHT160)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11AC_VHT80)) &&
                    ((des_hw_mode >= IEEE80211_MODE_11AC_VHT80)) &&
                    (ic->ic_opmode != IEEE80211_M_IBSS) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_VHT80)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11AC_VHT40)) &&
                    ((des_hw_mode >= IEEE80211_MODE_11AC_VHT40)) &&
                    (ic->ic_opmode != IEEE80211_M_IBSS) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_VHT40PLUS)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11AC_VHT40)) &&
                    ((des_hw_mode >= IEEE80211_MODE_11AC_VHT40)) &&
                    (ic->ic_opmode != IEEE80211_M_IBSS) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_VHT40MINUS)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11AC_VHT20)) &&
                    ((des_hw_mode >= IEEE80211_MODE_11AC_VHT20)) &&
                    (ic->ic_opmode != IEEE80211_M_IBSS) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_VHT20)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11NA_HT40)) &&
                          ((des_hw_mode >= IEEE80211_MODE_11NA_HT40)) &&
                    ((ic->ic_opmode != IEEE80211_M_IBSS) || ieee80211_ic_ht40Adhoc_is_set(ic)) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_HT40PLUS)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11NA_HT40)) &&
                          ((des_hw_mode >= IEEE80211_MODE_11NA_HT40)) &&
                    ((ic->ic_opmode != IEEE80211_M_IBSS) || ieee80211_ic_ht40Adhoc_is_set(ic)) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag |  IEEE80211_CHAN_HT40MINUS)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11NA_HT20)) &&
                          ((des_hw_mode >= IEEE80211_MODE_11NA_HT20)) &&
                    ((ic->ic_opmode != IEEE80211_M_IBSS) || ieee80211_ic_ht20Adhoc_is_set(ic)) &&
                    ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, band_flag | IEEE80211_CHAN_HT20)) != NULL)) {
                    return nc;
                }

                if ((ic->ic_modecaps & (1<<IEEE80211_MODE_11A)) &&
                           ((nc = ieee80211_find_channel(ic, c->ic_freq, 0, IEEE80211_CHAN_A)) != NULL)) {
                    return nc;
                }

            }
        } else if (mode == IEEE80211_MODE_11NG_HT40) {
            if (IEEE80211_IS_CHAN_2GHZ(c)) {
                 /* Precedence is 11NG PLUS channels first */

                if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HT40PLUS)) == (band_flag | IEEE80211_CHAN_HT40PLUS))
                    return c;

                if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HT40MINUS)) == (band_flag | IEEE80211_CHAN_HT40MINUS))
                    return c;
            }
        } else if (mode == IEEE80211_MODE_11NA_HT40) {
            if (IEEE80211_IS_CHAN_5GHZ(c)) {
                 /* Precedence is 11NA PLUS channels first */

                if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HT40PLUS)) == (band_flag | IEEE80211_CHAN_HT40PLUS))
                    return c;

                if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HT40MINUS)) == (band_flag | IEEE80211_CHAN_HT40MINUS))
                    return c;
            }
        } else if (mode == IEEE80211_MODE_11NG_HT40MINUS) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HT40MINUS)) == (band_flag | IEEE80211_CHAN_HT40MINUS))
		    return c;
        } else if (mode == IEEE80211_MODE_11NG_HT40PLUS) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HT40PLUS)) == (band_flag | IEEE80211_CHAN_HT40PLUS))
		    return c;
        } else if (mode == IEEE80211_MODE_11NA_HT40MINUS) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HT40MINUS)) == (band_flag | IEEE80211_CHAN_HT40MINUS))
		    return c;
        } else if (mode == IEEE80211_MODE_11NA_HT40PLUS) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HT40PLUS)) == (band_flag | IEEE80211_CHAN_HT40PLUS))
		    return c;
        } else if (mode == IEEE80211_MODE_11AC_VHT20) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_VHT20)) == (band_flag | IEEE80211_CHAN_VHT20))
		    return c;
        } else if (mode == IEEE80211_MODE_11AC_VHT40) {

            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_VHT40PLUS)) == (band_flag | IEEE80211_CHAN_VHT40PLUS))
		    return c;

            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_VHT40MINUS)) == (band_flag | IEEE80211_CHAN_VHT40MINUS))
		    return c;

        } else if (mode == IEEE80211_MODE_11AC_VHT40PLUS) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_VHT40PLUS)) == (band_flag | IEEE80211_CHAN_VHT40PLUS))
		    return c;
        } else if (mode == IEEE80211_MODE_11AC_VHT40MINUS) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_VHT40MINUS)) == (band_flag | IEEE80211_CHAN_VHT40MINUS))
		    return c;
        } else if (mode == IEEE80211_MODE_11AC_VHT80) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_VHT80)) == (band_flag | IEEE80211_CHAN_VHT80)) {
		    return c;
            }
        } else if (mode == IEEE80211_MODE_11AC_VHT160) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_VHT160)) == (band_flag | IEEE80211_CHAN_VHT160)) {
		    return c;
            }
        } else if (mode == IEEE80211_MODE_11AC_VHT80_80) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_VHT80_80)) == (band_flag | IEEE80211_CHAN_VHT80_80)) {
                if (freq2 == 0 || c->ic_vhtop_freq_seg2 == freq2) {
                    return c;
                }
            }
        } else if (mode == IEEE80211_MODE_11AXG_HE20) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HE20)) ==
                    (band_flag | IEEE80211_CHAN_HE20)) {
                return c;
            }
        } else if (mode == IEEE80211_MODE_11AXA_HE20) {
            if ((c->ic_flags & (IEEE80211_CHAN_HE20 | band_flag)) ==
                    (IEEE80211_CHAN_HE20 | band_flag)) {
                return c;
            }
        } else if (mode == IEEE80211_MODE_11AXG_HE40) {
            if (IEEE80211_IS_CHAN_2GHZ(c)) {
                 /* Precedence is 11AXG PLUS channels first */
                if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HE40PLUS)) ==
                        (band_flag | IEEE80211_CHAN_HE40PLUS)) {
                    return c;
                }

                if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HE40MINUS)) ==
                        (band_flag | IEEE80211_CHAN_HE40MINUS)) {
                    return c;
                }
            }
        } else if (mode == IEEE80211_MODE_11AXA_HE40) {
            if (IEEE80211_IS_CHAN_5GHZ_6GHZ(c)) {
                 /* Precedence is 11AXA PLUS channels first */
                if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HE40PLUS)) ==
                        (band_flag | IEEE80211_CHAN_HE40PLUS)) {
                    return c;
                }

                if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HE40MINUS)) ==
                        (band_flag | IEEE80211_CHAN_HE40MINUS)) {
                    return c;
                }
            }
        } else if (mode == IEEE80211_MODE_11AXG_HE40MINUS) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HE40MINUS)) ==
                    (band_flag | IEEE80211_CHAN_HE40MINUS)) {
                return c;
            }
        } else if (mode == IEEE80211_MODE_11AXG_HE40PLUS) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HE40PLUS)) ==
                    (band_flag | IEEE80211_CHAN_HE40PLUS)) {
                return c;
            }
        } else if (mode == IEEE80211_MODE_11AXA_HE40MINUS) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HE40MINUS)) ==
                    (band_flag | IEEE80211_CHAN_HE40MINUS)) {
                return c;
            }
        } else if (mode == IEEE80211_MODE_11AXA_HE40PLUS) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HE40PLUS)) ==
                    (band_flag | IEEE80211_CHAN_HE40PLUS)) {
                return c;
            }
        } else if (mode == IEEE80211_MODE_11AXA_HE80) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HE80)) ==
                    (band_flag | IEEE80211_CHAN_HE80)) {
                return c;
            }
        } else if (mode == IEEE80211_MODE_11AXA_HE160) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HE160)) ==
                    (band_flag | IEEE80211_CHAN_HE160)) {
                return c;
            }
        } else if (mode == IEEE80211_MODE_11AXA_HE80_80) {
            if ((c->ic_flags & (band_flag | IEEE80211_CHAN_HE80_80)) ==
                    (band_flag | IEEE80211_CHAN_HE80_80)) {
                if (freq2 == 0 || c->ic_vhtop_freq_seg2 == freq2) {
                    return c;
                }
            }
        } else {
            /* TODO: This is a temporary fix for 4.9 half/quarter/full-rate.
             * When the user configures a channel number, this function is called
             * to pick a valid channel pointer depending on iv_des_mode and
             * ic_chanbwflags. But, mode parameter may be passed from the caller by
             * 'OR'ing iv_des_mode (enum) and ic_chanbwflags (bit flag) which
             * is not correct.
             * A caller calls this function by setting
             * mode = vap->iv_des_mode | ic->ic_chanbwflag.
             * At the begining of this function, when calculating the modeflags
             * the channel bandwidth flags are lost. Therefore, for full-band
             * this function returns Quarter rate channel.
             */
            if(WLAN_REG_IS_49GHZ_FREQ(c->ic_freq)) {
                if ((ic->ic_chanbwflag == IEEE80211_CHAN_HALF) && IEEE80211_IS_CHAN_HALF(c))
                    return c;
                else if ((ic->ic_chanbwflag == IEEE80211_CHAN_QUARTER) && IEEE80211_IS_CHAN_QUARTER(c))
                    return c;
                else if (ic->ic_chanbwflag == 0)
                    if (!(IEEE80211_IS_CHAN_HALF(c)) && !(IEEE80211_IS_CHAN_QUARTER(c)))
                        return c;
            } else  if ((c->ic_flags & modeflags) == modeflags)
                return c;
        }

    }
    return NULL;
}


#define IS_CHANNEL_WEATHER_RADAR(freq) ((freq >= 5600) && (freq <= 5650))
#define ADJACENT_WEATHER_RADAR_CHANNEL   5580
#define CH100_START_FREQ                 5490
#define CH100                            100
/*
 * Print a console message with the device name prepended.
 */
static void
if_printf( osdev_t dev, const char *fmt, ...)
{
    va_list ap;
    char buf[512];              /* XXX */

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    qdf_nofl_info("\n %s\n", buf);
}
int ieee80211_find_any_valid_channel(struct ieee80211com *ic,  u_int64_t chan_mode)
{
    int i;
    u_int64_t chan_flags = 0;
    u_int32_t chan_flagext = 0;
    int ret_val = -1;

   /* find a valid channel in alt_chan_mode */

    for (i = 0; i < ic->ic_nchans; i++) {
        chan_flags = ic->ic_channels[i].ic_flags;
        chan_flagext = ic->ic_channels[i].ic_flagext;

        /* skip the channel if this is not desired mode */
        if ((chan_flags & chan_mode) == 0) {
            continue;
        }
        /* skip if weathere channles are not allowed */
        if(ic->ic_no_weather_radar_chan) {
            u_int32_t freq = ieee80211_chan2freq(ic,&ic->ic_channels[i]);
            if(IS_CHANNEL_WEATHER_RADAR(freq)) {
                continue;
            }
        }

        /* skip if radar was found in the channel */
        if (chan_flags & IEEE80211_CHAN_DFS_RADAR) {
            continue;
        }

        /* we found a channel */
        ret_val = i;
        break;
    }
    return ret_val;
}

#if WLAN_SUPPORT_PRIMARY_ALLOWED_CHAN
/*
 * Function to check the given frequency is present in the allowed
 * primary frequency list or not
 *
 */
bool ieee80211_check_allowed_prim_freqlist(struct ieee80211com *ic,
                uint16_t freq)
{
        u_int8_t i = 0;
        struct primary_allowed_chanlist *chanlist = ic->ic_primary_chanlist;

        for(i = 0; i < chanlist->n_freq; i++)
        {
                if(freq == chanlist->freq[i]) {
                        return true;
                }
        }

        return false;
}
#endif

/*
 * Check if two channels are in the same frequency band.
 */
bool
ieee80211_is_same_frequency_band(const struct ieee80211_ath_channel *chan1, const struct ieee80211_ath_channel *chan2)
{
    if (chan2 == NULL) {
        return false;
    }

    if (IEEE80211_IS_CHAN_2GHZ(chan1)) {
        /*
         * Channel1 is 2GHz, return TRUE only if channel2 is also 2GHz
         */
        return IEEE80211_IS_CHAN_2GHZ(chan2);
    }
    else if (IEEE80211_IS_CHAN_5GHZ(chan1)) {
        /*
         * Channel1 is 5GHz, return TRUE only if channel2 is also 5GHz
         */
        return IEEE80211_IS_CHAN_5GHZ(chan2);
    } else {
        /*
         * Channel1 is 6GHz, return TRUE only if channel2 is also 6GHz
         */
        return IEEE80211_IS_CHAN_6GHZ(chan2);
    }
}

void wlan_update_current_mode_caps(struct ieee80211com *ic)
{
    struct ieee80211_ath_channel *c;
    int i;
    uint64_t modcapmask;

    modcapmask = (1ULL << IEEE80211_MODE_MAX) -1;
    ic->ic_current_modecaps &= (~modcapmask);
    ic->ic_current_modecaps |= 1<<IEEE80211_MODE_AUTO;

    for (i = 0; i < ic->ic_nchans; i++) {
        c = &ic->ic_channels[i];

        if (IEEE80211_IS_CHAN_RADAR(c))
            continue;

        /* Identify mode capabilities. */
        if (IEEE80211_IS_CHAN_A(c))
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11A;
        if (IEEE80211_IS_CHAN_B(c))
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11B;
        if (IEEE80211_IS_CHAN_PUREG(c) || IEEE80211_IS_CHAN_G(c))
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11G;
        if (IEEE80211_IS_CHAN_FHSS(c))
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_FH;
        if (IEEE80211_IS_CHAN_108A(c))
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_TURBO_A;
        if (IEEE80211_IS_CHAN_108G(c))
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_TURBO_G;
        if (IEEE80211_IS_CHAN_11NA_HT20(c))
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11NA_HT20;
        if (IEEE80211_IS_CHAN_11NG_HT20(c))
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11NG_HT20;
        if (IEEE80211_IS_CHAN_11NA_HT40PLUS(c)) {
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11NA_HT40PLUS;
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11NA_HT40;
        }
        if (IEEE80211_IS_CHAN_11NA_HT40MINUS(c)) {
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11NA_HT40MINUS;
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11NA_HT40;
        }

        /*
         * HT40 in 2GHz allowed only if user enabled it.
         */
        if (ic->ic_reg_parm.enable2GHzHt40Cap) {
            if (IEEE80211_IS_CHAN_11NG_HT40PLUS(c)) {
                ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11NG_HT40PLUS;
                ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11NG_HT40;
            }
            if (IEEE80211_IS_CHAN_11NG_HT40MINUS(c)) {
                ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11NG_HT40MINUS;
                ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11NG_HT40;
            }
        }

        /* VHT */
        if (IEEE80211_IS_CHAN_11AC_VHT20(c)) {
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AC_VHT20;
        }
        if (IEEE80211_IS_CHAN_11AC_VHT40PLUS(c)) {
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AC_VHT40PLUS;
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AC_VHT40;
        }
        if (IEEE80211_IS_CHAN_11AC_VHT40MINUS(c)) {
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AC_VHT40MINUS;
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AC_VHT40;
        }
        if (IEEE80211_IS_CHAN_11AC_VHT80(c)) {
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AC_VHT80;
        }

        if (IEEE80211_IS_CHAN_11AC_VHT160(c)) {
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AC_VHT160;
        }
        if (IEEE80211_IS_CHAN_11AC_VHT80_80(c)) {
            /* Set mode only if IEEE80211_MODE_11AC_VHT160 is set */
            if (ic->ic_current_modecaps & (1<<IEEE80211_MODE_11AC_VHT160)) {
                ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AC_VHT80_80;
            }
        }

        /* HE */

        if (IEEE80211_IS_CHAN_11AXA_HE20(c)) {
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AXA_HE20;
        }

        if (IEEE80211_IS_CHAN_11AXG_HE20(c)) {
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AXG_HE20;
        }

        if (IEEE80211_IS_CHAN_11AXA_HE40PLUS(c)) {
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AXA_HE40PLUS;
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AXA_HE40;
        }

        if (IEEE80211_IS_CHAN_11AXA_HE40MINUS(c)) {
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AXA_HE40MINUS;
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AXA_HE40;
        }

        if (IEEE80211_IS_CHAN_11AXG_HE40PLUS(c)) {
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AXG_HE40PLUS;
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AXG_HE40;
        }

        if (IEEE80211_IS_CHAN_11AXG_HE40MINUS(c)) {
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AXG_HE40MINUS;
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AXG_HE40;
        }

        if (IEEE80211_IS_CHAN_11AXA_HE80(c)) {
            ic->ic_current_modecaps |= 1<<IEEE80211_MODE_11AXA_HE80;
        }

        if (IEEE80211_IS_CHAN_11AXA_HE160(c)) {
            ic->ic_current_modecaps |= 1ULL << IEEE80211_MODE_11AXA_HE160;
        }

        if (IEEE80211_IS_CHAN_11AXA_HE80_80(c)) {
             /* Set mode only if IEEE80211_MODE_11AXA_HE160 is set */
             if (ic->ic_current_modecaps & (1ULL << IEEE80211_MODE_11AXA_HE160)) {
                 ic->ic_current_modecaps |= 1ULL <<IEEE80211_MODE_11AXA_HE80_80;
             }
        }
    }
}

/*
 * Update channel list and associated PHY mode bitmask
 */
int
ieee80211_update_channellist(struct ieee80211com *ic, int exclude_11d,
                             bool no_chanchange)
{
    struct ieee80211_ath_channel *c;
    int i;
    u_int64_t modcapmask;

    if (ic->ic_nchans == 0) {
        qdf_print("%s: No ic channels available",__func__);
        return -1;
    }
    /*
     * Fill in 802.11 available channel set, mark
     * all available channels as active, and pick
     * a default channel if not already specified.
     */
    OS_MEMZERO(ic->ic_chan_avail_2g_5g, sizeof(ic->ic_chan_avail_2g_5g));
    OS_MEMZERO(ic->ic_chan_avail_6g, sizeof(ic->ic_chan_avail_6g));

    modcapmask = (1ULL << IEEE80211_MODE_MAX) -1;
    ic->ic_modecaps &= (~modcapmask);
    ic->ic_modecaps |= 1<<IEEE80211_MODE_AUTO;

#ifdef CONFIG_WIFI_EMULATION_WIFI_3_0
    ic->ic_modecaps |= modcapmask;
    return 0;
#endif

    for (i = 0; i < ic->ic_nchans; i++) {
        c = &ic->ic_channels[i];
        KASSERT(c->ic_flags != 0, ("channel with no flags"));
        KASSERT(c->ic_ieee < IEEE80211_CHAN_MAX,
                ("channel with bogus ieee number %u", c->ic_ieee));

        if (exclude_11d && IEEE80211_IS_CHAN_11D_EXCLUDED(c))
            continue;

        if (IEEE80211_IS_CHAN_6GHZ(c)) {
            setbit(ic->ic_chan_avail_6g, c->ic_ieee);
        } else {
            setbit(ic->ic_chan_avail_2g_5g, c->ic_ieee);
        }

        /*
         * Identify mode capabilities.
         */
        if (IEEE80211_IS_CHAN_A(c))
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11A;
        if (IEEE80211_IS_CHAN_B(c))
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11B;
        if (IEEE80211_IS_CHAN_PUREG(c) || IEEE80211_IS_CHAN_G(c))
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11G;
        if (IEEE80211_IS_CHAN_FHSS(c))
            ic->ic_modecaps |= 1<<IEEE80211_MODE_FH;
        if (IEEE80211_IS_CHAN_108A(c))
            ic->ic_modecaps |= 1<<IEEE80211_MODE_TURBO_A;
        if (IEEE80211_IS_CHAN_108G(c))
            ic->ic_modecaps |= 1<<IEEE80211_MODE_TURBO_G;
        if (IEEE80211_IS_CHAN_11NA_HT20(c))
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11NA_HT20;
        if (IEEE80211_IS_CHAN_11NG_HT20(c))
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11NG_HT20;
        if (IEEE80211_IS_CHAN_11NA_HT40PLUS(c)) {
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11NA_HT40PLUS;
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11NA_HT40;
        }
        if (IEEE80211_IS_CHAN_11NA_HT40MINUS(c)) {
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11NA_HT40MINUS;
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11NA_HT40;
        }

        /*
         * HT40 in 2GHz allowed only if user enabled it.
         */
        if (ic->ic_reg_parm.enable2GHzHt40Cap) {
            if (IEEE80211_IS_CHAN_11NG_HT40PLUS(c)) {
                ic->ic_modecaps |= 1<<IEEE80211_MODE_11NG_HT40PLUS;
                ic->ic_modecaps |= 1<<IEEE80211_MODE_11NG_HT40;
            }
            if (IEEE80211_IS_CHAN_11NG_HT40MINUS(c)) {
                ic->ic_modecaps |= 1<<IEEE80211_MODE_11NG_HT40MINUS;
                ic->ic_modecaps |= 1<<IEEE80211_MODE_11NG_HT40;
            }
        }

        /* VHT */
        if (IEEE80211_IS_CHAN_11AC_VHT20(c)) {
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11AC_VHT20;
        }
        if (IEEE80211_IS_CHAN_11AC_VHT40PLUS(c)) {
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11AC_VHT40PLUS;
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11AC_VHT40;
        }
        if (IEEE80211_IS_CHAN_11AC_VHT40MINUS(c)) {
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11AC_VHT40MINUS;
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11AC_VHT40;
        }
        if (IEEE80211_IS_CHAN_11AC_VHT80(c)) {
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11AC_VHT80;
        }

        if (IEEE80211_IS_CHAN_11AC_VHT160(c)) {
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11AC_VHT160;
        }
        if (IEEE80211_IS_CHAN_11AC_VHT80_80(c)) {
            /* Set mode only if IEEE80211_MODE_11AC_VHT160 is set */
            if (ic->ic_modecaps & (1<<IEEE80211_MODE_11AC_VHT160)) {
                ic->ic_modecaps |= 1<<IEEE80211_MODE_11AC_VHT80_80;
            }
        }

        /* HE */

        if (IEEE80211_IS_CHAN_11AXA_HE20(c)) {
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11AXA_HE20;
        }

        if (IEEE80211_IS_CHAN_11AXG_HE20(c)) {
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11AXG_HE20;
        }

        if (IEEE80211_IS_CHAN_11AXA_HE40PLUS(c)) {
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11AXA_HE40PLUS;
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11AXA_HE40;
        }

        if (IEEE80211_IS_CHAN_11AXA_HE40MINUS(c)) {
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11AXA_HE40MINUS;
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11AXA_HE40;
        }

        /*
         * 11AX TODO (Phase II) - Consider whether to add an equivalent of
         * ic->ic_reg_parm.enable2GHzHt40Cap here and control inclusion
         * of HE modes in 2.4 GHz. Decision to be taken based on latest draft at
         * the time.
         */
         if (IEEE80211_IS_CHAN_11AXG_HE40PLUS(c)) {
             ic->ic_modecaps |= 1<<IEEE80211_MODE_11AXG_HE40PLUS;
             ic->ic_modecaps |= 1<<IEEE80211_MODE_11AXG_HE40;
         }

         if (IEEE80211_IS_CHAN_11AXG_HE40MINUS(c)) {
             ic->ic_modecaps |= 1<<IEEE80211_MODE_11AXG_HE40MINUS;
             ic->ic_modecaps |= 1<<IEEE80211_MODE_11AXG_HE40;
         }

         if (IEEE80211_IS_CHAN_11AXA_HE80(c)) {
            ic->ic_modecaps |= 1<<IEEE80211_MODE_11AXA_HE80;
         }

         if (IEEE80211_IS_CHAN_11AXA_HE160(c)) {
             ic->ic_modecaps |= 1ULL << IEEE80211_MODE_11AXA_HE160;
         }

         if (IEEE80211_IS_CHAN_11AXA_HE80_80(c)) {
             /* Set mode only if IEEE80211_MODE_11AXA_HE160 is set */
             if (ic->ic_modecaps & (1ULL << IEEE80211_MODE_11AXA_HE160)) {
                 ic->ic_modecaps |= 1ULL <<IEEE80211_MODE_11AXA_HE80_80;
             }
         }
    }

    /* initialize candidate channels to all available */
    OS_MEMCPY(ic->ic_chan_active_2g_5g, ic->ic_chan_avail_2g_5g,
              sizeof(ic->ic_chan_avail_2g_5g));
    OS_MEMCPY(ic->ic_chan_active_6g, ic->ic_chan_avail_6g,
              sizeof(ic->ic_chan_avail_6g));

    if (exclude_11d)
        wlan_scan_update_channel_list(ic);

    /* bug #103186
     * after re-setting the country code, if curchan is
     * not availble anymore in the new country, then
     * let's find another channel.
     */
    if ((exclude_11d) && (ic->ic_curchan != NULL)) {
        struct ieee80211_ath_channel *first_valid_c = NULL;
        for(i = 0; i < ic->ic_nchans; i++) {
            c = &ic->ic_channels[i];
            if ((IEEE80211_IS_CHAN_6GHZ(c) && (isset(ic->ic_chan_avail_6g, c->ic_ieee))) ||
                        (!IEEE80211_IS_CHAN_6GHZ(c) && (isset(ic->ic_chan_avail_2g_5g, c->ic_ieee)))) {
                /* the ic_curchan is still valid, break */
                if( ic->ic_curchan == c)
                    break;
                if( first_valid_c == NULL)
                    first_valid_c = c;
            }
        }
        if(!no_chanchange && (i >= ic->ic_nchans) && (first_valid_c != NULL)) {
            /* the ic_curchan is not valid, set a valid channel */
            ieee80211_set_channel(ic, first_valid_c);
        }
    }
    return 0;
}
qdf_export_symbol(ieee80211_update_channellist);

/*
 * Set current channel
 */
int
ieee80211_set_channel(struct ieee80211com *ic, struct ieee80211_ath_channel *chan)
{
    int error;
    struct ieee80211_ath_channel *tempchan;
#ifdef ATH_SUPPORT_DFS
    struct wlan_objmgr_pdev *pdev;
#endif
#if UNIFIED_SMARTANTENNA
    QDF_STATUS status = QDF_STATUS_E_FAILURE;
#endif

    if(!chan)
        return -1;

    tempchan = ic->ic_prevchan;
    ic->ic_prevchan = ic->ic_curchan;
    ic->ic_curchan = chan;
    error = ic->ic_set_channel(ic);
    if (error) {
        ic->ic_curchan = ic->ic_prevchan;
        ic->ic_prevchan = tempchan;
        return error;
    }
    ic->ic_curmode = ieee80211_chan2mode(ic->ic_curchan);
#ifdef ATH_SUPPORT_DFS
    if (ic->ic_prevchan && ic->ic_curchan) {
        pdev = ic->ic_pdev_obj;
        if(pdev == NULL) {
            qdf_print("%s : pdev is null", __func__);
            return -1;
        }

        if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                QDF_STATUS_SUCCESS) {
            return -1;
        }
        mlme_dfs_cac_valid_reset_for_freq(pdev,
                ic->ic_prevchan->ic_freq,
                ic->ic_prevchan->ic_flags);
        wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
    }
#endif
#if UNIFIED_SMARTANTENNA
    if (ic->ic_opmode == IEEE80211_M_STA) {
        ic->sta_not_connected_cfg = FALSE;
    }
    {
        status = wlan_objmgr_pdev_try_get_ref(ic->ic_pdev_obj, WLAN_SA_API_ID);
        if (QDF_IS_STATUS_ERROR(status)) {
            qdf_print("%s, %d unable to get reference", __func__, __LINE__);
        } else {
            wlan_sa_api_channel_change(ic->ic_pdev_obj);
            wlan_objmgr_pdev_release_ref(ic->ic_pdev_obj, WLAN_SA_API_ID);
        }
    }
#endif
    /* Note: In VHT mode the right channel center frequency index will be available
     * from the regulatory domain table */

    /*
     * When there is radar detect in Repeater, repeater sends RCSAs, CSAs and
     * switches to new next channel, in ind rpt case repeater AP could start
     * beaconing before Root comes up, next channel needs to be changed
     *
     * For offload, resmgr will trigger channel change and fw resp of vdev up will
     * update dfs channel
     */
    return error;
}
/*
 * Set the current phy mode.
 */
int ieee80211_setmode(struct ieee80211com *ic,
                      enum ieee80211_phymode mode,
                      enum ieee80211_opmode opmode)
{
    ieee80211_reset_erp(ic, mode, opmode); /* reset ERP state */
    ic->ic_curmode = mode;      /* NB: must do post reset_erp */
    return 0;
}

const char *ieee80211_phymode_to_name( enum ieee80211_phymode mode)
{
    static const char unknown_mode[]="UNKNWON";
    if (mode >= sizeof(ieee80211_phymode_name)/sizeof(char *)) {
        return unknown_mode;
    }
    return (ieee80211_phymode_name[mode]);
}

int
wlan_get_supported_phymodes(wlan_dev_t devhandle,
                            enum ieee80211_phymode *modes,
                            u_int16_t *nmodes,
                            u_int16_t len)
{
    struct ieee80211com *ic = devhandle;
    int n = 0;
#define ADD_PHY_MODE(_m) do {                       \
    if (IEEE80211_SUPPORT_PHY_MODE(ic, (_m))) {     \
        if (len < (n+1))                            \
            goto bad;                               \
        modes[n++] = (_m);                          \
    }                                               \
} while (0)

    /*
     * NB: we fill in the modes array in certain order to be
     * compatible with Win 7/Vista SP1 driver.
     */
    ADD_PHY_MODE(IEEE80211_MODE_11B);
    ADD_PHY_MODE(IEEE80211_MODE_11A);
    ADD_PHY_MODE(IEEE80211_MODE_11G);
    ADD_PHY_MODE(IEEE80211_MODE_11NG_HT40PLUS);
    ADD_PHY_MODE(IEEE80211_MODE_11NG_HT40MINUS);
    ADD_PHY_MODE(IEEE80211_MODE_11NG_HT40);
    ADD_PHY_MODE(IEEE80211_MODE_11NG_HT20);
    ADD_PHY_MODE(IEEE80211_MODE_11NA_HT40PLUS);
    ADD_PHY_MODE(IEEE80211_MODE_11NA_HT40MINUS);
    ADD_PHY_MODE(IEEE80211_MODE_11NA_HT40);
    ADD_PHY_MODE(IEEE80211_MODE_11NA_HT20);
    ADD_PHY_MODE(IEEE80211_MODE_11AC_VHT80_80);
    ADD_PHY_MODE(IEEE80211_MODE_11AC_VHT160);
    ADD_PHY_MODE(IEEE80211_MODE_11AC_VHT80);
    ADD_PHY_MODE(IEEE80211_MODE_11AC_VHT40PLUS);
    ADD_PHY_MODE(IEEE80211_MODE_11AC_VHT40MINUS);
    ADD_PHY_MODE(IEEE80211_MODE_11AC_VHT40);
    ADD_PHY_MODE(IEEE80211_MODE_11AC_VHT20);
    ADD_PHY_MODE(IEEE80211_MODE_11AXG_HE40PLUS);
    ADD_PHY_MODE(IEEE80211_MODE_11AXG_HE40MINUS);
    ADD_PHY_MODE(IEEE80211_MODE_11AXG_HE20);
    ADD_PHY_MODE(IEEE80211_MODE_11AXA_HE80_80);
    ADD_PHY_MODE(IEEE80211_MODE_11AXA_HE160);
    ADD_PHY_MODE(IEEE80211_MODE_11AXA_HE80);
    ADD_PHY_MODE(IEEE80211_MODE_11AXA_HE40PLUS);
    ADD_PHY_MODE(IEEE80211_MODE_11AXA_HE40MINUS);
    ADD_PHY_MODE(IEEE80211_MODE_11AXA_HE20);

    *nmodes = n;
    return 0;

bad:
    *nmodes = IEEE80211_MODE_MAX;
    return -EOVERFLOW;
#undef ADD_PHY_MODE
}

int
wlan_set_desired_phylist(wlan_if_t vaphandle, enum ieee80211_phymode *phylist, u_int16_t nphy)
{
    struct ieee80211vap *vap = vaphandle;
    int i;

    if (nphy > IEEE80211_MODE_MAX || nphy < 1) {
        return -EINVAL;
    }

    vap->iv_des_modecaps = 0;

    for (i = 0; i < nphy; i++) {
        if (phylist[i] == IEEE80211_MODE_AUTO) {
            vap->iv_des_modecaps = (1 << IEEE80211_MODE_AUTO);
            return 0;
        }

        if (!IEEE80211_SUPPORT_PHY_MODE(vap->iv_ic, phylist[i])) {
            return -EINVAL;
        }

        vap->iv_des_modecaps |= (1 << phylist[i]);
    }

    return 0;
}

int
wlan_get_desired_phylist(wlan_if_t vaphandle,
                         enum ieee80211_phymode *phylist,
                         u_int16_t *nphy,
                         u_int16_t len)
{
    struct ieee80211vap *vap = vaphandle;
    enum ieee80211_phymode m;
    u_int16_t count;

    if (len < 1) {
        *nphy = IEEE80211_MODE_MAX;
        return -EOVERFLOW;
    }

    /* return AUTO if we accept any PHY modes */
    if (IEEE80211_ACCEPT_ANY_PHY_MODE(vap)) {
        phylist[0] = IEEE80211_MODE_AUTO;
        *nphy = 1;
        return 0;
    }

    count = 0;
    for (m = IEEE80211_MODE_AUTO + 1; m < IEEE80211_MODE_MAX; m++) {
        if (IEEE80211_ACCEPT_PHY_MODE(vap, m)) {
            /* is input big enough */
            if (len < (count+1))
                return -EINVAL;

            phylist[count++] = m;
        }
    }

    *nphy = count;
    return 0;
}

enum ieee80211_phymode
wlan_get_desired_phymode(wlan_if_t vaphandle)
{
    struct ieee80211vap *vap = vaphandle;
    return vap->iv_des_mode;
}

int
wlan_set_desired_phymode(wlan_if_t vaphandle, enum ieee80211_phymode mode)
{
    struct ieee80211vap *vap = vaphandle;
    wlan_chan_t chan = wlan_get_current_channel(vap, false);
    struct ieee80211vap *tmpvap = NULL;
    struct ieee80211com *ic = vap->iv_ic;
    int numvaps_up = 0;
    wlan_if_t first_vap;

    if (!IEEE80211_SUPPORT_PHY_MODE(vap->iv_ic, mode)) {
            qdf_nofl_info("Rejecting mode %d: This mode may be invalid or may be unavailable for the requested values of parameters such as channel and chainmasks\n", mode);
            return -EINVAL;
    }

    if (!(ic->ic_current_modecaps & (1ULL << mode))) {
        first_vap = TAILQ_FIRST(&(vap->iv_ic)->ic_vaps);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s : mode = %d is not available in the current_modecaps, override vap = %d (%s) mode as %d\n",
                __func__, mode, vaphandle->iv_unit, vaphandle->iv_netdev_name, first_vap->iv_des_mode);
        mode = first_vap->iv_des_mode;
    }

    if (chan == NULL) {
        qdf_nofl_info("chan is NULL for mode: %d\n", mode);
        return -EINVAL;
    }

    if (ic->ic_update_target_caps)
        ic->ic_update_target_caps(ic, mode);

    /* in multivap case, should we check if this is in agreement with other vaps */
    if (chan != IEEE80211_CHAN_ANYC) {
        /* If any vap is running, find the same frequency channel with vap desired mode */
        numvaps_up = ieee80211_get_num_vaps_up(ic);

        if ((numvaps_up) && (ic->ic_curchan != chan)) {
            chan = ic->ic_curchan;
        }
        chan = ieee80211_find_dot11_channel(ic, chan->ic_freq, chan->ic_vhtop_freq_seg2, mode);
    }

    /* don't allow to change to channel with radar found */
    if(chan && chan != IEEE80211_CHAN_ANYC && IEEE80211_IS_CHAN_RADAR(chan)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DFS,
                "%s:Cannot move to a RADAR detected channel\n",
                __func__);
        return -EINVAL;
    }

    if ((mode == IEEE80211_MODE_AUTO) || (vap->iv_opmode == IEEE80211_M_STA)) {
        if (vap->iv_des_mode != mode)
           vap->iv_wme_reset = 1;
        vap->iv_des_mode = mode;
        vap->iv_des_hw_mode = mode;
        if (chan != IEEE80211_CHAN_ANYC && chan) {
            vap->iv_des_chan[mode] = chan;
        }
    } else {
        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            if (tmpvap->iv_des_mode != mode)
               tmpvap->iv_wme_reset = 1;
            tmpvap->iv_des_mode = mode;
            tmpvap->iv_des_hw_mode = mode;
            if (chan != IEEE80211_CHAN_ANYC && chan) {
                tmpvap->iv_des_chan[mode] = chan;
            }
        }
    }

    return 0;
}

int
wlan_set_desired_ibsschan(wlan_if_t vaphandle, uint16_t chan_freq)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_ath_channel *channel = NULL;
    struct ieee80211com *ic = vap->iv_ic;

    if (chan_freq > IEEE80211_FREQ_MAX)
        return -EINVAL;

    if(chan_freq == (uint16_t)IEEE80211_FREQ_ANY) {
            channel = vap->iv_des_chan[vap->iv_des_mode];
            if(channel == IEEE80211_CHAN_ANYC)
                return -EINVAL;
            chan_freq = channel->ic_freq;
    } else {
        channel = ieee80211_find_dot11_channel(ic, chan_freq, vap->iv_des_cfreq2, vap->iv_des_mode | ic->ic_chanbwflag);
        if (channel == NULL) {
            channel = ieee80211_find_dot11_channel(ic, chan_freq, 0, IEEE80211_MODE_AUTO);
            if (channel == NULL)
                return -EINVAL;
        }
    }

    if (IEEE80211_IS_CHAN_RADAR(channel)) {
        return -EINVAL;
    }

    vap->iv_des_ibss_chan_freq = chan_freq;

    return 0;
}


enum ieee80211_phymode
wlan_get_current_phymode(wlan_if_t vaphandle)
{
    return ieee80211_get_current_phymode(vaphandle->iv_ic);
}

enum ieee80211_phymode
wlan_get_bss_phymode(wlan_if_t vaphandle)
{
    return ieee80211_chan2mode(vaphandle->iv_bsschan);
}

enum ieee80211_phymode
wlan_get_des_phymode(struct ieee80211_ath_channel *des_chan)
{
    return ieee80211_chan2mode(des_chan);
}

wlan_chan_t
wlan_get_current_channel(wlan_if_t vaphandle, bool hwChan)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
    bool is_spoof_check_enabled = 0;
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    int dfs_region;

    if (ic->ic_is_host_dfs_check_enabled)
        ic->ic_is_host_dfs_check_enabled(pdev, &is_spoof_check_enabled);
    ieee80211_regdmn_get_dfs_region(pdev, (enum dfs_reg *)&dfs_region);
#endif /* HOST_DFS_SPOOF_TEST */

    /*
     * If the VAP is in RUN state, return the current channel.
     * Otherwise, return the desired channel of the desired phymode.
     */
    if ((wlan_vdev_is_up(vap->vdev_obj) == QDF_STATUS_SUCCESS) || hwChan) {
        return ic->ic_curchan;
#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
    } else if (is_spoof_check_enabled && mlme_dfs_is_spoof_check_failed(pdev)
            && dfs_region == DFS_FCC_DOMAIN && ieee80211_get_num_vaps_up(ic)) {
        return wlan_get_dev_current_channel(ic);
#endif /* HOST_DFS_SPOOF_TEST */
    } else {
        return vap->iv_des_chan[vap->iv_des_mode];
    }
}

wlan_chan_t
wlan_get_dev_current_channel(wlan_dev_t devhandle)
{
    struct ieee80211com *ic = devhandle;

    return (ic->ic_curchan == IEEE80211_CHAN_ANYC)? NULL: ic->ic_curchan;
}

wlan_chan_t
wlan_get_bss_channel(wlan_if_t vaphandle)
{
    struct ieee80211vap *vap = vaphandle;

    return vap->iv_bsschan;
}

wlan_chan_t
wlan_get_des_channel(wlan_if_t vaphandle)
{
    struct ieee80211vap *vap = vaphandle;
#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
    struct ieee80211com *ic = vap->iv_ic;
    int dfs_region;
    bool is_spoof_check_enabled = 0;
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;

    if (ic->ic_is_host_dfs_check_enabled)
        ic->ic_is_host_dfs_check_enabled(pdev, &is_spoof_check_enabled);

    ieee80211_regdmn_get_dfs_region(pdev, (enum dfs_reg *)&dfs_region);

    if (is_spoof_check_enabled && mlme_dfs_is_spoof_check_failed(pdev)
            && dfs_region == DFS_FCC_DOMAIN && ieee80211_get_num_vaps_up(ic)) {
        return wlan_get_dev_current_channel(ic);
    }
#endif /* HOST_DFS_SPOOF_TEST */
    return vap->iv_des_chan[vap->iv_des_mode];
}


int
wlan_get_channel_list(wlan_dev_t devhandle, enum ieee80211_phymode phymode,
                      wlan_chan_t chanlist[], u_int32_t n)
{
    struct ieee80211com *ic = devhandle;
    struct ieee80211_ath_channel *chan;
    int i, nchan = 0;
    for (i = 0; i < ic->ic_nchans; i++) {
        chan = &ic->ic_channels[i];

        /*
         * only active channels
         */
        if ((IEEE80211_IS_CHAN_6GHZ(chan) && isclr(ic->ic_chan_avail_6g, chan->ic_ieee)) ||
                (!IEEE80211_IS_CHAN_6GHZ(chan) && isclr(ic->ic_chan_avail_2g_5g, chan->ic_ieee))) {
            continue;
        }

        if (phymode == IEEE80211_MODE_AUTO ||
            phymode == ieee80211_chan2mode(chan)) {
            /*
             * found a matching channel
             */
            if (n < (nchan + 1))
                return -EOVERFLOW;

            chanlist[nchan++] = chan;
        }
    }

    return nchan;
}

void
wlan_get_noise_floor(wlan_if_t vaphandle, int16_t *nfBuf)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;

    ic->ic_get_chainnoisefloor(ic, ic->ic_curchan, nfBuf);
}

int16_t
wlan_get_chan_noise_floor(wlan_if_t vaphandle, u_int16_t freq, u_int64_t flags)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_ath_channel chan;

    chan.ic_freq  = freq;
    chan.ic_flags = flags;

    return ic->ic_get_noisefloor(ic, &chan, 0);
}

u_int32_t
wlan_channel_frequency(wlan_chan_t chan)
{
    return (chan == IEEE80211_CHAN_ANYC) ?  IEEE80211_FREQ_ANY : chan->ic_freq;
}

u_int32_t
wlan_channel_ieee(wlan_chan_t chan)
{
    return (chan == IEEE80211_CHAN_ANYC) ?  IEEE80211_CHAN_ANY : chan->ic_ieee;
}

enum ieee80211_phymode
wlan_channel_phymode(wlan_chan_t chan)
{
    return ieee80211_chan2mode(chan);
}

int8_t
wlan_channel_maxpower(wlan_chan_t chan)
{
    return chan->ic_maxregpower;
}

u_int64_t
wlan_channel_flags(wlan_chan_t chan)
{
    return chan->ic_flags;
}

bool
wlan_channel_is_passive(wlan_chan_t chan)
{
    return (IEEE80211_IS_CHAN_PASSIVE(chan));
}

bool
wlan_channel_is_5GHzOdd(wlan_chan_t chan)
{
    return (IEEE80211_IS_CHAN_ODD(chan));
}

bool
wlan_channel_is_dfs(wlan_chan_t chan, bool flagOnly)
{
    if (flagOnly)
        return (IEEE80211_IS_CHAN_DFSFLAG(chan));
    else
        return (IEEE80211_IS_CHAN_DFS(chan));
}


/*
 * Auto Channel Select handler used for interface up.
 */
static void spectral_eacs_event_handler(void *arg, wlan_chan_t channel)
{
    struct ieee80211vap *vap = (struct ieee80211vap *)arg;
    struct ieee80211com *ic = vap->iv_ic;
    int error = 0;

    /* Skip channel set, if channel is ANYC */
    if ((!channel) || (channel == IEEE80211_CHAN_ANYC)) {
        /* Restore dcs state so that interference detection will work*/
        if(ic->ic_dcs_restore) {
            ic->ic_dcs_restore(ic);
        }
        goto done;
    }

    error = wlan_set_ieee80211_channel(vap, channel);
    if (error !=0) {
        /* Restore dcs state so that interference detection will work*/
        if(ic->ic_dcs_restore) {
            ic->ic_dcs_restore(ic);
        }
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
            "%s : failed to set channel with error code %d\n",
            __func__, error);
    }

done:
    wlan_autoselect_unregister_event_handler(vap, &spectral_eacs_event_handler, vap);
}


/**
* @brief            set known ieee802111_channel to vap
*
* @param vaphandle  handle to vap for which channel has to be set
* @param channel    handle to ieee80211_channel
*
* @return:          0 for success, -ve error code other wise.
*/
int
wlan_set_ieee80211_channel(wlan_if_t vaphandle,
                           struct ieee80211_ath_channel *channel)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211vap *tmp_vap = NULL;

    if (!channel) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
                "%s: vap-%d NULL channel specified\n", __func__, vap->iv_unit);
        return -EINVAL;
    }

/* The default value of this variable is false.When NOL violation is reported
 * by FW in vap's start response, during restart of the vap, it will be reset
 * to true in dfs_action. After this if user again tries to set another NOL
 * channel using iwconfig athx chan "NOL_chan", if is variable is remains to
 * set to true, no action will be taken on vap's start failure from FW. Hence
 * resetting it here.
 */
#if defined(WLAN_DFS_FULL_OFFLOAD) && defined(QCA_DFS_NOL_OFFLOAD)
    if (vap->vap_start_failure_action_taken)
        vap->vap_start_failure_action_taken = false;
#endif

#if ATH_SUPPORT_VOW_DCS
    if (!ic->ic_eacs_done) {
        /* disable dcs when channel is not chosen by EACS */
        ic->ic_disable_dcsim(ic);
    } else {
        ic->ic_eacs_done = 0;
    }
#endif

    if ((vap->iv_opmode == IEEE80211_M_HOSTAP) &&
        (ieee80211_check_chan_mode_consistency(ic,vap->iv_des_mode,channel))) {
        return -EINVAL;
    }

    /* don't allow to change to channel with radar found */
    if (IEEE80211_IS_CHAN_RADAR(channel)) {
        return -EINVAL;
    }

    /* we are ready to change channel, restore some ic flag , EV#133678 */
    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        IEEE80211_DISABLE_PROTECTION(ic);
        ieee80211_set_protmode(ic);
        if (ic->ic_caps & IEEE80211_C_SHPREAMBLE) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,"%s: restore short preamble setting\n", __func__);
                ieee80211com_set_flags(ic, IEEE80211_F_SHPREAMBLE);
                ieee80211com_clear_flags(ic, IEEE80211_F_USEBARKER);
        }
    }

    /* mark desired channel */
    vap->iv_des_chan[vap->iv_des_mode] = channel;

    /*
     * 2.4 GHz Channel Switch Announcement would be disabled in default.
     * Due to maybe some STAs do not handle the CSA in 2.4 GHz very well.
     * Also make sure the channel change is not due to interference. In this
     * case, do not wait for CSA
     */
    if ((ieee80211_ic_2g_csa_is_set(ic)) &&
        (wlan_vdev_is_up(vap->vdev_obj) == QDF_STATUS_SUCCESS)  && !(ic->cw_inter_found)) {
        ieee80211_ucfg_set_chanswitch(vap, channel->ic_freq, IEEE80211_2GCSA_TBTTCOUNT, 0);
        return 0;
    }

    /*
     * Do a channel change only when we're already in the RUN or DFSWAIT state.
     * The MLME will pickup the desired channel later.
     */

    /*
     * TBD: If curchan = channel, still need to set channel again to pass
     * SendRecv_ext in ndistest.
     */
    if ((wlan_vdev_chan_config_valid(vap->vdev_obj) == QDF_STATUS_SUCCESS) ||
        (ic->cw_inter_found)) {// && ic->ic_curchan != channel) {

        /* AP vap skips CAC if iv_bsschan != ic_curchan.
         * Therefore change the iv_bsschan per vap before channel change.
         */
        TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
            tmp_vap->iv_bsschan = channel;
            ieee80211_update_vdev_chan(tmp_vap->vdev_obj->vdev_mlme.des_chan,
                                       channel);
        }

        ieee80211_set_channel(ic, channel);
        {
            /* In case of multi BSSID, make sure all the VAPs change channel */
            TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                /* clear erpupdate bit */
                ieee80211_vap_erpupdate_clear(tmp_vap);
                /* This is needed to make the beacon is re-initlized */
                tmp_vap->channel_change_done = 1;
                IEEE80211_DPRINTF(tmp_vap, IEEE80211_MSG_STATE, "%s switch channel %d freq %d\n",
                                    __func__, ic->ic_curchan->ic_ieee,ic->ic_curchan->ic_freq);
            }
        }
    }
    return 0;
}

int
wlan_set_channel(wlan_if_t vaphandle, uint16_t chan_freq, uint16_t cfreq2)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_ath_channel *channel = NULL;
    struct ieee80211vap *tmp_vap = NULL;

    if ((chan_freq > IEEE80211_FREQ_MAX) && (chan_freq != (uint16_t)IEEE80211_FREQ_ANY))
        return -EINVAL;

    if (chan_freq == (uint16_t)IEEE80211_FREQ_ANY) {

        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            /* allow IEEE80211_CHAN_ANYC for auto channel select in AP mode*/
            vap->iv_des_chan[vap->iv_des_mode] = IEEE80211_CHAN_ANYC;
            /* Trigger EACS only when vap is ready or channel change issued by DCS module */
            if ((wlan_vdev_is_up(vap->vdev_obj) == QDF_STATUS_SUCCESS) || (ic->cw_inter_found)) {
              wlan_autoselect_register_event_handler(vap, &spectral_eacs_event_handler, (void *)vap);
              wlan_autoselect_find_infra_bss_channel(vap, NULL);
            }
            return 0;
        } else {
            /* select the desired channel for the desired PHY mode */
            TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                if (tmp_vap && (tmp_vap->iv_opmode == IEEE80211_M_HOSTAP)) {
                    channel = tmp_vap->iv_des_chan[vap->iv_des_mode];
                    if (channel && channel != IEEE80211_CHAN_ANYC) {
                        break;
                    }
                }
            }
            if ((!channel) || (channel == IEEE80211_CHAN_ANYC))
                return -EINVAL;
        }
    } else {
        /*
         * find the corresponding channel object for the desired PHY mode.
         */
        channel = ieee80211_find_dot11_channel(ic, chan_freq, cfreq2, vap->iv_des_mode | ic->ic_chanbwflag);
        if (channel == NULL) {
            channel = ieee80211_find_dot11_channel(ic, chan_freq, 0, IEEE80211_MODE_AUTO);
            if (channel == NULL)
                return -EINVAL;
        }
    }

    return wlan_set_ieee80211_channel(vap, channel);
}

/* Structure used in the ieee80211_vap_iter_get_bss_chan() to get the BSS frequencies */
struct ieee80211_iter_vaps_get_bss_chan_arg {
    int         max_list_size;
    int         current_list_size;
    u_int32_t   *bss_freq_list;
    int         ret_param;
};

static void ieee80211_vap_iter_get_bss_chan(void *arg, wlan_if_t vap)
{
    struct ieee80211_iter_vaps_get_bss_chan_arg *params;

    params = (struct ieee80211_iter_vaps_get_bss_chan_arg *) arg;

    if (params->ret_param != EOK) {
        return;
    }

    if (wlan_vdev_is_up(vap->vdev_obj) == QDF_STATUS_SUCCESS) {
        /* Get the BSS channel and its frequency */
        wlan_chan_t     bsschan;
        int             i;
        u_int32_t       bss_freq;

        bsschan = vap->iv_bsschan;
        if (bsschan && (bsschan != IEEE80211_CHAN_ANYC)) {
            bss_freq = wlan_channel_frequency(bsschan);
        }
        else {
            return;
        }

        /* Check whether it is a duplicate */
        for (i = 0; i < params->current_list_size; i++) {
            if (params->bss_freq_list[i] == bss_freq) {
                /* A match */
                return;
            }
        }
        /* Else no match */
        params->current_list_size++;
        if (params->current_list_size >= params->max_list_size) {
            /* No more space */
            params->ret_param = -EOVERFLOW;
            return;
        }
        params->bss_freq_list[params->current_list_size - 1] = bss_freq;
    }
}

/*
 * Get the list of BSS channel used by other active VAPs. Note that as VAPs go up and down,
 * this list can change with time.
 * bss_freq_list contains an array of frequencies to return the BSS channels used by
 * other active VAPs. On function entry, list_size contains the size of array bss_freq_list.
 * On exit, list_size contains the size of BSS frequency list filled. If no other active VAPs,
 * then list_size will be zero.
 */
int
wlan_get_bss_chan_list(wlan_dev_t devhandle, u_int32_t *bss_freq_list, int *list_size)
{
    struct ieee80211_iter_vaps_get_bss_chan_arg params;

    if (*list_size <= 0) {
        /* Empty list */
        return -EOVERFLOW;
    }

    OS_MEMZERO(&params, sizeof(params));

    params.max_list_size = *list_size;
    params.bss_freq_list = bss_freq_list;
    params.ret_param = EOK;

    wlan_iterate_vap_list(devhandle, ieee80211_vap_iter_get_bss_chan,(void *) &params);

    /* Return the number of BSS channels found */
    *list_size = params.current_list_size;

    return params.ret_param;
}

/*
 * Calculate the channel width of the given umac channel.
 *
 * XXX verify that half/quarter rates are always 5/10MHz, or
 *     whether it should take the actual channel width
 *     (20/40/80) into account (ie, by dividing it by 2 or 4.)
 */
int
ieee80211_get_chan_width(struct ieee80211_ath_channel *chan)
{

    /*
     * Since HE channels have VHT flags, VHT channels have HT flags and HT
     * channels have legacy flags, start at HE, then do VHT, then do HT, then
     * check legacy.
     *
     * Or, check the PHY mode for the given channel.
     */

    /*
     * XXX should these just shift the PHY width by 2 or 4?
     * (eg, would we ever have a HT40 channel in 5MHz?)
     */
    if (IEEE80211_IS_CHAN_QUARTER(chan))
        return (5);
    else if (IEEE80211_IS_CHAN_HALF(chan))
        return (10);

    switch (ieee80211_chan2mode(chan)) {
        /* HE160 */
        case IEEE80211_MODE_11AXA_HE160:
            return (160);
        /* HE80 + 80 */
        case IEEE80211_MODE_11AXA_HE80_80:
            return (80+80);
        /* HE80 */
        case IEEE80211_MODE_11AXA_HE80:
            return (80);
        /* HE40 */
        case IEEE80211_MODE_11AXA_HE40PLUS:
        case IEEE80211_MODE_11AXA_HE40MINUS:
        case IEEE80211_MODE_11AXA_HE40:
        case IEEE80211_MODE_11AXG_HE40PLUS:
        case IEEE80211_MODE_11AXG_HE40MINUS:
        case IEEE80211_MODE_11AXG_HE40:
            return (40);

        /* VHT160 */
        case IEEE80211_MODE_11AC_VHT160:
            return (160);
        /* VHT80+80 */
        case IEEE80211_MODE_11AC_VHT80_80:
            return (80+80);
        /* VHT80 */
        case IEEE80211_MODE_11AC_VHT80:
            return (80);

        /* VHT40 */
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:

        /* HT40 */
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NA_HT40:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
            return (40);

        default:
            return (20);
    }
}

enum phy_ch_width
ieee80211_get_phy_chan_width(struct ieee80211_ath_channel *chan)
{
    if (IEEE80211_IS_CHAN_QUARTER(chan))
        return CH_WIDTH_5MHZ;
    else if (IEEE80211_IS_CHAN_HALF(chan))
        return CH_WIDTH_10MHZ;

    switch (ieee80211_chan2mode(chan)) {
        case IEEE80211_MODE_11AXA_HE160:
        case IEEE80211_MODE_11AC_VHT160:
            return CH_WIDTH_160MHZ;
        case IEEE80211_MODE_11AXA_HE80_80:
        case IEEE80211_MODE_11AC_VHT80_80:
            return CH_WIDTH_80P80MHZ;
        case IEEE80211_MODE_11AXA_HE80:
        case IEEE80211_MODE_11AC_VHT80:
            return CH_WIDTH_80MHZ;
        case IEEE80211_MODE_11AXA_HE40PLUS:
        case IEEE80211_MODE_11AXA_HE40MINUS:
        case IEEE80211_MODE_11AXA_HE40:
        case IEEE80211_MODE_11AXG_HE40PLUS:
        case IEEE80211_MODE_11AXG_HE40MINUS:
        case IEEE80211_MODE_11AXG_HE40:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NA_HT40:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
            return CH_WIDTH_40MHZ;
        default:
            return CH_WIDTH_20MHZ;
    }

    return CH_WIDTH_INVALID;
}
qdf_export_symbol(ieee80211_get_phy_chan_width);

enum phy_ch_width
ieee80211_get_chan_width_from_phymode(enum ieee80211_phymode mode)
{
    switch(mode) {
    case IEEE80211_MODE_AUTO:
    case IEEE80211_MODE_11A:
    case IEEE80211_MODE_11B:
    case IEEE80211_MODE_11G:
    case IEEE80211_MODE_FH:
    case IEEE80211_MODE_TURBO_A:
    case IEEE80211_MODE_TURBO_G:
    case IEEE80211_MODE_11NA_HT20:
    case IEEE80211_MODE_11NG_HT20:
    case IEEE80211_MODE_11AC_VHT20:
    case IEEE80211_MODE_11AXA_HE20:
    case IEEE80211_MODE_11AXG_HE20:
        return CH_WIDTH_20MHZ;
    case IEEE80211_MODE_11NA_HT40PLUS:
    case IEEE80211_MODE_11NA_HT40MINUS:
    case IEEE80211_MODE_11NG_HT40PLUS:
    case IEEE80211_MODE_11NG_HT40MINUS:
    case IEEE80211_MODE_11NG_HT40:
    case IEEE80211_MODE_11NA_HT40:
    case IEEE80211_MODE_11AC_VHT40PLUS:
    case IEEE80211_MODE_11AC_VHT40MINUS:
    case IEEE80211_MODE_11AC_VHT40:
    case IEEE80211_MODE_11AXA_HE40PLUS:
    case IEEE80211_MODE_11AXA_HE40MINUS:
    case IEEE80211_MODE_11AXG_HE40PLUS:
    case IEEE80211_MODE_11AXG_HE40MINUS:
    case IEEE80211_MODE_11AXA_HE40:
    case IEEE80211_MODE_11AXG_HE40:
        return CH_WIDTH_40MHZ;
    case IEEE80211_MODE_11AC_VHT80:
    case IEEE80211_MODE_11AXA_HE80:
        return CH_WIDTH_80MHZ;
    case IEEE80211_MODE_11AC_VHT160:
    case IEEE80211_MODE_11AXA_HE160:
        return CH_WIDTH_160MHZ;
    case IEEE80211_MODE_11AC_VHT80_80:
    case IEEE80211_MODE_11AXA_HE80_80:
        return CH_WIDTH_80P80MHZ;
    default:
        return CH_WIDTH_INVALID;
    }
}

/*
 * Calculate the centre frequency of the given channel.
 *
 * XXX doesn't know about VHT 80+80 yet!
 * XXX half/quarter rates!
 */
int
ieee80211_get_chan_centre_freq(struct ieee80211com *ic,
    struct ieee80211_ath_channel *chan)
{
    int chan_centre, chan_offset, chan_width;

    /*
     * XXX Only >= VHT80/HE80 channels have freq1/freq2 setup.
     */
    if ((IEEE80211_IS_CHAN_11AC_VHT80(chan)) ||
            (IEEE80211_IS_CHAN_11AC_VHT80_80(chan)) ||
            (IEEE80211_IS_CHAN_11AXA_HE80(chan)) ||
            (IEEE80211_IS_CHAN_11AXA_HE80_80(chan))) {
        /* 11AC/11AX, so cfreq1/cfreq2 are setup */

		/*
		 * XXX center frequency of only first segment is provided even for 80+80
		 */
		chan_centre = chan->ic_vhtop_freq_seg1;
    } else if (IEEE80211_IS_CHAN_11AC_VHT160(chan) ||
                  IEEE80211_IS_CHAN_11AXA_HE160(chan)) {

        /* For 160 MHz, centre frequency is ic_vhtop_ch_freq_seg2 */
        chan_centre = chan->ic_vhtop_freq_seg2;
    } else {
		/* HT20/HT40, VHT20/VHT40, HE20/HE40  */

        /*
         * XXX this is hard-coded - it should be 5 or 10 for
         * half/quarter appropriately.
         */
        chan_width = 20;

        /* Grab default channel centre */
        chan_centre = ieee80211_chan2freq(ic, chan);

        /* Calculate offset based on HT40U/HT40D */
        /* XXX and also VHT40, HE40 for now */
        /* XXX add flag check methods to umac */
        if (chan->ic_flags & IEEE80211_CHAN_HE40PLUS)
            chan_offset = chan_width;
        else if (chan->ic_flags & IEEE80211_CHAN_HE40MINUS)
            chan_offset = -chan_width;
        else if (chan->ic_flags & IEEE80211_CHAN_VHT40PLUS)
            chan_offset = chan_width;
        else if (chan->ic_flags & IEEE80211_CHAN_VHT40MINUS)
            chan_offset = -chan_width;
        else if (IEEE80211_IS_CHAN_11N_HT40PLUS(chan))
            chan_offset = chan_width;
        else if (IEEE80211_IS_CHAN_11N_HT40MINUS(chan))
            chan_offset = -chan_width;
        else
            /* HT20/VHT20/HE20 */
            chan_offset = 0;

        /* Calculate new _real_ channel centre */
        chan_centre += (chan_offset / 2);
    }

    /*
     * XXX TODO: add half/quarter rate support!
     */

    return (chan_centre);
}

/*
 * Check whether cp falls within p1 and p2, exclusively.
 */
static int
ol_check_intersect_excl(int p1, int p2, int cp)
{

	return (cp > p1 && cp < p2);
}

/*
 * Check whether two frequency centre/channel width entries
 * overlap in any way.
 *
 * This is an exclusive overlap - ie, two touching edges
 * do not match.
 *
 * XXX very likely not optimal at all!
 */
int
ieee80211_check_overlap(int f1, int w1, int f2, int w2)
{
	int f1_h, f1_l;
	int f2_h, f2_l;
	int ret;

	/* Calculate low/high frequency ranges */
	f1_l = f1 - (w1 / 2);
	f1_h = f1 + (w1 / 2);

	f2_l = f2 - (w2 / 2);
	f2_h = f2 + (w2 / 2);

	/*
	 * Since the intersect check is exclusive, two
	 * exact overlaps won't actually work as each
	 * edge only touches the other edge.  It's not
	 * considered inside a range.  Hence why there's
	 * a separate "is totally equal" check.
	 */
	ret = (
	    ((f1 == f2) && (w1 == w2)) ||
	    ol_check_intersect_excl(f1_l, f1_h, f2_l) ||
	    ol_check_intersect_excl(f1_l, f1_h, f2_h) ||
	    ol_check_intersect_excl(f2_l, f2_h, f1_l) ||
	    ol_check_intersect_excl(f2_l, f2_h, f1_h)
	);

	return (ret);
}

/*
 * Check whether the given channel overlaps (exclusive, not inclusive)
 * the given centre frequency and width.
 *
 * This has to take the VHT flags into account.
 *
 * XXX TODO: 80 + 80 requires two checks!
 * XXX TODO: no 160MHz support!
 */
int
ieee80211_check_channel_overlap(struct ieee80211com *ic,
    struct ieee80211_ath_channel *chan, int nol_freq, int nol_width)
{
	int chan_freq;
	int chan_width;
        int overlap = 0;

	/* Calculate centre frequency */
	chan_freq = ieee80211_get_chan_centre_freq(ic, chan);

	/* Grab width */
	chan_width = ieee80211_get_chan_width(chan);

#if 0
	qdf_print("%s: checking ic_freq=%d, chan_freq=%d, chan_width=%d; freq=%d"
	    " against nol_freq=%d, nol_width=%d",
	    __func__,
	    chan->ic_freq,
	    chan_freq,
	    chan_width,
	    chan->ic_vhtop_ch_freq_seg1,
	    nol_freq,
	    nol_width);
#endif
        if (IEEE80211_IS_CHAN_11AC_VHT80_80 (chan) ||
                IEEE80211_IS_CHAN_11AXA_HE80_80 (chan)) {
            /* HT80_80 mode has 2 segments and */
            /* each segment must be checked    */
            /* check for control channel first */
	    overlap = ieee80211_check_overlap(chan_freq, chan_width/2, nol_freq, nol_width);
            /* check extension channel */
            chan_freq = chan->ic_vhtop_freq_seg2;
	    overlap += ieee80211_check_overlap(chan_freq, chan_width/2, nol_freq, nol_width);
        } else {
	    /* Return if there's overlap */
	    overlap = ieee80211_check_overlap(chan_freq, chan_width, nol_freq, nol_width);
        }
        return overlap;
}

void
ieee80211_get_extchaninfo(struct ieee80211com *ic,
        struct ieee80211_ath_channel *chan,
        struct ieee80211_ath_channel_list *chan_info)
{
    int chan_center;
    uint64_t flags = 0;

    if (IEEE80211_IS_CHAN_6GHZ(chan)) {
        flags = IEEE80211_CHAN_6GHZ | IEEE80211_CHAN_HE20;
    } else {
        flags = (chan->ic_flags & (IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_2GHZ)) | IEEE80211_CHAN_HT20;
    }

    if (IEEE80211_IS_CHAN_11AXA_HE40PLUS(chan) ||
            IEEE80211_IS_CHAN_11AC_VHT40PLUS(chan) ||
            IEEE80211_IS_CHAN_11NA_HT40PLUS(chan)) {
        chan_info->cl_nchans = 2;
        chan_info->cl_channels[0] = chan;
        chan_info->cl_channels[1] = ic->ic_find_channel(ic, chan->ic_freq + 20, 0, flags);
    } else if (IEEE80211_IS_CHAN_11AXA_HE40MINUS(chan) ||
            IEEE80211_IS_CHAN_11AC_VHT40MINUS(chan) ||
            IEEE80211_IS_CHAN_11NA_HT40MINUS(chan)) {
        chan_info->cl_nchans = 2;
        chan_info->cl_channels[0] = chan;
        chan_info->cl_channels[1] = ic->ic_find_channel(ic, chan->ic_freq - 20, 0, flags);
    } else if (IEEE80211_IS_CHAN_11AXA_HE80(chan) ||
            IEEE80211_IS_CHAN_11AC_VHT80(chan)) {
        chan_center = chan->ic_vhtop_freq_seg1;
        chan_info->cl_nchans = 4;
        chan_info->cl_channels[0] = ic->ic_find_channel(ic, chan_center - 30, 0, flags);
        chan_info->cl_channels[1] = ic->ic_find_channel(ic, chan_center - 10, 0, flags);
        chan_info->cl_channels[2] = ic->ic_find_channel(ic, chan_center + 10, 0, flags);
        chan_info->cl_channels[3] = ic->ic_find_channel(ic, chan_center + 30, 0, flags);
    } else if (IEEE80211_IS_CHAN_11AXA_HE160(chan) ||
            IEEE80211_IS_CHAN_11AC_VHT160(chan)) {
        chan_center = chan->ic_vhtop_freq_seg2;
        chan_info->cl_nchans = 8;
        chan_info->cl_channels[0] = ic->ic_find_channel(ic, chan_center - 70, 0, flags);
        chan_info->cl_channels[1] = ic->ic_find_channel(ic, chan_center - 50, 0, flags);
        chan_info->cl_channels[2] = ic->ic_find_channel(ic, chan_center - 30, 0, flags);
        chan_info->cl_channels[3] = ic->ic_find_channel(ic, chan_center - 10, 0, flags);
        chan_info->cl_channels[4] = ic->ic_find_channel(ic, chan_center + 70, 0, flags);
        chan_info->cl_channels[5] = ic->ic_find_channel(ic, chan_center + 50, 0, flags);
        chan_info->cl_channels[6] = ic->ic_find_channel(ic, chan_center + 30, 0, flags);
        chan_info->cl_channels[7] = ic->ic_find_channel(ic, chan_center + 10, 0, flags);
    } else if (IEEE80211_IS_CHAN_11AXA_HE80_80(chan) ||
            IEEE80211_IS_CHAN_11AC_VHT80_80(chan)) {
        chan_center = chan->ic_vhtop_freq_seg1;
        chan_info->cl_nchans = 8;
        chan_info->cl_channels[0] = ic->ic_find_channel(ic, chan_center - 30, 0, flags);
        chan_info->cl_channels[1] = ic->ic_find_channel(ic, chan_center - 10, 0, flags);
        chan_info->cl_channels[2] = ic->ic_find_channel(ic, chan_center + 10, 0, flags);
        chan_info->cl_channels[3] = ic->ic_find_channel(ic, chan_center + 30, 0, flags);

        chan_center = chan->ic_vhtop_freq_seg2;

        chan_info->cl_channels[4] = ic->ic_find_channel(ic, chan_center - 30, 0, flags);
        chan_info->cl_channels[5] = ic->ic_find_channel(ic, chan_center - 10, 0, flags);
        chan_info->cl_channels[6] = ic->ic_find_channel(ic, chan_center + 10, 0, flags);
        chan_info->cl_channels[7] = ic->ic_find_channel(ic, chan_center + 30, 0, flags);
    } else  {
        chan_info->cl_nchans = 1;
        chan_info->cl_channels[0] = chan;
    }
    return;
}

/***
  Check whether missing extchan is 144
**/
u_int8_t ieee80211_is_extchan_144(struct ieee80211com *ic,
           struct ieee80211_ath_channel *chan, u_int8_t extchan)
{
   u_int16_t chan_center = 0;
   u_int16_t chan_center2 = 0;
   u_int16_t chan_freq = chan->ic_freq;

   if(IEEE80211_IS_CHAN_11AC_VHT80(chan)) {
      chan_center = chan->ic_vhtop_freq_seg1;
   }
   if(IEEE80211_IS_CHAN_11AC_VHT80_80(chan)) {
      chan_center = chan->ic_vhtop_freq_seg1;
      chan_center2 = chan->ic_vhtop_freq_seg2;
   }
   /* Check whether the channel freq is with in the range */
   /* if it is primary, extchan 144 index is 3 */
   /* if it is secondary, extchan 144 index is 7 */
   if(((chan_center == 5690) && (extchan == 3))||
      ((chan_center2 == 5690) && (extchan == 7))) {
      return 1;
   }
   /* For HT40+, extchan 144 index is 1 */
   if (chan_freq == 5700) {
      if((IEEE80211_IS_CHAN_11NA_HT40PLUS(chan) ||
            IEEE80211_IS_CHAN_11AC_VHT40PLUS(chan)) &&
         (extchan == 1)) {
         return 1;
      }
   }
   return 0;
}

/**
 * @brief finds the offset for secondary twenty channel
 *
 * @param chan: channel for which secondary offset to find
 */

int8_t
ieee80211_secondary20_channel_offset(struct ieee80211_ath_channel *chan)
{

    int8_t pri_center_ch_diff, sec_level;
    u_int16_t pri_chan_40_center;

    if (!chan || IEEE80211_IS_CHAN_A(chan) ||
        IEEE80211_IS_CHAN_B(chan) || IEEE80211_IS_CHAN_G(chan) ||
        IEEE80211_IS_CHAN_PUREG(chan) || IEEE80211_IS_CHAN_ANYG(chan) ||
        IEEE80211_IS_CHAN_11N_HT20(chan) || IEEE80211_IS_CHAN_11AC_VHT20(chan) ||
        IEEE80211_IS_CHAN_11AX_HE20(chan)) {
        /* No secondary channel */
        return 0;
    }

    if (IEEE80211_IS_CHAN_11AXG_HE40PLUS(chan) ||
            IEEE80211_IS_CHAN_11AXA_HE40PLUS(chan) ||
            IEEE80211_IS_CHAN_11AC_VHT40PLUS(chan) ||
            IEEE80211_IS_CHAN_11NG_HT40PLUS(chan) ||
            IEEE80211_IS_CHAN_11NA_HT40PLUS(chan)) {
            return 1;
    }

    if (IEEE80211_IS_CHAN_11AXG_HE40MINUS(chan) ||
            IEEE80211_IS_CHAN_11AXA_HE40MINUS(chan) ||
            IEEE80211_IS_CHAN_11AC_VHT40MINUS(chan) ||
            IEEE80211_IS_CHAN_11NG_HT40MINUS(chan) ||
            IEEE80211_IS_CHAN_11NA_HT40MINUS(chan)) {
            return -1;
    }

    if (IEEE80211_IS_CHAN_11AXA_HE80(chan) ||
            IEEE80211_IS_CHAN_11AXA_HE80_80(chan) ||
            IEEE80211_IS_CHAN_11AC_VHT80(chan) ||
            IEEE80211_IS_CHAN_11AC_VHT80_80(chan)) {
        /* The following logic generates the extension channel offset from
         * the primary channel(ic_ieee) and 80M channel central frequency.
         * The channelization for 80M is as following:
         * | 20M  20M  20M  20M | with the following example | 36 40 44 48 |
         * |         80M        |                |     80M     |
         * The central frequency is 42 in the example.
         * If the primary channel is 36 and 44, the extension channel is 40PLUS.
         * If the primary channel is 40 and 48 the extension channel is 40MINUS.
         */

        if (chan->ic_ieee < chan->ic_vhtop_ch_num_seg1) {
            if ((chan->ic_vhtop_ch_num_seg1 - chan->ic_ieee) > 4) {
                return 1;
            } else {
                return -1;
            }
        } else {
            if ((chan->ic_ieee - chan->ic_vhtop_ch_num_seg1) > 4) {
                return -1;
            } else {
                return 1;
            }
        }
    }

    if (IEEE80211_IS_CHAN_11AXA_HE160(chan) ||
            IEEE80211_IS_CHAN_11AC_VHT160(chan)) {
        /* The channelization of 160M is as following:
         * | 20M 20M 20M 20M 20M 20M 20M 20M | with following example |
         * 36 40 44 48 52 56 60 64 | The center frequency is 40 in this example.
         * If primary channel is 36, 44, 52 or 60, the extension channel is 40PLUS.
         * If primary channel is 40, 48, 56 or 64, the extension channel is 40MINUS.
         */

        pri_center_ch_diff = chan->ic_ieee - chan->ic_vhtop_ch_num_seg2;

        if (pri_center_ch_diff > 0) {
            sec_level = -1;
        } else {
            sec_level = 1;
        }

        if (sec_level*pri_center_ch_diff < -6) {
            pri_chan_40_center = chan->ic_vhtop_ch_num_seg2 - (2*sec_level*6);
        } else {
            pri_chan_40_center = chan->ic_vhtop_ch_num_seg2 - (2*sec_level*2);
        }

        if (pri_chan_40_center > chan->ic_ieee) {
            return 1;
        } else {
            return -1;
        }
    }

    return 0;
}

uint8_t
ieee80211_sec_chan_offset(struct ieee80211_ath_channel *chan)
{
    int     offset      = 0;
    uint8_t secoffset   = 0;

    offset = ieee80211_secondary20_channel_offset(chan);
    switch (offset) {
        case 1:
            secoffset = IEEE80211_SEC_CHAN_OFFSET_SCA;
            break;
        case -1:
            secoffset = IEEE80211_SEC_CHAN_OFFSET_SCB;
            break;
        case 0:
        default:
            secoffset = IEEE80211_SEC_CHAN_OFFSET_SCN;
            break;
    }
    return secoffset;
}


/**
* @brief finds current mode of underlying
         radio interface (like a/b/g/n/ac/ax etc)
*
* @param ic pointer to struct ieee80211com
*
* @return current phymode or invalid
*/
enum ieee80211_mode ieee80211_get_mode(struct ieee80211com *ic)
{
    struct ieee80211_ath_channel *ch = ic->ic_curchan;
    enum ieee80211_mode mode = IEEE80211_MODE_INVALID;

    if (IEEE80211_IS_CHAN_A(ch)) {
        mode = IEEE80211_MODE_A;
    } else if (IEEE80211_IS_CHAN_B(ch)) {
        mode = IEEE80211_MODE_B;
    } else if (IEEE80211_IS_CHAN_G(ch) ||
            IEEE80211_IS_CHAN_PUREG(ch) ||
            IEEE80211_IS_CHAN_ANYG(ch)) {
        mode = IEEE80211_MODE_G;
    } else if (IEEE80211_IS_CHAN_11NG(ch) ||
               IEEE80211_IS_CHAN_11NA(ch)) {
        mode = IEEE80211_MODE_N;
    } else if (IEEE80211_IS_CHAN_VHT(ch)) {
        mode = IEEE80211_MODE_AC;
    } else if (IEEE80211_IS_CHAN_11AXG(ch) ||
               IEEE80211_IS_CHAN_11AXA(ch)) {
        mode = IEEE80211_MODE_AX;
    }

    return mode;
}

/**
 * get_mode_from_phymode() - get phy type from phymode
 * @phymode: phymode
 *
 * get phy type from phymode
 *
 * Return: ieee80211_mode corrosponding to the phy mode
 */
enum ieee80211_mode get_mode_from_phymode(enum ieee80211_phymode phymode) {
    enum ieee80211_mode mode = IEEE80211_MODE_INVALID;

    switch(phymode) {
        case IEEE80211_MODE_AUTO:
            mode = IEEE80211_MODE_INVALID;
            break;
        case IEEE80211_MODE_11A:
            mode = IEEE80211_MODE_A;
            break;
        case IEEE80211_MODE_11B:
            mode = IEEE80211_MODE_B;
            break;
        case IEEE80211_MODE_11G:
            mode = IEEE80211_MODE_G;
            break;
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NA_HT40:
            mode = IEEE80211_MODE_NA;
            break;
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
            mode = IEEE80211_MODE_NG;
            break;
        case IEEE80211_MODE_11AC_VHT20:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
            mode = IEEE80211_MODE_AC;
            break;
        case IEEE80211_MODE_11AXA_HE20:
        case IEEE80211_MODE_11AXA_HE40PLUS:
        case IEEE80211_MODE_11AXA_HE40MINUS:
        case IEEE80211_MODE_11AXA_HE40:
        case IEEE80211_MODE_11AXA_HE80:
        case IEEE80211_MODE_11AXA_HE160:
        case IEEE80211_MODE_11AXA_HE80_80:
            mode = IEEE80211_MODE_AXA;
            break;
        case IEEE80211_MODE_11AXG_HE20:
        case IEEE80211_MODE_11AXG_HE40PLUS:
        case IEEE80211_MODE_11AXG_HE40MINUS:
        case IEEE80211_MODE_11AXG_HE40:
            mode = IEEE80211_MODE_AXG;
            break;
        default:
            mode = IEEE80211_MODE_INVALID;
            break;
    }

    return mode;
}

/**
* @brief calclulates composite phymode from given mode,
         chwidth and secondary channel offset.
*
* @param mode       :   a/b/g/n/ac etc
* @param chwidth    :   channel width
* @param secchanoffset: secondary channel offset.
*
* @return ieee80211_phymode
*/
enum ieee80211_phymode ieee80211_get_composite_phymode (enum ieee80211_mode mode,
        enum ieee80211_cwm_width chwidth, uint8_t secchanoffset)
{
    enum ieee80211_phymode phymode = IEEE80211_MODE_AUTO;

    switch(mode) {
        case IEEE80211_MODE_AXA:
        {
            if (chwidth == IEEE80211_CWM_WIDTH20) {
                phymode = IEEE80211_MODE_11AXA_HE20;
            } else if (chwidth == IEEE80211_CWM_WIDTH40) {
                if (secchanoffset == IEEE80211_SEC_CHAN_OFFSET_SCA) {
                    phymode = IEEE80211_MODE_11AXA_HE40PLUS;
                } else if (secchanoffset == IEEE80211_SEC_CHAN_OFFSET_SCB) {
                    phymode = IEEE80211_MODE_11AXA_HE40MINUS;
                }
            } else if (chwidth == IEEE80211_CWM_WIDTH80) {
                phymode = IEEE80211_MODE_11AXA_HE80;
            } else if (chwidth == IEEE80211_CWM_WIDTH160) {
                phymode = IEEE80211_MODE_11AXA_HE160;
            } else if (chwidth == IEEE80211_CWM_WIDTH80_80) {
                phymode = IEEE80211_MODE_11AXA_HE80_80;
            }
            break;
        }
        case IEEE80211_MODE_AXG:
        {
            if (chwidth == IEEE80211_CWM_WIDTH20) {
                phymode = IEEE80211_MODE_11AXG_HE20;
            } else if (chwidth == IEEE80211_CWM_WIDTH40) {
                if (secchanoffset == IEEE80211_SEC_CHAN_OFFSET_SCA) {
                    phymode = IEEE80211_MODE_11AXG_HE40PLUS;
                } else if (secchanoffset == IEEE80211_SEC_CHAN_OFFSET_SCB) {
                    phymode = IEEE80211_MODE_11AXG_HE40MINUS;
                }
            }
            break;
        }
        case IEEE80211_MODE_AC:
        {
            if (chwidth == IEEE80211_CWM_WIDTH20) {
                phymode = IEEE80211_MODE_11AC_VHT20;
            } else if (chwidth == IEEE80211_CWM_WIDTH40) {
                if (secchanoffset == IEEE80211_SEC_CHAN_OFFSET_SCA) {
                    phymode = IEEE80211_MODE_11AC_VHT40PLUS;
                } else if (secchanoffset == IEEE80211_SEC_CHAN_OFFSET_SCB) {
                    phymode = IEEE80211_MODE_11AC_VHT40MINUS;
                }
            } else if (chwidth == IEEE80211_CWM_WIDTH80) {
                phymode = IEEE80211_MODE_11AC_VHT80;
            } else if (chwidth == IEEE80211_CWM_WIDTH160) {
                phymode = IEEE80211_MODE_11AC_VHT160;
            } else if (chwidth == IEEE80211_CWM_WIDTH80_80) {
                phymode = IEEE80211_MODE_11AC_VHT80_80;
            }
            break;
        }
        case IEEE80211_MODE_NA:
        {
            if (chwidth == IEEE80211_CWM_WIDTH20) {
                phymode = IEEE80211_MODE_11NA_HT20;
            } else if (chwidth == IEEE80211_CWM_WIDTH40) {
                if (secchanoffset == IEEE80211_SEC_CHAN_OFFSET_SCA) {
                    phymode = IEEE80211_MODE_11NA_HT40PLUS;
                } else if (secchanoffset == IEEE80211_SEC_CHAN_OFFSET_SCB) {
                    phymode = IEEE80211_MODE_11NA_HT40MINUS;
                }
            }
            break;
        }
        case IEEE80211_MODE_NG:
        {
            if (chwidth == IEEE80211_CWM_WIDTH20) {
                phymode = IEEE80211_MODE_11NG_HT20;
            } else if (chwidth == IEEE80211_CWM_WIDTH40) {
                if (secchanoffset == IEEE80211_SEC_CHAN_OFFSET_SCA) {
                    phymode = IEEE80211_MODE_11NG_HT40PLUS;
                } else if (secchanoffset == IEEE80211_SEC_CHAN_OFFSET_SCB) {
                    phymode = IEEE80211_MODE_11NG_HT40MINUS;
                }
            }
            break;
        }
        case IEEE80211_MODE_A:
        {
            if (chwidth == IEEE80211_CWM_WIDTH20) {
                phymode = IEEE80211_MODE_11A;
            }
            break;
        }
        case IEEE80211_MODE_G:
        {
            if (chwidth == IEEE80211_CWM_WIDTH20) {
                phymode = IEEE80211_MODE_11G;
            }
            break;
        }
        case IEEE80211_MODE_B:
        {
            if (chwidth == IEEE80211_CWM_WIDTH20) {
                phymode = IEEE80211_MODE_11B;
            }
            break;
        }
        default:
        {
            break;
        }
    }

    return phymode;
}

enum ieee80211_cwm_width
ieee80211_get_cwm_width_from_channel(struct ieee80211_ath_channel *chan)
{
    /* enum ieee80211_cwm_width = IEEE80211_CWM_WIDTHINVALID; */

   if (IEEE80211_IS_CHAN_11AXA(chan)) {
        if (IEEE80211_IS_CHAN_11AXA_HE80_80(chan)) {
            return IEEE80211_CWM_WIDTH80_80;
        }
        if (IEEE80211_IS_CHAN_11AXA_HE160(chan)) {
            return IEEE80211_CWM_WIDTH160;
        }
        if (IEEE80211_IS_CHAN_11AXA_HE80(chan)) {
            return IEEE80211_CWM_WIDTH80;
        }
        if (IEEE80211_IS_CHAN_11AXA_HE40(chan)) {
            return IEEE80211_CWM_WIDTH40;
        }
        if (IEEE80211_IS_CHAN_11AXA_HE20(chan)) {
            return IEEE80211_CWM_WIDTH20;
        }
    }

    if (IEEE80211_IS_CHAN_11AXG(chan)) {
        if (IEEE80211_IS_CHAN_11AXG_HE20(chan)) {
            return IEEE80211_CWM_WIDTH20;
        } else {
            return IEEE80211_CWM_WIDTH40;
        }
    }

    if (IEEE80211_IS_CHAN_11AC(chan)) {
        if (IEEE80211_IS_CHAN_11AC_VHT80_80(chan)) {
            return IEEE80211_CWM_WIDTH80_80;
        }
        if (IEEE80211_IS_CHAN_11AC_VHT160(chan)) {
            return IEEE80211_CWM_WIDTH160;
        }
        if (IEEE80211_IS_CHAN_11AC_VHT80(chan)) {
            return IEEE80211_CWM_WIDTH80;
        }
        if (IEEE80211_IS_CHAN_11AC_VHT40(chan)) {
            return IEEE80211_CWM_WIDTH40;
        }
        if (IEEE80211_IS_CHAN_11AC_VHT20(chan)) {
            return IEEE80211_CWM_WIDTH20;
        }
    }

    if (IEEE80211_IS_CHAN_11N(chan)) {
        if (IEEE80211_IS_CHAN_11NA_HT20(chan) || IEEE80211_IS_CHAN_11NG_HT20(chan)) {
            return IEEE80211_CWM_WIDTH20;
        } else {
            return IEEE80211_CWM_WIDTH40;
        }
    }

    return IEEE80211_CWM_WIDTH20;
}

static enum ieee80211_phymode
ieee80211_get_11axa_phymode(uint64_t chan_flag)
{
    enum ieee80211_phymode mode;

    switch (chan_flag & IEEE80211_CHAN_HE_ALL) {
        case IEEE80211_CHAN_HE20:
            mode = IEEE80211_MODE_11AXA_HE20;
            break;
        case IEEE80211_CHAN_HE40PLUS:
            mode = IEEE80211_MODE_11AXA_HE40PLUS;
            break;
        case IEEE80211_CHAN_HE40MINUS:
            mode = IEEE80211_MODE_11AXA_HE40MINUS;
            break;
        case IEEE80211_CHAN_HE80:
            mode = IEEE80211_MODE_11AXA_HE80;
            break;
        case IEEE80211_CHAN_HE80_80:
            mode = IEEE80211_MODE_11AXA_HE80_80;
            break;
        case IEEE80211_CHAN_HE160:
            mode = IEEE80211_MODE_11AXA_HE160;
            break;
        default:
            mode = 0;
    }

    return mode;
}

static enum ieee80211_phymode
ieee80211_get_11axg_phymode(uint64_t chan_flag)
{
    enum ieee80211_phymode mode;

    switch (chan_flag) {
        case IEEE80211_CHAN_HE20:
            mode = IEEE80211_MODE_11AXG_HE20;
            break;
        case IEEE80211_CHAN_HE40PLUS:
            mode = IEEE80211_MODE_11AXG_HE40PLUS;
            break;
        case IEEE80211_CHAN_HE40MINUS:
            mode = IEEE80211_MODE_11AXG_HE40MINUS;
            break;
        default:
            mode = 0;
            break;
    }

    return mode;
}

static enum ieee80211_phymode
ieee80211_get_11ac_phymode(uint64_t chan_flag)
{
    enum ieee80211_phymode mode;

    switch (chan_flag) {
        case IEEE80211_CHAN_VHT20:
            mode = IEEE80211_MODE_11AC_VHT20;
            break;
        case IEEE80211_CHAN_VHT40PLUS:
            mode = IEEE80211_MODE_11AC_VHT40PLUS;
            break;
        case IEEE80211_CHAN_VHT40MINUS:
            mode = IEEE80211_MODE_11AC_VHT40MINUS;
            break;
        case IEEE80211_CHAN_VHT80:
            mode = IEEE80211_MODE_11AC_VHT80;
            break;
        case IEEE80211_CHAN_VHT80_80:
            mode = IEEE80211_MODE_11AC_VHT80_80;
            break;
        case IEEE80211_CHAN_VHT160:
            mode = IEEE80211_MODE_11AC_VHT160;
            break;
        default:
            mode = 0;
            break;
    }

    return mode;
}

static enum ieee80211_phymode
ieee80211_get_11n_phymode(uint64_t chan_flag)
{
    enum ieee80211_phymode mode = 0;

    if (chan_flag & IEEE80211_CHAN_5GHZ) {
        switch (chan_flag) {
            case IEEE80211_CHAN_HT20:
                mode = IEEE80211_MODE_11NA_HT20;
                break;
            case IEEE80211_CHAN_HT40PLUS:
                mode = IEEE80211_MODE_11NA_HT40PLUS;
                break;
            case IEEE80211_CHAN_HT40MINUS:
                mode = IEEE80211_MODE_11NA_HT40MINUS;
                break;
	}
    } else if (chan_flag & IEEE80211_CHAN_2GHZ) {
        switch (chan_flag) {
            case IEEE80211_CHAN_HT20:
                mode = IEEE80211_MODE_11NG_HT20;
                break;
            case IEEE80211_CHAN_HT40PLUS:
                mode = IEEE80211_MODE_11NG_HT40PLUS;
                break;
            case IEEE80211_CHAN_HT40MINUS:
                mode = IEEE80211_MODE_11NG_HT40MINUS;
                break;
	}
    }

    return mode;
}

enum ieee80211_phymode
ieee80211_get_phymode_from_chan_flag(
        struct ieee80211_ath_channel *curchan,
        uint64_t chan_flag)
{
    enum ieee80211_phymode mode = 0;

    if (IEEE80211_IS_CHAN_11AXA(curchan))
        mode = ieee80211_get_11axa_phymode(chan_flag);
    else if (IEEE80211_IS_CHAN_11AXG(curchan))
        mode = ieee80211_get_11axg_phymode(chan_flag);
    else if (IEEE80211_IS_CHAN_11AC(curchan))
        mode = ieee80211_get_11ac_phymode(chan_flag);
    else if (IEEE80211_IS_CHAN_11N(curchan))
        mode = ieee80211_get_11n_phymode(chan_flag);

    return mode;
}

int wlan_get_target_phymode(struct ieee80211com *ic, uint32_t phymode,
                            bool is_2gvht_en)
{
    if (ic && ic->ic_get_target_phymode)
        return ic->ic_get_target_phymode(ic, phymode, is_2gvht_en);
    return 0;
}

bool
ieee80211_update_custom_scan_chan_list(
        struct ieee80211vap *vap, bool associated)
{
    struct ieee80211com *ic = NULL;
    uint32_t chcount = 0;
    uint32_t *chanlist = NULL;
    struct chan_list *chan_list = NULL;
    enum wlan_band band;
    int i = 0;

#if ATH_SUPPORT_WRAP
    if (!vap || !vap->iv_ic || (vap->iv_psta && !vap->iv_mpsta))
        return false;
#endif

    ic = vap->iv_ic;
    if (ic->ic_use_custom_chan_list) {
        if (associated && ic->ic_custom_chanlist_assoc_size) {
            chcount = ic->ic_custom_chanlist_assoc_size;
            chanlist = ic->ic_custom_chan_list_associated;
        } else if (ic->ic_custom_chanlist_nonassoc_size) {
            chcount = ic->ic_custom_chanlist_nonassoc_size;
            chanlist = ic->ic_custom_chan_list_nonassociated;
        }
    }
    if (chcount) {
        chan_list = qdf_mem_malloc(sizeof(*chan_list));

        if (!chan_list) {
             qdf_err("chan_list is NULL");
             return false;
        }

        chan_list->num_chan =  chcount;
        for (i = 0; i < chcount; i++) {
            chan_list->chan[i].freq = chanlist[i];
            band = util_scan_scm_chan_to_band(chan_list->chan[i].freq);
            if (band == WLAN_BAND_2_4_GHZ)
                chan_list->chan[i].phymode = SCAN_PHY_MODE_11G;
            else
                chan_list->chan[i].phymode = SCAN_PHY_MODE_11A;
        }
    }
    ucfg_scan_set_custom_scan_chan_list(ic->ic_pdev_obj, chan_list);
    if (chan_list)
        qdf_mem_free(chan_list);

    return true;
}

void ieee80211_update_vdev_chan(struct wlan_channel *vdev_chan,
        struct ieee80211_ath_channel *curchan)
{
    enum ieee80211_phymode phymode;
    if (curchan == IEEE80211_CHAN_ANYC) {
        qdf_mem_zero(vdev_chan, sizeof(struct wlan_channel));
    } else {
        vdev_chan->ch_freq = curchan->ic_freq;
        vdev_chan->ch_ieee = curchan->ic_ieee;
        vdev_chan->ch_flags = curchan->ic_flags;
        vdev_chan->ch_flagext = curchan->ic_flagext;
        vdev_chan->ch_maxpower = curchan->ic_maxpower;
        vdev_chan->ch_freq_seg1 = curchan->ic_vhtop_ch_num_seg1;
        vdev_chan->ch_freq_seg2 = curchan->ic_vhtop_ch_num_seg2;
        vdev_chan->ch_cfreq1 = curchan->ic_vhtop_freq_seg1;
        vdev_chan->ch_cfreq2 = curchan->ic_vhtop_freq_seg2;
        vdev_chan->ch_width = ieee80211_get_phy_chan_width(curchan);

        phymode = ieee80211_chan2mode(curchan);
        vdev_chan->ch_phymode = phymode2convphymode[phymode];
    }
}

enum wlan_band_id ieee80211_get_ath_channel_band(struct ieee80211_ath_channel *chan)
{
    if (IEEE80211_IS_CHAN_2GHZ(chan)) {
        return WLAN_BAND_2GHZ;
    } else if (IEEE80211_IS_CHAN_5GHZ(chan)) {
        return WLAN_BAND_5GHZ;
    } else if (IEEE80211_IS_CHAN_6GHZ(chan)) {
        return WLAN_BAND_6GHZ;
    }

    return WLAN_BAND_UNSPECIFIED;
}

enum reg_wifi_band wlan_band_id_to_reg_wifi_band(
        enum wlan_band_id wlan_band)
{
    static uint32_t
        wlan_band_id_to_reg_wifi_band_map[] = {
            [WLAN_BAND_UNSPECIFIED] = BIT(REG_BAND_2G) | BIT(REG_BAND_5G),
            [WLAN_BAND_2GHZ] = BIT(REG_BAND_2G),
            [WLAN_BAND_5GHZ] = BIT(REG_BAND_5G),
            [WLAN_BAND_6GHZ] = BIT(REG_BAND_6G),
        };

        if ((wlan_band < WLAN_BAND_UNSPECIFIED) ||
            (wlan_band >= WLAN_BAND_MAX)) {
            qdf_warn("Invalid wlan_band %d", wlan_band);
            return -EINVAL;
        }

        return wlan_band_id_to_reg_wifi_band_map[wlan_band];
}

enum wlan_band_id reg_wifi_band_to_wlan_band_id(
        enum reg_wifi_band reg_wifi_band)
{
    enum wlan_band_id wlan_band;
    static uint32_t
        reg_wifi_band_to_wlan_band_id_map[] = {
            [REG_BAND_2G] = WLAN_BAND_2GHZ,
            [REG_BAND_5G] = WLAN_BAND_5GHZ,
            [REG_BAND_6G] = WLAN_BAND_6GHZ,
            [REG_BAND_UNKNOWN] = WLAN_BAND_MAX,
        };

        if ((reg_wifi_band < REG_BAND_2G) || (reg_wifi_band >= REG_BAND_UNKNOWN)) {
            qdf_warn("Invalid reg_wifi_band %d", reg_wifi_band);
            dump_stack();
            return -EINVAL;
        }

        wlan_band = reg_wifi_band_to_wlan_band_id_map[reg_wifi_band];
        if (wlan_band == WLAN_BAND_MAX) {
            qdf_warn("Invalid wlan_band_id %d, reg_wifi_band: %d", wlan_band, reg_wifi_band);
            dump_stack();
            return -EINVAL;
        }

        return wlan_band;
}

uint16_t wlan_get_wlan_band_id_chan_to_freq(
        struct wlan_objmgr_pdev *pdev,
        uint8_t chan, enum wlan_band_id wlan_band)
{
    enum reg_wifi_band reg_wifi_band;
    struct ieee80211com *ic;
    uint16_t freq = 0;

    if (!pdev)
        return 0;

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!ic)
        return 0;

    if (!chan) {
        return freq;
    }

    if ((wlan_band < WLAN_BAND_UNSPECIFIED) ||
        (wlan_band >= WLAN_BAND_MAX))
        return 0;

    if (ic->ic_49ghz_enabled)
        reg_wifi_band = BIT(REG_BAND_5G);
    else
        reg_wifi_band = wlan_band_id_to_reg_wifi_band(wlan_band);

    freq = wlan_reg_chan_band_to_freq(pdev, chan, reg_wifi_band);
    if (!freq) {
        qdf_warn("Invalid freq: %d, wlan_band: %d, reg_wifi_band: %d, chan: %d",
                freq, wlan_band, reg_wifi_band, chan);
    }

    return freq;
}
