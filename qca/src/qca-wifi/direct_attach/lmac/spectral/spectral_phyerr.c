/* Copyright (c) 2011, 2017, 2019 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 */

/*
 * Copyright (c) 2002-2009 Atheros Communications, Inc.
 * All Rights Reserved.
 *
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include <osdep.h>
#include "spectral.h"
#if WLAN_SPECTRAL_ENABLE

/*
 * Function     : print_buf
 * Description  : Prints given buffer for given length
 * Input        : Pointer to buffer and length
 * Output       : Void
 *
 */
void print_buf(u_int8_t* pbuf, int len)
{
    int i = 0;
    for (i = 0; i < len; i++) {
        qdf_nofl_info("%02X ", pbuf[i]);
        if (i % 32 == 31) {
            qdf_nofl_info("\n");
        }
    }
}

/*
 * Function     : spectral_dump_fft
 * Description  : Dump Spectral FFT
 * Input        : Pointer to Spectral Phyerr FFT
 * Output       : Success/Failure
 *
 */
int spectral_dump_fft(u_int8_t* pfft, int fftlen)
{
    int i = 0;

    /* TODO : Do not delete the following print
     *        The scripts used to validate Spectral depend on this Print
     */
    qdf_nofl_info("SPECTRAL : FFT Length is 0x%x (%d)\n", fftlen, fftlen);

    qdf_nofl_info("fft_data # ");
    for (i = 0; i < fftlen; i++) {
        qdf_nofl_info("%d ", pfft[i]);
#if 0
        if (i % 32 == 31)
            qdf_nofl_info("\n");
#endif
    }
    qdf_nofl_info("\n");
    return 0;
}

/*
 * Function     : spectral_send_tlv_to_host
 * Description  : Send the TLV information to Host
 * Input        : Pointer to the TLV
 * Output       : Success/Failure
 *
 */

#ifdef HOST_OFFLOAD
extern void
atd_spectral_msg_send(struct net_device *dev, struct spectral_samp_msg *msg, uint16_t msg_len);
#endif

int spectral_send_tlv_to_host(struct ath_spectral* spectral, u_int8_t* data, u_int32_t datalen)
{

    int status = AH_TRUE;
    spectral_prep_skb(spectral);
    if (spectral->spectral_skb != NULL) {
        spectral->spectral_nlh = (struct nlmsghdr*)spectral->spectral_skb->data;
        memcpy(NLMSG_DATA(spectral->spectral_nlh), data, datalen);
        spectral_bcast_msg(spectral);
    } else {
        status = AH_FALSE;
    }
#ifdef HOST_OFFLOAD
    atd_spectral_msg_send(spectral->ic->ic_osdev->netdev,
            data,
            datalen);
#endif
    return status;
}qdf_export_symbol(spectral_send_tlv_to_host);

/*
 * Function     : dbg_print_SAMP_param
 * Description  : Print contents of SAMP struct
 * Input        : Pointer to SAMP message
 * Output       : Void
 *
 */
void dbg_print_SAMP_param(struct samp_msg_params* p)
{
    qdf_nofl_info("\nSAMP Packet : -------------------- START --------------------\n");
    qdf_nofl_info("Freq        = %d\n", p->freq);
    qdf_nofl_info("RSSI        = %d\n", p->rssi);
    qdf_nofl_info("Bin Count   = %d\n", p->pwr_count);
    qdf_nofl_info("Timestamp   = %d\n", p->tstamp);
    qdf_nofl_info("SAMP Packet : -------------------- END -----------------------\n");
}

/*
 * Function     : dbg_print_SAMP_msg
 * Description  : Print contents of SAMP Message
 * Input        : Pointer to SAMP message
 * Output       : Void
 *
 */
void dbg_print_SAMP_msg(struct spectral_samp_msg* ss_msg)
{
    int i = 0;

    struct spectral_samp_data *p = &ss_msg->samp_data;
    struct spectral_classifier_params *pc = &p->classifier_params;
    struct interf_src_rsp  *pi = &p->interf_list;

    line();
    qdf_nofl_info("Spectral Message\n");
    line();
    qdf_nofl_info("Signature   :   0x%x\n", ss_msg->signature);
    qdf_nofl_info("Freq        :   %d\n", ss_msg->freq);
    qdf_nofl_info("Freq load   :   %d\n", ss_msg->freq_loading);
    qdf_nofl_info("Intfnc type :   %d\n", ss_msg->int_type);
    line();
    qdf_nofl_info("Spectral Data info\n");
    line();
    qdf_nofl_info("data length     :   %d\n", p->spectral_data_len);
    qdf_nofl_info("rssi            :   %d\n", p->spectral_rssi);
    qdf_nofl_info("combined rssi   :   %d\n", p->spectral_combined_rssi);
    qdf_nofl_info("upper rssi      :   %d\n", p->spectral_upper_rssi);
    qdf_nofl_info("lower rssi      :   %d\n", p->spectral_lower_rssi);
    qdf_nofl_info("bw info         :   %d\n", p->spectral_bwinfo);
    qdf_nofl_info("timestamp       :   %d\n", p->spectral_tstamp);
    qdf_nofl_info("max index       :   %d\n", p->spectral_max_index);
    qdf_nofl_info("max exp         :   %d\n", p->spectral_max_exp);
    qdf_nofl_info("max mag         :   %d\n", p->spectral_max_mag);
    qdf_nofl_info("last timstamp   :   %d\n", p->spectral_last_tstamp);
    qdf_nofl_info("upper max idx   :   %d\n", p->spectral_upper_max_index);
    qdf_nofl_info("lower max idx   :   %d\n", p->spectral_lower_max_index);
    qdf_nofl_info("bin power count :   %d\n", p->bin_pwr_count);
    line();
    qdf_nofl_info("Classifier info\n");
    line();
    qdf_nofl_info("20/40 Mode      :   %d\n", pc->spectral_20_40_mode);
    qdf_nofl_info("dc index        :   %d\n", pc->spectral_dc_index);
    qdf_nofl_info("dc in MHz       :   %d\n", pc->spectral_dc_in_mhz);
    qdf_nofl_info("upper channel   :   %d\n", pc->upper_chan_in_mhz);
    qdf_nofl_info("lower channel   :   %d\n", pc->lower_chan_in_mhz);
    line();
    qdf_nofl_info("Interference info\n");
    line();
    qdf_nofl_info("inter count     :   %d\n", pi->count);

    for (i = 0; i < pi->count; i++) {
        qdf_nofl_info("inter type  :   %d\n", pi->interf[i].interf_type);
        qdf_nofl_info("min freq    :   %d\n", pi->interf[i].interf_min_freq);
        qdf_nofl_info("max freq    :   %d\n", pi->interf[i].interf_max_freq);
    }


}

/*
 * Function     : get_offset_swar_sec80
 * Description  : Get offset for SWAR according to the channel width
 * Input        : Channel width
 * Output       : Offset for SWAR algorithm
 */
uint32_t get_offset_swar_sec80(uint32_t channel_width)
{
    uint32_t offset = 0;
    switch (channel_width)
    {
        case IEEE80211_CWM_WIDTH20:
            offset = OFFSET_CH_WIDTH_20;
            break;
        case IEEE80211_CWM_WIDTH40:
            offset = OFFSET_CH_WIDTH_40;
            break;
        case IEEE80211_CWM_WIDTH80:
            offset = OFFSET_CH_WIDTH_80;
            break;
        case IEEE80211_CWM_WIDTH160:
            offset = OFFSET_CH_WIDTH_160;
            break;
        default:
            offset = OFFSET_CH_WIDTH_80;
            break;
    }
    return offset;
}

#endif  /* WLAN_SPECTRAL_ENABLE */
