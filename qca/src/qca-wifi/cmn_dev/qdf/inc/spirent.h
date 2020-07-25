#ifndef _SPIRENT_H_
#define _SPIRENT_H_

#ifndef A_UINT32
typedef unsigned int A_UINT32;
#endif

#define WAL_CCA_CNTR_HIST_LEN                       10
#define MAX_NUM_MACS                                3

typedef struct {
    /* Below values are obtained from the HW Cycles counter registers */
    A_UINT32 tx_frame_usec;
    A_UINT32 rx_frame_usec;
    A_UINT32 rx_clear_usec;
    A_UINT32 my_rx_frame_usec;
    A_UINT32 usec_cnt;
    A_UINT32 med_rx_idle_usec;
    A_UINT32 med_tx_idle_global_usec;
    A_UINT32 cca_obss_usec;
} pdev_stats_cca_counters;

#endif
