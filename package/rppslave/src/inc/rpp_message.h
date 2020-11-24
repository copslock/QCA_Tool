#ifndef _RPP_MESSAGE_H_
#define _RPP_MESSAGE_H_

#include "spirent.h"
#include "rpp_header.h"

#define ENABLE_STATS_FROM_ETHTOOL_LIB  1
#define RPP_NUM_OF_NSS 8
#define RPP_NUM_OF_BW 4
#define RPP_NUM_OF_GI 4
#define RPP_NUM_OF_MCS 12

#if ENABLE_STATS_FROM_ETHTOOL_LIB
#include <stddef.h>

#define ETHTOOL_GSTATS          0x0000001d /* get NIC-specific statistics */
#define ETHTOOL_GET_DUMP_DATA   0x00000040 /* Get dump data */
#define ETHTOOL_GSSET_INFO      0x00000037
#define ETHTOOL_GDRVINFO        0x00000003
#define SIOCETHTOOL             0x8946
#define ETHTOOL_FWVERS_LEN      32
#define ETHTOOL_BUSINFO_LEN     32
#endif

#define DP_PEER_STATS_NUM_MCS_COUNTERS        12
#define DP_PEER_STATS_NUM_GI_COUNTERS          4
#define DP_PEER_STATS_NUM_BW_COUNTERS          4
#define DP_PEER_STATS_NUM_SPATIAL_STREAMS      8

#define radios 4
#define HE_MCS_ID_MAX 12
#define PINE_HE_MCS_ID_MAX 14

#if ENABLE_STATS_FROM_ETHTOOL_LIB
enum ethtool_stringset {
    ETH_SS_TEST       = 0,
    ETH_SS_STATS,
    ETH_SS_PRIV_FLAGS,
    ETH_SS_NTUPLE_FILTERS,
    ETH_SS_FEATURES,
};

/* Context for sub-commands */
struct cmd_context {
    int32_t fd;             /* socket suitable for ethtool ioctl */
    struct ifreq ifr;       /* ifreq suitable for ethtool ioctl */
};

struct ethtool_stats {
    uint32_t   cmd;
    uint32_t   n_stats;
    uint64_t   data[0];
};

struct ethtool_dump {
	uint32_t	cmd;
	uint32_t	version;
	uint32_t	flag;
	uint32_t	len;
	uint8_t	    	data[0];
};

struct ethtool_sset_info {
    uint32_t   cmd;
    uint32_t   reserved;
    uint64_t   sset_mask;
    uint32_t   data[0];
};

struct ethtool_drvinfo {
    uint32_t   cmd;
    char    driver[32];
    char    version[32];
    char    fw_version[ETHTOOL_FWVERS_LEN];
    char    bus_info[ETHTOOL_BUSINFO_LEN];
    char    reserved1[32];
    char    reserved2[12];
    uint32_t   n_priv_flags;
    uint32_t   n_stats;
    uint32_t   testinfo_len;
    uint32_t   eedump_len;
    uint32_t   regdump_len;
};
#endif

typedef struct {
    uint8_t     cat;
    uint8_t     type;
    uint32_t    len;
    uint8_t     body[0];

} __attribute__((packed)) RppMessageHead;

typedef struct {
    uint32_t handle;
    uint32_t hwver;
    uint32_t swver;

} __attribute__((packed)) ProbeResp;

typedef struct {
    uint32_t handle;
    uint8_t supportedbands;
    uint16_t htcap[radios];
    uint32_t vhtcap[radios];
    uint64_t hemaccap[radios];
    uint64_t hephycaplow[radios];
    uint64_t hephycaphigh[radios];
    uint8_t maxnss;
    uint32_t maxsta;
} __attribute__((packed)) PhyIntfDesc;

typedef struct {
    uint32_t errcode;
    uint32_t nbrofphys;
    uint8_t phys[0];
} __attribute__((packed)) GetPhyResp;

typedef struct SetPhyReq {
    uint32_t handle;
    uint8_t regulatory[2];
    uint32_t freqband;
    uint8_t cfgnss;
    uint16_t supportedrates;
    uint16_t supportedhtmcsset;
    uint16_t supportedvhtmcsset;
    uint16_t supportedhemcsset;
    uint32_t amsdudepth;
    uint32_t ampdudepth;
    uint32_t txpowerattnueation;
    uint8_t txmcsmap;
    uint8_t rxmcsmap;
    uint32_t heflags;
    uint8_t hebsscolor;
    uint8_t hefrag;
    uint32_t flags;
    uint32_t noisegeneratorchannel;
    int8_t ftRoamThreshold;
    int8_t scanThreshold;
} __attribute__((packed)) SetPhyReq;

typedef struct {
    uint32_t errcode;
} __attribute__((packed)) SetPhyResp;

typedef struct {
    uint8_t enable;
    uint8_t overds;
    uint32_t nbroftargets;
    uint32_t targetsoffset;
} __attribute__((packed)) FastBssTransit;

enum PMFOption {
    PMF_DISABLED   = 0,
    PMF_OPTIONAL,
    PMF_REQUIRED,
    PMF_INVALID = 0xFF
};

typedef struct {
    uint8_t passphrase[64];

} __attribute__((packed)) EncryptionPersonal;

typedef struct {
    uint32_t format;
    uint8_t key[64];

} __attribute__((packed)) EncryptionWEP;

typedef struct {
    char peeridentity[64];
    char password[64];
    char cacertfilename[64];
    char privkeyfilename[64];
    char certfilename[64];

} __attribute__((packed)) EapTls;

typedef struct {
    uint32_t phase2Type;
    char peeridentity[64];
    char anonymousidentity[64];
    char password[64];
    char cacertfilename[64];
    char phase2_cacertfilename[64];
    char phase2_certfilename[64];
    char phase2_privkeyfilename[64];
    char phase2_privkeypassphrase[64];

} __attribute__((packed)) EapTtls;

typedef struct {
    uint32_t phase2Type;
    char peeridentity[64];
    char anonymousidentity[64];
    char password[64];
    char cacertfilename[64];
    char phase2_cacertfilename[64];
    char phase2_certfilename[64];
    char phase2_privkeyfilename[64];
    char phase2_privkeypassphrase[64];

} __attribute__((packed)) EapPeap;

enum EAP_AKA_SUBTYPE {
    EAP_AKA_SUBTYPE_AKA = 0,
    EAP_AKA_SUBTYPE_SIM,
    EAP_AKA_SUBTYPE_AKA_PRIME
};

typedef struct {
    uint8_t subtype;
    char identity[64];
    char password[128];

} __attribute__((packed)) EapAka;

typedef struct {
    uint32_t type;
    union {
        EapTls tls;
        EapTtls ttls;
        EapPeap peap;
        EapAka  aka;
    } u;

} __attribute__((packed)) EncryptionEAP;


typedef struct {
    uint32_t type;
    uint32_t cfglen;
    uint32_t cfgoffset;

} __attribute__((packed)) Encryption;

typedef struct {
    uint32_t phyhandle;
    uint8_t mac[6];
    char apssid[64];
    uint8_t apbssid[6];
    uint8_t protocolrate;
    uint32_t gi;
    uint8_t disableht40M;
    uint8_t disablemaxamsdu;
    uint8_t disableldpc;
    uint32_t maxampdusize;
    uint32_t minampdudensity;
    uint32_t vhtmaxampdusize;
    FastBssTransit fbtcfg;
    Encryption encryption;
    uint8_t pmftype;
    uint32_t exdatalen;
    uint8_t exdata[0];

} __attribute__((packed)) AddStaReq;

typedef struct {
    uint32_t stahandle;
    uint32_t errcode;
} __attribute__((packed)) AddStaResp;

typedef struct {
    uint32_t phyhandle;
    uint32_t stahandle;
} __attribute__((packed)) DelStaReq;

typedef struct {
    uint32_t errcode;
} __attribute__((packed)) DelStaResp;

typedef struct {
    uint32_t phyhandle;
    uint32_t duration;
} __attribute__((packed)) ScanReq;

typedef struct {
    uint8_t ssid[33];
    uint8_t ssidlen;
    uint8_t bssid[6];
    int8_t rssi;
    uint8_t htcap;
    uint8_t vhtcap;
    uint8_t hecap;
    uint32_t freq;
    uint32_t maxphyrate;
    uint32_t chnbw;
    uint8_t sgi;
    uint32_t enctype;
    char encinfo[32];
    uint8_t manufacturer[32];
    uint8_t modelname[32];
} __attribute__((packed)) ScanInfo;

typedef struct {
    uint32_t errcode;
    uint32_t nbrofresults;

    /* New code added */
    uint8_t more;

    ScanInfo results[0];
} __attribute__((packed)) ScanResp;

typedef struct {
    uint32_t phyhandle;
    uint32_t stahandle;
} __attribute__((packed)) AssocReq;

typedef struct {
    uint32_t errcode;
} __attribute__((packed)) AssocResp;

typedef struct {
    uint32_t phyhandle;
    uint32_t stahandle;
} __attribute__((packed)) DeAssocReq;

typedef struct {
    uint32_t errcode;
} __attribute__((packed)) DeAssocResp;

typedef struct {
    uint32_t phyhandle;
    uint32_t stahandle;
    uint8_t targetap[6];

} __attribute__((packed)) FBTReq;

typedef struct {
    uint32_t errcode;
} __attribute__((packed)) FBTResp;

typedef struct {
    uint32_t phyhandle;
    uint32_t mode;
    uint32_t bw;
    uint32_t ctl_freq;
    uint32_t center_freq1;
    uint32_t center_freq2;
    uint32_t buffaction;
    uint32_t capfilterlen;
    char capfilter[0];
} __attribute__((packed)) SetModeReq;

typedef struct {
    uint32_t errcode;
} __attribute__((packed)) SetModeResp;

typedef struct {
    uint32_t phyhandle;
    uint32_t stahandle;
} __attribute__((packed)) GetStatsReq;

typedef struct {
    uint32_t wlanmode;
    uint32_t mimomode;
    uint8_t rxnss;
    uint8_t txnss;
    uint32_t freqband;
    uint32_t chnbw;
    uint8_t txmcsindex;
    uint8_t rxmcsindex;
    uint32_t ctlfreq;
    uint8_t stastate;
    uint8_t bssid[6];
    int8_t rssi;
    int8_t noisefloor;
    uint32_t rxgi;
    uint32_t txgi;
    uint32_t sectype;
    uint32_t sumumode;
    uint8_t groupid;
    uint8_t wmmstate;
    uint8_t mfpstatus;
    uint8_t tdlspeerstatus;
    uint64_t maxrxphyrate;
    uint64_t rxpkts;
    uint64_t rxbytes;
    uint64_t maxtxphyrate;
    uint64_t txpkts;
    uint64_t txbytes;
    uint64_t ftdelay;
    uint64_t ftmindelay;
    uint64_t ftmaxdelay;
    uint64_t ftavedelay;
    uint64_t ftsuccess;
    uint64_t ftfail;
    uint8_t rxofdmamode;// 0: non-ofdma mode, 1: ofdma mode
    uint8_t txofdmamode;// 0: non-ofdma mode, 1: ofdma mode

    uint8_t rxrutype;
    int16_t rxruassignmentindex;
    uint8_t rxloruindex;
    uint8_t rxhiruindex;
    uint64_t rxofdmapkt;

    uint8_t txrutype;
    int16_t txruassignmentindex;
    uint8_t txloruindex;
    uint8_t txhiruindex;
    uint64_t txofdmapkt;
    // per stream rssi
    int8_t ps_rssi[RPP_NUM_OF_BW][RPP_NUM_OF_NSS]; // [CHW20~CHW160][NSS1~NSS8]
    // per nss tx/rx counter
    uint64_t ps_txpkts[RPP_NUM_OF_NSS]; // NSS1 ~ NSS8
    uint64_t ps_rxpkts[RPP_NUM_OF_NSS];
    // per chw tx/rx counter
    uint64_t pcw_txpkts[RPP_NUM_OF_BW]; //0: 20Mhz; 1:40Mhz, 2:80Mhz, 3:80+80/160Mhz
    uint64_t pcw_rxpkts[RPP_NUM_OF_BW]; //0: 20Mhz; 1:40Mhz, 2:80Mhz, 3:80+80/160Mhz

    // per mcstype tx/rx counter
    uint64_t pmcs_txpkts[RPP_NUM_OF_MCS]; //MCS0 ~ MSC11
    uint64_t pmcs_rxpkts[RPP_NUM_OF_MCS]; //MCS0 ~ MCS11

    // per mcstype tx/rx su-mimo counter
    uint64_t pmcs_txsupkts[RPP_NUM_OF_MCS]; //MCS0 ~ MSC11
    uint64_t pmcs_rxsupkts[RPP_NUM_OF_MCS]; //MCS0 ~ MCS11

    // per mcstype tx/rx mu-mimo counter
    uint64_t pmcs_txmupkts[RPP_NUM_OF_MCS]; //MCS0 ~ MSC11
    uint64_t pmcs_rxmupkts[RPP_NUM_OF_MCS]; //MCS0 ~ MCS11

    // per GUI tx/rx couter
    uint64_t pgi_txpkts[RPP_NUM_OF_GI]; //0: 400ns; 1: 800ns; 2: 1600ns; 3: 3200ns [400ns~3200ns][MCS0~MCS11]
    uint64_t pgi_rxpkts[RPP_NUM_OF_GI][RPP_NUM_OF_MCS]; //0: 400ns; 1: 800ns; 2: 1600ns; 3: 3200ns [400ns~3200ns][MCS0~MCS11]
    uint32_t  bsscolorcollisioncounter;
    uint8_t  bsscolorcode;
    uint8_t txppdutype;
    uint8_t rxppdutype;
    uint32_t btm_query_counter;
    uint32_t btm_request_counter;
    uint32_t btm_resp_accept_counter;
    uint32_t btm_resp_denial_counter;
} __attribute__((packed)) StaStats;

typedef struct {
    uint32_t errcode;
    uint32_t nbrofstats;
    StaStats stats[0];
} __attribute__((packed)) GetStatsResp;

typedef struct {
    uint32_t phyhandle;
    uint32_t stahandle;
    StaStats stat;
} __attribute__((packed)) StatsUpdate;

typedef struct {
    uint32_t nbrofstats;
    StatsUpdate stats[0];
} __attribute__((packed)) StatsBulkUpdate;

typedef struct {
    uint32_t phyhandle;
    uint32_t stahandle;
} __attribute__((packed)) ClearStatsReq;

typedef struct {
    uint32_t errcode;
} __attribute__((packed)) ClearStatsResp;

typedef struct {
    uint32_t severity;
} __attribute__((packed)) SetLogLevelReq;

typedef struct {
    uint32_t errcode;
} __attribute__((packed)) SetLogLevelResp;

typedef struct {
    uint32_t phyhandle;
    uint32_t stahandle;
    uint32_t state;
    uint8_t bssid[6];
    uint32_t errcode;
} __attribute__((packed)) AssocStateNtfy;

typedef struct {
    uint32_t severity;
    uint8_t message[256];
} __attribute__((packed)) LogReport;

typedef struct {
    uint8_t dummy;
} __attribute__((packed)) KeepAlive;

enum CaptureControlCmd {
    CMD_START = 0,
    CMD_STOP,
    CMD_RETRIEVE
};

enum CapHandleType {
    CAP_HND_REGULAR = 0,
    CAP_HND_SDR
};

enum CaptureControlErrCode {
    CAP_MODE_SUCCESS = 0,
    CAP_MODE_INVALID_PHY,
    CAP_MODE_FAILED,
    CAP_MODE_UNDEFINED_ERROR
};

enum CaptureProcStatus {
   CAP_PROCCESS_STARTED = 0,
   CAP_PROCCESS_STOPPED,
   CAP_PROCCESS_RETRIEVED
};

typedef struct {
    uint32_t phyhandle;
    enum CaptureControlCmd cmd;
    enum CapHandleType caphnd;
    uint32_t CapFilterLen;// capture filter string length, used for CAP_HND_SDR
    char CapFilter[0];
} __attribute__((packed)) CaptureControlReq;

typedef struct {
    uint32_t errcode;
    uint32_t pktcount;
    uint16_t streamcrvport;
}__attribute__((packed)) CaptureControlResp;

typedef struct {
    uint32_t txframeusec;
    uint32_t rxframeusec;
    uint32_t rxclearusec;
    uint32_t myrxframeusec;
    uint32_t useccnt;
    uint32_t medrxidleusec;
    uint32_t medtxidleglobalusec;
    uint32_t ccaobssusec;
} __attribute__((packed)) PhyCcaCounters;

typedef struct {
    uint32_t numseconds;
    PhyCcaCounters counters[WAL_CCA_CNTR_HIST_LEN];
} __attribute__((packed)) PhyCcaStats;

typedef struct  {
    uint32_t phyhandle;
    PhyCcaStats stat;
} __attribute__((packed)) PhyCcaStatsUpdate;

typedef struct {
      char apssid[64];
      uint8_t apbssid[6];
      int8_t rssi;
} __attribute__((packed)) NeighborReport; 

typedef struct {
    uint32_t phyhandle;
    uint32_t stahandle;
    uint32_t nbrofneighboraps; /*if this is 0, there could be possibility neighbor report not generated or not processed.*/
    NeighborReport roamingaps[0];
} __attribute__((packed)) NeighborReportStats;

#define RPP_MSG_REQ     1
#define RPP_MSG_RESP    2
#define RPPMSG_HDR_SIZE sizeof(RppMessageHead)
#define CAL_MSGSZ(a) (RPPMSG_HDR_SIZE + sizeof(a))
#define RPPMSG_PROB_REQ_SZ (RPPMSG_HDR_SIZE)
#define RPPMSG_PROB_RESP_SZ CAL_MSGSZ(ProbeResp)
#define RPPMSG_GETPHY_REQ_SZ (RPPMSG_HDR_SIZE)
#define RPPMSG_GETPHY_RESP_SZ CAL_MSGSZ(GetPhyResp)
#define RPPMSG_SETPHY_REQ_SZ CAL_MSGSZ(SetPhyReq)
#define RPPMSG_SETPHY_RESP_SZ CAL_MSGSZ(SetPhyResp)
#define RPPMSG_ADDSTA_REQ_SZ CAL_MSGSZ(AddStaReq)
#define RPPMSG_ADDSTA_RESP_SZ CAL_MSGSZ(AddStaResp)
#define RPPMSG_DELSTA_REQ_SZ CAL_MSGSZ(DelStaReq)
#define RPPMSG_DELSTA_RESP_SZ CAL_MSGSZ(DelStaResp)
#define RPPMSG_SCAN_REQ_SZ CAL_MSGSZ(ScanReq)
#define RPPMSG_ASSOC_REQ_SZ CAL_MSGSZ(AssocReq)
#define RPPMSG_ASSOC_RESP_SZ CAL_MSGSZ(AssocResp)
#define RPPMSG_DEASSOC_REQ_SZ CAL_MSGSZ(DeAssocReq)
#define RPPMSG_DEASSOC_RESP_SZ CAL_MSGSZ(DeAssocResp)
#define RPPMSG_FBT_REQ_SZ CAL_MSGSZ(FBTReq)
#define RPPMSG_FBT_RESP_SZ CAL_MSGSZ(FBTResp)
#define RPPMSG_SETMODE_REQ_SZ CAL_MSGSZ(SetModeReq)
#define RPPMSG_SETMODE_RESP_SZ CAL_MSGSZ(SetModeResp)
#define RPPMSG_ASSOCNTF_REQ_SZ CAL_MSGSZ(AssocStateNtfy)
#define RPPMSG_GETSTAT_REQ_SZ CAL_MSGSZ(GetStatsReq)
#define RPPMSG_GETSTAT_RESP_SZ CAL_MSGSZ(GetStatsResp)
#define RPPMSG_CLRSTAT_REQ_SZ CAL_MSGSZ(ClearStatsReq)
#define RPPMSG_CLRSTAT_RESP_SZ CAL_MSGSZ(ClearStatsResp)
#define RPPMSG_SETLOG_REQ_SZ CAL_MSGSZ(SetLogLevelReq)
#define RPPMSG_SETLOG_RESP_SZ CAL_MSGSZ(SetLogLevelResp)
#define RPPMSG_LOGGER_SZ CAL_MSGSZ(LogReport)
#define RPPMSG_KEEPALIVE_REQ_SZ CAL_MSGSZ(KeepAlive)
#define RPPMSG_CAPTURE_REQ_SZ CAL_MSGSZ(CaptureControlReq)
#define RPPMSG_CAPTURE_RESP_SZ CAL_MSGSZ(CaptureControlResp)
#define RPPMSG_STATS_BULK_UPDATE_RESP_SZ CAL_MSGSZ(StatsBulkUpdate)
#define RPPMSG_CCA_STATS_SZ CAL_MSGSZ(PhyCcaStatsUpdate)
#define RPPMSG_NEIGHBOR_REPORT_STATS_REQ_SZ CAL_MSGSZ(NeighborReportStats)

enum {
    RPP_MSG_PROB_REQ = 1,
    RPP_MSG_PROB_RESP,
    RPP_MSG_GETPHY_REQ,
    RPP_MSG_GETPHY_RESP,
    RPP_MSG_SETPHY_REQ,
    RPP_MSG_SETPHY_RESP,
    RPP_MSG_ADDSTA_REQ,
    RPP_MSG_ADDSTA_RESP,
    RPP_MSG_DELSTA_REQ,
    RPP_MSG_DELSTA_RESP,
    RPP_MSG_SCAN_REQ,
    RPP_MSG_SCAN_RESP,
    RPP_MSG_ASSOC_REQ,
    RPP_MSG_ASSOC_RESP,
    RPP_MSG_DEASSOC_REQ,
    RPP_MSG_DEASSOC_RESP,
    RPP_MSG_FBT_REQ,
    RPP_MSG_FBT_RESP,
    RPP_MSG_SETMODE_REQ,
    RPP_MSG_SETMODE_RESP,
    RPP_MSG_ASSOCSTATE_NOTF,
    RPP_MSG_GETSTATS_REQ,
    RPP_MSG_GETSTATS_RESP,
    RPP_MSG_CLRSTATS_REQ,
    RPP_MSG_CLRSTATS_RESP,
    RPP_MSG_SETLOG_REQ,
    RPP_MSG_SETLOG_RESP,
    RPP_MSG_LOGGER_REQ,
    RPP_MSG_KEEPALIVE,
    RPP_MSG_CAPCTRL_REQ,
    RPP_MSG_CAPCTRL_RESP,
    RPP_MSG_REBOOT,
    RPP_MSG_STATS_UPDATE,
    RPP_MSG_NEIGHBOR_REPORT_STATS_UPDATE,
    RPP_MSG_CCA_STATS_UPDATE=148,
    RPP_MSG_MAX_REQ
};

/* Phy Interface description */
enum PhyFreqBand {
    FREQBAND_2_4_GHz = 0,
    FREQBAND_5_0_GHz,
    FREQBAND_5_0_GHz_2,
    FREQBAND_60_GHz,
#ifdef RDP419
    FREQBAND_6_0_GHz
#endif
};

enum GetPhyErrCode{
    GET_PHY_SUCCESS = 0,
    GET_PHY_NOT_FOUND,
    GET_PHY_NOT_READY,
    GET_PHY_OTHERS
};

enum FreqBand {
    FREQ_BAND_AUTO = 0, 
    FREQ_BAND_2_4_GHZ,
    FREQ_BAND_5_0_GHZ,
    FREQ_BAND_6_0_GHZ
};

enum PhyIntfCfgReqErrorCode {
    PHY_INTF_CFG_SUCCESS = 0,
    PHY_INTF_CFG_INVALID_PHY_HANDLE,
    PHY_INTF_CFG_REGULATORY_NOT_SUPPORTED,
    PHY_INTF_CFG_FREQUENCY_NOT_SUPPORTED,
    PHY_INTF_CFG_SPATIAL_STREAM_NOT_SUPPORTED,
    PHY_INTF_CFG_RATE_SETTING_NOT_SUPPORTED,
    PHY_INTF_CFG_HTMCS_SETTING_NOT_SUPPORTED,
    PHY_INTF_CFG_VHTMCS_SETTING_NOT_SUPPORTED,
    PHY_INTF_CFG_AMSDU_DEPTH_NOT_SUPPORTED,
    PHY_INTF_CFG_AMPDU_DEPTH_NOT_SUPPORTED,
    PHY_INTF_CFG_UNDEFINED_ERROR
};

enum EncryptionType {
    OPEN,
    PERSONAL,
    ENTERPRISE,
    WEP,
    ENHANCED_OPEN,
    WPA3_PERSONAL,
    WPA2_WPA3_PERSONAL,
    WPA3_ENTERPRISE,
    ENCTYPE_INVALID = 0xFF
};

enum EapAuthType{
    EAP_TLS,
    EAP_TTLS,
    EAP_PEAP,
    EAP_AKA
} ;

enum EapPhase2AuthType{
    MD5,
    MSCHAP,
    MSCHAPV2,
    PAP,
    CHAP,
    GTC,
    TLS
} ;

enum WepKeyFormat{
    WEP_KEY_HEX,
    WEP_KEY_ASCII
} ;

enum ProtocolRate {
    PROTO_A = 1,
    PROTO_B,
    PROTO_G,
    PROTO_N,
    PROTO_AC,
    PROTO_AX,
    PROTO_AUTO = PROTO_AX
};

enum GIMode {
    GIMODE_LONG = 1,
    GIMODE_SHORT,
    GIMODE_DLONG
} ;

enum MaxAMPDUSize {
    MAX_AMPDU_8K,
    MAX_AMPDU_16K,
    MAX_AMPDU_32K,
    MAX_AMPDU_64K
};

enum MinAMPDUDensity {
    DENSITY_NONE,
    DENSITY_0_25_US,
    DENSITY_0_50_US,
    DENSITY_1_US,
    DENSITY_2_US,
    DENSITY_4_US,
    DENSITY_8_US,
};

enum VhtMaxAMPDUSize {
    VHT_MAX_AMPDU_8K,
    VHT_MAX_AMPDU_16K,
    VHT_MAX_AMPDU_32K,
    VHT_MAX_AMPDU_64K,
    VHT_MAX_AMPDU_128K,
    VHT_MAX_AMPDU_256K,
    VHT_MAX_AMPDU_512K,
    VHT_MAX_AMPDU_1024K
};

enum PerStreamSupportedVHTMCSSet {
    VHTMCS_PER_STREAM_0_7,
    VHTMCS_PER_STREAM_0_8,
    VHTMCS_PER_STREAM_0_9,
    VHTMCS_PER_STREAM_NONE
};

enum PerStreamSupportedHEMCSSet {
    HEMCS_PER_STREAM_0_7,
    HEMCS_PER_STREAM_0_9,
    HEMCS_PER_STREAM_0_11,
    HEMCS_PER_STREAM_NONE
};

enum SupportedHETxMCSSet {
    HEMCS_NONE = 0,
    HEMCS_0_7  = 7,
    HEMCS_0_8  = 8,
    HEMCS_0_9  = 9,
    HEMCS_0_11 = 11,
    HE_TX_TYPE_0,
    HE_TX_TYPE_11 = 23 
};

enum SupportedHERxMCSSet {
    HERxMCS_NONE = 0x20,
    HERxMCS_0_7  = 0x80,
    HERxMCS_0_8  = 0x100,
    HERxMCS_0_9  = 0x200,
    HERxMCS_0_11  = 0x800
};

enum StaCreateState {
    STA_NOT_CREATED = 0,
    STA_ACTIVE,
    STA_DORMANT
};

enum StaHandleCase {
    HANDLE_STA_DUPLICATE = 0,
    HANDLE_STA_NEW,
    HANDLE_STA_COUNT_EXHAUST
};

enum AddStationRespErrorCode {
    ADD_STATION_SUCCESS = 0,
    ADD_STATION_INVALID_PHY_HANDLE,
    ADD_STATION_INVALID_MAC,
    ADD_STATION_INVALID_SSID,
    ADD_STATION_INVALID_BSSID,
    ADD_STATION_INVALID_EXTRA_DATA_LEN,
    ADD_STATION_HTMCS_SETTING_NOT_SUPPORTED,
    ADD_STATION_VHTMCS_SETTING_NOT_SUPPORTED,
    ADD_STATION_AMSDU_DEPTH_NOT_SUPPORTED,
    ADD_STATION_AMPDU_DEPTH_NOT_SUPPORTED,
    ADD_STATION_UNDEFINED_ERROR
};

enum DelStationRespErrorCode {
    DELETE_STATION_SUCCESS = 0,
    DELETE_STATION_INVALID_PHY_HANDLE,
    DELETE_STATION_INVALID_HANDLE,
    DELETE_STATION_UNDEFINED_ERROR
};

enum AssocRespErrorCode {
    ASSOCIATE_SUCCESS = 0,
    ASSOCIATE_INVALID_PHY_HANDLE,
    ASSOCIATE_INVALID_HANDLE,
    ASSOCIATE_UNDEFINED_ERROR
};

enum DeAssocRespErrorCode {
    DEASSOCIATE_SUCCESS = 0,
    DEASSOCIATE_INVALID_PHY_HANDLE,
    DEASSOCIATE_INVALID_HANDLE,
    DEASSOCIATE_NOT_ASSOCIATED,
    DEASSOCIATE_UNDEFINED_ERROR
};

enum FastBssTransitRespErrorCode {
    FAST_BSS_TRANSIT_SUCCESS = 0,
    FAST_BSS_TRANSIT_INVALID_PHY_HANDLE,
    FAST_BSS_TRANSIT_INVALID_STA_HANDLE,
    FAST_BSS_TRANSIT_STATION_NOT_ASSOCIATED,
    FAST_BSS_TRANSIT_ASSOCIATED_TO_TARGET_AP,
    FAST_BSS_TRANSIT_INVALID_BSS,
    FAST_BSS_TRANSIT_UNDEFINED_ERROR
};

enum WorkMode {
    STATION_MODE,
    SNIFFER_MODE,
    REGULAR_CAP_MODE
};

enum BufferAction {
    WRAP,
    STOP
};

enum Bandwidth {
    BW_20MHz,
    BW_40MHz,
    BW_80Mhz,
    BW_80P80MHz,
    BW_160MHz
};

enum SetModeRespErrorCode {
    SET_MODE_SUCCESS = 0,
    SET_MODE_INVALID_PHY_HANDLE,
    SET_MODE_CANNOT_CHANGE_TO_SNIFFER_MODE,
    SET_MODE_INVALID_BANDWIDTH,
    SET_MODE_INVALID_CTRL_FREQUENCY,
    SET_MODE_INVALID_CENTER_FREQUENCY_1,
    SET_MODE_INVALID_CENTER_FREQUENCY_2,
    SET_MODE_UNDEFINED_ERROR
};

enum AssocState {
    STATE_ASSOCIATED,
    STATE_ASSOCIATE_FAILED
};

enum AssocStateNotificationErrorCode {
    ASSOC_STATE_NOTIFICATION_SUCCESS = 0,
    ASSOC_STATE_NOTIFICATION_UNKNOWN_ERROR,
    ASSOC_STATE_NOTIFICATION_AP_NOT_FOUND,
    ASSOC_STATE_NOTIFICATION_PASSWORD_INCORRECT,
    ASSOC_STATE_NOTIFICATION_AUTH_FAIL,
    ASSOC_STATE_NOTIFICATION_CONNECT_FAILED,
    ASSOC_STATE_NOTIFICATION_TIMEOUT,
    ASSOC_STATE_NOTIFICATION_FTROAM_TIMEOUT
};

/* Rpp_GetStationStats : This is the request from RppHost to slave application
 * to retrieve station statistics. Host will send this request to slave and
 * waits for response forever.
 */

enum WlanMode {
    MODE_NA,
    MODE_A,
    MODE_B,
    MODE_G,
    MODE_N,
    MODE_AC,
    MODE_AX
};

enum MIMOMode {
    MIMO_NA,
    MIMO_1X1,
    MIMO_2X2,
    MIMO_3X3,
    MIMO_4X4,
    MIMO_5X5,
    MIMO_6X6,
    MIMO_7X7,
    MIMO_8X8
};


enum FrequencyBand {
    FREQBAND_NA,
    FREQBAND_2GHZ,
    FREQBAND_5GHZ
};


enum ChannelBandWidth {
    CBW_NA,
    CBW_20MHz,
    CBW_40MHz,
    CBW_80MHz,
    CBW_80P80Mhz,
    CBW_160MHz
};

enum GuardIntervalMode {
    GI_NA,
    GI_800NS,
    GI_400NS,
    GI_1600NS,
    GI_3200NS
};

enum SecurityType {
    Security_NA,
    Security_OPEN,
    Security_PERSONAL,
    Security_ENTERPRISE,
    Security_OWE,
    Security_WPA3_PERSONAL,
    Security_WPA2_WPA3_PERSONAL,
    Security_WPA3_ENTERPRISE
};

enum SuMuType {
    SUMIMO,
    MUMIMO
};

enum GetStationStatsRespErrorCode {
    GET_STATION_STATE_SUCCESS = 0,
    GET_STATION_STATE_INVALID_PHY_HANDLE,
    GET_STATION_STATE_INVALID_STA_HANDLE,
    GET_STATION_STATE_UNDEFINED_ERROR
};

/* Rpp_ClearStationStats : This is the request from RppHost to FPGA Driver to
 * clear station statistics. Host will send this request to slave and waits for
 * response forever
 */


enum ClearStationStatsRespErrorCode {
    CLEAR_STATION_STATE_SUCCESS = 0,
    CLEAR_STATION_STATE_INVALID_PHY_HANDLE,
    CLEAR_STATION_STATE_INVALID_STA_HANDLE,
    CLEAR_STATION_STATE_UNDEFINED_ERROR
};

/* Rpp_SetLogLevel
 * This is the request from RppHost to slave application to set log severity
 * level for the slave. Any log message which has log severity value higher
 * need to report to RPP host.
 */
enum LogSeverity {
    FATAL,
    ERROR,
    WARN,
    INFO,
    DEBUG
};

enum SetLogLevelRespErrorCode {
    SET_LOG_LEVEL_SUCCESS = 0,
    SET_LOG_LEVEL_UNDEFINED_ERROR
};

enum PPDUType {
    PPDU_SU,
    PPDU_MU_MIMO,
    PPDU_OFDMA,
    PPDU_MU_MIMO_OFDMA
};
;

#endif /* _RPP_MESSAGE_H_ */
