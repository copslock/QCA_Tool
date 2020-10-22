
#ifndef RPP_DATAPARSING_H_
#define RPP_DATAPARSING_H_

#include "rpp_message.h"
#include "rpp_header.h"

//Support for 200 per radio, 240 per nic
#define RPP_MAX_STA_PER_RADIO   200
#define RPP_MAX_STA_SUPPORTED   246
#define RPP_ADD_STA_CMD         1
#define RPP_DEL_STA_CMD         0

#define RPP_MAX_SPATIAL_STREAMS 8
#define RPP_MAX_NEIGHBOR_AP_NUM 6
#define VHTMCS_RESERVED_FIELDS  0xFFFF0000
#define HE_MCS_TX_POSN          0x03F
#define HE_MCS_RX_POSN          0xFC0
#define HT_MCS_START_INDEX      128
#define HT_MCS_COUNT            8
#define HT_MAX_SMA_SUPPORT      4

typedef struct {
    int16_t totalCount;
    int16_t activeCount;
    int16_t nextPos;
    int8_t phy[RPP_MAX_STA_SUPPORTED];
    int16_t staNum[RPP_MAX_STA_SUPPORTED];
    uint32_t staHandle[RPP_MAX_STA_SUPPORTED];
    int8_t staCreateStatus[RPP_MAX_STA_SUPPORTED];
    AddStaReq addStaReq[RPP_MAX_STA_SUPPORTED];
    EncryptionPersonal  encryptionPersonalTemp;
    EncryptionPersonal  encryptionPersonal[RPP_MAX_STA_SUPPORTED];
    EncryptionWEP  encryptionWepTemp;
    EncryptionWEP  encryptionWep[RPP_MAX_STA_SUPPORTED];
    EncryptionEAP  encryptionEapTemp;
    EncryptionEAP  encryptionEap[RPP_MAX_STA_SUPPORTED];
    apMacAddData*  targetAPList[RPP_MAX_STA_SUPPORTED];
} __attribute__((packed)) RppStaHandleStruct;

extern gSphyBandInfo gSphyBandData[RPP_NUM_OF_RADIO];

void rpp_stahandle_init(void);

int32_t rpp_stahandle_process(uint32_t staHandle, uint8_t phy, uint8_t command,
        uint8_t *staNum, AddStaReq *addStaReq);

int32_t rpp_fetch_string_output_from_cmd(char *cmdInput, char *cmdOutput,
        int32_t cmdOutputSize, char *debugStr);

int32_t rpp_set_supported_htmcs(uint16_t htmcsVal, uint8_t nssCount, int32_t *computedHtmcsVal);

int32_t rpp_compute_supportedrates(uint16_t supportedRateGet, float *supportedRateToSet);

int32_t rpp_set_supported_mcs(uint16_t mcsVal, uint8_t nssCount, int8_t protocolMode, int32_t *computedRxmcsVal,int32_t *computedTxmcsVal,int8_t *txFixedMcs);

int32_t gen_fixed_rate_param(uint8_t preambleType, uint8_t nssVal, uint16_t mcsVal, int32_t *fixedRateVal);

uint8_t rpp_get_ap_count(const char * msg);

uint8_t rpp_parser_ap_list(char * msg , ScanInfo * info );

ScanInfo * rpp_ap_list_builder( int32_t * totalAp );

int32_t rpp_parse_neighbor_report(char * buf, NeighborReportStats *NRRStats, uint8_t nbrOfAPInList);
#endif /* RPP_DATAPARSING_H_ */
