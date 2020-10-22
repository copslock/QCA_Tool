
#ifndef RPP_CORE_H_
#define RPP_CORE_H_

#include "rpp_header.h"
#include "rpp_dataparsing.h"
#include "rpp_util.h"

#define RPP_MSG_CATEGORY_SIZE           1
#define RPP_MSG_TYPE_SIZE               1
#define RPP_MSG_LEN_SIZE                4
#define RPP_MSG_NON_PAYLOAD_SIZE        (RPP_MSG_CATEGORY_SIZE + RPP_MSG_TYPE_SIZE + RPP_MSG_LEN_SIZE)

#define RPP_MAX_RECV_SIZE               8096
#define RPP_APP_BUFF_SIZE               1024

#ifdef THREE_RADIO
#define PHY_HANDLE_5G 0
#define PHY_HANDLE_5G2 1
#define PHY_HANDLE_2G 2
extern uint8_t spirent_to_qcom_map[];
#else
#define PHY_HANDLE_5G 0
#define PHY_HANDLE_2G  1
#endif

#ifdef THREE_RADIO
#define REMAP_PHY_HANDLE(handle)        handle = spirent_to_qcom_map[handle]
#else
#define REMAP_PHY_HANDLE(handle)
#endif

#define RPP_NG_ENABLE(phy)           (phy->noisegeneratorchannel)

/* Rpp message mapping */
typedef struct __attribute__((packed)) {
    uint8_t MessageCat;
    uint8_t MessageType;
    uint32_t MessageLength;
} RppNonPayloadStruct;

typedef struct {
    RppNonPayloadStruct rppNonPayloadStruct;
    int8_t   *messageStruct;
} RppMesgMapToDataStruct;

typedef enum {
    CMD_SET = 0,
    CMD_GET,
    CMD_NONE
}driverCmd;

typedef enum {
    ASSOC_ERROR_MANUALLY_TRIGGERD_DISASSOCIATION =0,
    ASSOC_ERROR_AP_DOWN_AFTER_ASSOCIATION = 3,
    ASSOC_ERROR_OPEN_AP_ENCRYPTED_UI,
    ASSOC_ERROR_ENCRYPTED_AP_OPEN_UI,
    ASSOC_ERROR_ENCRYPTION_TYPE_MISMATCH,
    ASSOC_ERROR_AP_DOWN_BEFORE_ASSOCIATION,
    ASSOC_ERROR_INCORRECT_PASSWORD = 9,
    ASSOC_ERROR_AUTHENTICATION_FAILURE = 23
}eAssocErrorCodeDriver;

typedef struct {
    int32_t staCount;
    struct staInfo {
        int32_t staHandle;
        int32_t phyHandle;
        int32_t staNum;
        uint8_t staStatus;
        uint8_t assocReqStatus;
        uint8_t assocStatus;
        uint8_t deassocnotify;
        uint8_t apbssid[ETHER_MAC_ADDR_LEN];
        bool is11kNRRtriggered;
        bool is11vBTMtriggered;
        bool staRoamTrigger;
        uint8_t staRoamTrialCount;
        uint8_t targetApbssid[ETHER_MAC_ADDR_LEN];
        uint8_t preambleType;
    }staCountInfo[RPP_MAX_STA_SUPPORTED];
    uint32_t associated_stations_per_radio;
    uint32_t pendingMsg;
    pthread_mutex_t wpaCtrlLock;
    /* Separate wpa_ctrl interface for monitor and msg parser thread 
    to avoid acquire lock while using it */
    struct wpa_ctrl *monIntf;
    struct wpa_ctrl *msgParserIntf;
}staAssocInfo;

int system_cmd (char * cmdin);
//Separate station monitor thread per radio
pthread_t   staMonThreadId[RPP_NUM_OF_RADIO];

void *thread_staMonRadio(void *p_threadData);

pthread_t   staStatsThreadId;

void *thread_get_stats(void *p_threadData);

pthread_t   keepAliveThread;

void *thread_rpp_sendKeepAlive(void *p_threadData);

int32_t rpp_slave_probe_req(void);

int32_t rpp_get_phy_req (void);

int32_t rpp_set_phy_req (int8_t *buf);

int32_t rpp_add_station_req (int8_t *buf);

int32_t rpp_delete_station_req (int8_t *buf);

int32_t rpp_scan_req (int8_t *buf);

int32_t rpp_associate_req (int8_t *buf);

int32_t rpp_deassociate_req (int8_t *buf);

int32_t rpp_send_assocstate(struct staInfo *stainfo, uint32_t associateState, uint32_t errCode);

int32_t rpp_station_stats_get_req (int8_t *buf);

int32_t rpp_fastBss_transit_req (int8_t *buf);

int32_t rpp_setmode_req (int8_t *buf);

int32_t rpp_clear_station_stats_req (int8_t *buf);

int32_t rpp_set_log_level_req (int8_t *buf);

int32_t rpp_send_log_Report_req (int8_t *buf);

int32_t rpp_capturemode_req(int8_t *buf);

int32_t rpp_validate_phyhandle(int32_t phyhandle);

int32_t rpp_session_cleanup();

int32_t rpp_configure_freq_settings(char *infName, int32_t freqValue, uint32_t index,uint32_t phyHandle);

int32_t rpp_get_neighbor_report(uint32_t phyHandle, uint32_t staHandle);

int32_t system_cmd_set_f(const char* format, ...);

int32_t system_cmd_get_f(char *cmdOutput, int32_t sizeCmdOutput, const char *format, ...);
#endif /* RPP_CORE_H_ */
