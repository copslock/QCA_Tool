#include <stdarg.h>
#include "rpp_core.h"
#include "rpp_ethcomm.h"
#include "rpp_message.h"
#include "rpp_wpactrl_helper.h"
#include <sys/time.h>
#include <stdarg.h>
#include <libgen.h>

#define GET_PHY_APPEND_MAXSTACMD     "iwpriv wifi"
#define GET_PHY_HTCAP                "g_ht_cap |grep \"g_ht_cap\" |cut -d \":\" -f 2"
#define GET_PHY_VHTCAP               "g_vht_cap |grep \"g_vht_cap\" |cut -d \":\" -f 2"
#define GET_PHY_MAXNSS               "get_nss |grep \"get_nss\" | cut -d  \":\" -f 2"
#define GET_PHY_NUM_OF_STA           "g_max_sta |grep \"g_max_sta\" | cut -d  \":\" -f 2"
#define GET_PHY_MODE                 "get_mode |cut -d \":\" -f 2"

#define SET_PHY_APPEND_CMD           "iwpriv ath"
#define SET_PHY_REG_CMD              "iwpriv wifi"
#define SET_PHY_FRQBAND              "freq_band"
#define RPP_STA_ASSOC_STATE         3
#define RPP_ASSOC_TIMEOUT               1 /* 1 -second */

#define RPP_INFNAME_BUFF_SIZE       24
#define RPP_MODE_BUFF_SIZE          12
#define NUMBER_OF_SCAN_RESULT        4
#define RPP_STATS_SLEEP              10*1000 //Changed sleep to 10ms
#define RPP_STATS_TIME              2000 // 2 seconds
#define RPP_KEEPALIVE_TIMER          5
#define RPP_CLEARPROBE_TIMER        25
#define RPP_CLEAR_STATS_REQ         257
#define RPP_DEFAULT_RSSI_VALUE      128
#define RPP_BW_SHIFT_VALUE          3

#define CAPDAEMON_PORT_NUMBER_5G    63560
#define CAPDAEMON_PORT_NUMBER_2G    63561
#define CAPDAEMON_PORT_NUMBER_5G2   63564

#define CAPDAEMON_SDR_PORT_NUMBER_5G    63562
#define CAPDAEMON_SDR_PORT_NUMBER_2G    63563
#define CAPDAEMON_SDR_PORT_NUMBER_5G2   63565

#define RPP_UNSET_ASOCIATE_REQSTATE     0
#define RPP_SET_ASOCIATE_REQSTATE       1

#define RPP_STATE_STATION_NOTPRESENT    0
#define RPP_STATE_STATION_PRESENT       1

#define RPP_DEASSOC_NOTIFY_UNSET        0
#define RPP_DEASSOC_NOTIFY_SET          1

#ifdef RDP419
// RDP419 maximum tx power is 30
#define TX_MAX_POWER    30
#else
#define TX_MAX_POWER    31
#endif
#define PROXY_STA_ASSOCTIME 15

//Increased OWE transition association time
#define PROXY_STA_OWE_TRANS_ASSOCTIME 25

#define ADVANCE_STATS   1   /* Enable advance stats */
#define NOISE_FLOOR   95

#define CMD_SUFIX_LEN 16
#define CMD_LEN 256

#define PHYFLAGS_RTSCTS_SHIFT 7
#define PHYFLAGS_80211K_SHIFT 9
#define PHYFLAGS_80211V_SHIFT 10

#define TEST_BIT(var, shift) ( var & (1 << shift))

#define WNM_REASON_LOW_RSSI		16
#define MAX_FT_ROAM_FAIL_COUNT	5
char *phyMapping_5G[][5] = { {"AUTO", "AUTO", "AUTO", "AUTO", "AUTO"},
                {"11A", "11A", "11A", "11A", "11A"},
                {"AUTO", "AUTO", "AUTO", "AUTO", "AUTO"},
                {"AUTO", "AUTO", "AUTO", "AUTO", "AUTO"},
                {"11NAHT20", "11NAHT40", "11NAHT40", "11NAHT40", "11NAHT40"},
                {"11ACVHT20", "11ACVHT40", "11ACVHT80", "11ACVHT160", "11ACVHT160"},
                {"11AHE20", "11AHE40", "11AHE80", "11AHE80_80", "11AHE160"} };

char *phyMapping_2G[][5] = { {"AUTO", "AUTO", "AUTO", "AUTO", "AUTO"},
                {"AUTO", "AUTO", "AUTO", "AUTO", "AUTO"},
                {"11B", "11B", "11B", "11B", "11B"},
                {"11G", "11G", "11G", "11G", "11G"},
                {"11NGHT20", "11NGHT40", "11NGHT40", "11NGHT40", "11NGHT40"},
                {"AUTO", "AUTO", "AUTO", "AUTO", "AUTO"},
                {"11GHE20", "11GHE40", "11GHE40", "11GHE40", "11GHE40"} };

#ifdef RDP419
#define AUTO_PHY_6G "11AHE160"
char *phyMapping_6G[][5] = { {AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G},
                {AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G},
                {AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G},
                {AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G},
                {AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G},
                {AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G, AUTO_PHY_6G},
                {"11AHE20", "11AHE40", "11AHE80", "11AHE160", "11AHE160"} };
#endif

#define DEFAULT_WIFI_MAC_ID "00:11:12:13:14:15"
const char *gDefAthMac[RPP_NUM_OF_RADIO] = {
                        "00:41:42:43:44:45",
                        "00:51:52:53:54:55",
                        "00:61:62:63:64:65"
};

typedef enum {
    WIFI5G_160MHZ = 0,
    WIFI5G_80MHZ,
    WIFI5G_40MHZ,
    WIFI5G_20MHZ,
    WIFI5G_MAX
}eWifi5GBW;

typedef enum {
    WIFI2_4G_40MHZ = 0,
    WIFI2_4G_20MHZ,
    WIFI2_4G_MAX
}eWifi2_4GBW;

uint32_t wifi5gbw[][30] = {{50, 114}, {42, 58, 106, 122, 138, 155},
                {38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159},
                {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116,
                120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165}};

char wifi5Garrsize[] = {2, 6, 12, 25};

uint32_t wifi2_4gbw[][30] = {{50, 114}, {42, 58, 106, 122, 138, 155},
                {38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159},
                {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116,
                120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165}};

char wifi2_4Garrsize[] = {2, 6, 12, 25};

typedef struct {
    uint8_t TxpowerStatus;
    uint8_t assocStatus;
    uint8_t assocStanum;
} setTxpowerData;
setTxpowerData setTxpowerInfo;

typedef enum {
    RPP_CAPTURE_TYPE_LIVE = 0,
    RPP_CAPTURE_TYPE_OFFLINE
}eCaptureType;

typedef enum {
    RSSI_THRESHOLD_FOR_11K_11V,
    RSSI_THRESHOLD_FOR_11V,
    RSSI_THRESHOLD_FOR_11K
}eRssiThresholdType;

typedef enum {
    FT_ROAM_OVER_AIR,
    FT_ROAM_OVER_DS
}eFTRoamType;

// Initialize wpa_ctrl interface
staAssocInfo staAssocHdl[RPP_NUM_OF_RADIO] = {
                                                {.monIntf=NULL, .msgParserIntf=NULL},
                                                {.monIntf=NULL, .msgParserIntf=NULL},
                                                {.monIntf=NULL, .msgParserIntf=NULL}
};

typedef struct {
    uint32_t total_stations_per_radio;
    uint32_t active_stations_per_radio;
}RppStationPerRadioStruct;
RppStationPerRadioStruct staPerRadioHdl[RPP_NUM_OF_RADIO];

typedef struct {
    char pidVal[15];
} gPidValdata;

typedef struct {
    uint32_t modeVal;
    uint32_t buffflag;
    uint32_t captype;
    uint32_t filterexplen;
    char     *filterexp;
}gsetModeData;
gsetModeData gsetModeInfo[RPP_NUM_OF_RADIO];

typedef struct {
    int32_t rcVal;
    int32_t option;
    char    *buffer;
}sErrCode;
sErrCode errCodeInfo;

SetPhyReq addStaPhyData[RPP_NUM_OF_RADIO];
gPidValdata gPidValInfo[RPP_NUM_OF_RADIO];
gSphyBandInfo gSphyBandData[RPP_NUM_OF_RADIO];

extern RppStaHandleStruct rppStaHandle;
extern char wpaSupplicantEapTls[];
extern char wpaSupplicantEapTtls[];
extern char wpaSupplicantEapPeap[];
extern char wpaSupplicantEapAka[];
extern char wpaSupplicantWep[];
extern char *gnetInfName;
extern bool probeProcess;
extern bool cleanupProcess;
extern bool sendKeepAlive;
extern pthread_mutex_t staProcessLock;
extern pthread_mutex_t assocStatLock[RPP_NUM_OF_RADIO];
extern pthread_mutex_t proxyStateLock[RPP_NUM_OF_RADIO];
bool keepAliveThread_created = false;
int32_t createClientSocket;

char *wlanmode[RPP_APP_DEFNUM_SEVEN] = {"na","a","b","g","n","ac","axa"};
char *capdaemonName = "/usr/bin/monitord";
char *syslogdaemonName = "/sbin/syslogd";

typedef struct {
    int32_t gProcStatus;
    int32_t gProcStatus_SDR;
    int32_t captureMode;
    uint32_t snifferMode_chwidth;
    uint32_t snifferMode_ctl_freq;
    uint32_t snifferMode_center_freq2;
} __attribute__((packed)) RppPhyCaptureStruct;
RppPhyCaptureStruct RppPhyCaptureHdl[RPP_NUM_OF_RADIO];

uint8_t PROXY_STA[RPP_NUM_OF_RADIO];
typedef struct {
    bool proxy_sta_assoc;
    bool reset_assoc_trial_count_flag;
    time_t previous_assoc_req_time;
    uint32_t mpsta_assoc_trial_count;
    uint32_t failed_assoc_sent;
    apMacAddData apMacAddInfo_per_radio;
    proxyStaMacAddData proxyStaMacAddInfo_per_radio;
} __attribute__((packed)) RppProxyStaStatusStruct;

RppProxyStaStatusStruct RppProxyStaStatusHdl[RPP_NUM_OF_RADIO];

unsigned char *gPidValue[RPP_NUM_OF_RADIO] = {
    NULL,
    NULL,
    NULL
};
uint32_t gPhyHandle[RPP_NUM_OF_RADIO];

uint32_t Handle; //This handle is for RPPSlave, 0- 1st slave , 1- 2nd slave and so on
uint32_t hwver;  //This version will be read from FPGA HW Version register
uint32_t swver;  //This version will be read from FPGA IPQ SW Version register
uint32_t packetSent = 0;
int32_t  gTxpowerAttinution;
uint8_t gPMF = PMF_INVALID;
uint8_t gEncType = ENCTYPE_INVALID;
apMacAddData gPrevAPbssid[RPP_MAX_STA_SUPPORTED];

#define MPSTA_ASSOC_MAX_TRIAL   3

#define cat_variable_arg(iwCmd, ap)     \
                                                                                va_start(ap, format); \
                                                                                if (vsnprintf(iwCmd, CMD_LEN , format, ap) < 0) \
                                                                                    return -1; \
                                                                                va_end(ap);
/******************************************************************************
 * Function Name    : spirent_to_qcom_radio_num
 * Description      : This Function is used to map spirent to qualcom radio number
 ******************************************************************************/
uint8_t spirent_to_qcom_radio_num(uint8_t handle)
{
    if (IS_THREE_RADIO_PROFILE) {
        static uint8_t spirent_to_qcom_map[] = {0,2,1};
        return spirent_to_qcom_map[handle];
    }
     // Two radio profile
    return handle;
}

/******************************************************************************
 * Function Name    : system_cmd
 * Description      : This Function is used to execute commands
 ******************************************************************************/
int system_cmd (char * cmdin)
{
    char iwCmd[RPP_APP_BUFF_SIZE+10] = "\0";
    
    sprintf(iwCmd,"%s > /dev/null",cmdin);
    if(system(iwCmd) <  0) {
        SYSLOG_PRINT(LOG_ERR, "Cmd: %s fails\n",iwCmd);
        return -1;
    }
    return 1;
} 
 

int32_t system_cmd_set_f(const char* format, ...)
{
    char iwCmd[CMD_LEN + CMD_SUFIX_LEN] = "\0";
    va_list ap;
    cat_variable_arg(iwCmd, ap);
    SYSLOG_PRINT(LOG_DEBUG, "iwCmd = %s\n",iwCmd);
    return system_cmd(iwCmd);
}

int32_t system_cmd_get_f(char *cmdOutput, int32_t sizeCmdOutput, const char *format,  ...)
{
    char iwCmd[CMD_LEN + CMD_SUFIX_LEN] = "\0";
    va_list ap;

    cat_variable_arg(iwCmd, ap);
    return rpp_fetch_string_output_from_cmd(iwCmd, cmdOutput, sizeCmdOutput, NULL);
}

uint64_t current_timestamp()
{
    struct timeval  tv;
    gettimeofday(&tv, NULL);

    uint64_t time_in_ms = 
         (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000 ; // convert tv_sec & tv_usec to millisecond
    return time_in_ms;
}

/******************************************************************************
 * Function Name    : rpp_map_assoc_sta_errcode
 * Description      : This Function is used to map the assoc failure error code 
                      from driver to error code to be sent to wlanmgr
 ******************************************************************************/
uint8_t rpp_map_assoc_sta_errcode(uint8_t reasonCode)
{
    uint8_t assocStaErrCode = ASSOC_STATE_NOTIFICATION_UNKNOWN_ERROR;

    switch (reasonCode){
        case ASSOC_ERROR_INCORRECT_PASSWORD :
            assocStaErrCode = ASSOC_STATE_NOTIFICATION_PASSWORD_INCORRECT;
            break;
        case ASSOC_ERROR_MANUALLY_TRIGGERD_DISASSOCIATION :
            assocStaErrCode = ASSOC_STATE_NOTIFICATION_SUCCESS;
            break;
        case ASSOC_ERROR_OPEN_AP_ENCRYPTED_UI :
            assocStaErrCode = ASSOC_STATE_NOTIFICATION_AP_NOT_FOUND;
            break;
        case ASSOC_ERROR_ENCRYPTED_AP_OPEN_UI :
            assocStaErrCode = ASSOC_STATE_NOTIFICATION_AP_NOT_FOUND;
            break;
        case ASSOC_ERROR_ENCRYPTION_TYPE_MISMATCH :
            assocStaErrCode = ASSOC_STATE_NOTIFICATION_AP_NOT_FOUND;
            break;
        case ASSOC_ERROR_AP_DOWN_BEFORE_ASSOCIATION :
            assocStaErrCode = ASSOC_STATE_NOTIFICATION_AP_NOT_FOUND;
            break;
        case ASSOC_ERROR_AP_DOWN_AFTER_ASSOCIATION :
            assocStaErrCode = ASSOC_STATE_NOTIFICATION_AP_NOT_FOUND;
            break;
        case ASSOC_ERROR_AUTHENTICATION_FAILURE :
            assocStaErrCode = ASSOC_STATE_NOTIFICATION_AUTH_FAIL;
            break;
        default :
            assocStaErrCode = ASSOC_STATE_NOTIFICATION_UNKNOWN_ERROR;
    }
    SYSLOG_PRINT(LOG_DEBUG, "%s:reasonCode = %d, assocStaErrCode = %d\n", __func__, reasonCode, assocStaErrCode); 
    return assocStaErrCode;
}

/******************************************************************************
 * Function Name    : rpp_delete_station_process
 * Description      : This Function is used to delete the stations.
 ******************************************************************************/
int32_t rpp_delete_station(uint32_t phyhandle, char* intfName, uint8_t staNum)
{
    int32_t    errCode = RPP_APP_RET_SUCCESS;

    if(staPerRadioHdl[phyhandle].active_stations_per_radio == 1)
        system_cmd_set_f("wpa_cli -i %s%u -g/tmp/global%d scan_cache flush", intfName, staNum, phyhandle);
	
    system_cmd_set_f("ifconfig %s%u down", intfName, staNum);
    system_cmd_set_f("wpa_cli -g/tmp/global%d interface_remove %s%u", phyhandle, intfName, staNum);
    system_cmd_set_f("wlanconfig %s%u destroy", intfName, staNum);

    if (strcmp(intfName,"sta") == 0) {
        SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->sta%u going to NOT_CREATED state\n", staNum);
        rppStaHandle.staCreateStatus[staNum] = STA_NOT_CREATED;
        staPerRadioHdl[phyhandle].total_stations_per_radio -= 1;
        staPerRadioHdl[phyhandle].active_stations_per_radio -= 1;
        rppStaHandle.totalCount--;
    }

    return errCode;
}

/******************************************************************************
 * Function Name    : rpp_deactivate_station
 * Description      : This Function is used to deactivate the stations.
 ******************************************************************************/
int32_t rpp_deactivate_station(uint32_t phyhandle, char* intfName, uint8_t staNum)
{
    int32_t    errCode = RPP_APP_RET_SUCCESS;

    if ((rppStaHandle.addStaReq[staNum].fbtcfg.enable) && (rppStaHandle.targetAPList[staNum] != NULL)) {
        free(rppStaHandle.targetAPList[staNum]);
        rppStaHandle.targetAPList[staNum] = NULL;
    }

    system_cmd_set_f("ifconfig %s%u down", intfName, staNum);
    system_cmd_set_f("wpa_cli -g/tmp/global%d interface_remove %s%u", phyhandle, intfName, staNum);

    if (strcmp(intfName,"sta") == 0) {
        SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->sta%u going to DORMANT state\n", staNum);
        rppStaHandle.staCreateStatus[staNum] = STA_DORMANT;
    }

    return errCode;
}

/******************************************************************************
 * Function Name    : rpp_dissociation_process
 * Description      : This Function is used to dissociate the stations.
 ******************************************************************************/
int32_t rpp_dissociation_process(uint32_t phyhandle, char* intfName, uint8_t staNum)
{
    int32_t    errCode = RPP_APP_RET_SUCCESS;
    AddStaReq* staCfg = &rppStaHandle.addStaReq[staNum];
    /* This is handled in the qca driver. Hence Removing the scancache flush */
    //wpa_cli -i staX0 -g /tmp/global0 scan_cache flush
    //system_cmd_set_f("wpa_cli -i %s%u -g /tmp/global%d scan_cache flush", intfName, staNum, phyhandle);
    /* To deassociate the  station */
    system_cmd_set_f("ifconfig %s%u down", intfName, staNum);
    /* As we need to give the hold_bss/ unhold_bss  commands for the target APs and associated AP also..
     * Length of target AP List = number of targets from GUI + 1 (associated AP)
     */
    if ((staCfg->fbtcfg.enable) && (rppStaHandle.targetAPList[staNum] != NULL)) {
        for (uint8_t targetIndex = 0 ; targetIndex <= staCfg->fbtcfg.nbroftargets; targetIndex++) {
            system_cmd_set_f("wpa_cli -i %s%u -g /tmp/global%d unhold_bss %s",
                                                                    intfName, staNum, phyhandle,
                                                                    util_mac_addr_to_str((uint8_t *)&rppStaHandle.targetAPList[staNum][targetIndex]));
        }
    }
    //wpa_cli -i sta0 disable_network 0
    system_cmd_set_f("wpa_cli -i %s%u disable_network 0", intfName, staNum);
    system_cmd_set_f("wpa_cli -i %s%u remove_network 0", intfName, staNum);
    //wpa_cli -g/tmp/global0 interface_remove sta0
    system_cmd_set_f("wpa_cli -g/tmp/global%d interface_remove %s%u", phyhandle, intfName, staNum);

    util_uninstall_certificate(phyhandle);

    if (strcmp(intfName,"sta") == 0) {
        rppStaHandle.staCreateStatus[staNum] = STA_DORMANT;
    }

    return errCode;
}

/******************************************************************************
 * Function Name    : rpp_association_process
 * Description      : This Function is used to associate the stations.
 ******************************************************************************/
int32_t rpp_association_process(uint32_t phyhandle, char* intfName, uint8_t staNum)
{
    int32_t    errCode = RPP_APP_RET_SUCCESS;
    char       str[64] = "\0";
    char       formatedStr[64] = "\0";
    int32_t    strLength = 0;
    int32_t    count = 0;
    int8_t     temp_var1 = 0;
    int8_t     temp_var2 = 0;
    char*      pStr = NULL;
    /* Extract encryption and psk */
    Encryption *encryption = &(rppStaHandle.addStaReq[staNum].encryption);
    AddStaReq* staCfg = &rppStaHandle.addStaReq[staNum];

    system_cmd_set_f("ifconfig %s down", intfName);
    config_network_intf(phyhandle, "INTERFACE_REMOVE %s", intfName);
    system_cmd_set_f("ifconfig %s up", intfName);
    //wpa_cli -g/tmp/global0 interface_add athX "" athr /var/run/wpa_supplicant
    /* From wpa_cli.c, interface add command parameters separate by TAB
       command: INTERFACE_ADD <ifname>TAB<confname>TAB<driver>TAB<ctrl_interface>TAB<driver_param>TAB<bridge_name>[TAB<create>[TAB<type>]] */
    config_network_intf(phyhandle, "INTERFACE_ADD %s\t%s\t%s\t%s\t\t\t\t", intfName, "", "athr", "/var/run/wpa_supplicant");
    //wpa_cli -i athX add_network
    config_network_intf(phyhandle, "IFNAME=%s ADD_NETWORK", intfName);
    //wpa_cli -i athX set_network 0 ssid '"QCA_5G"'
    config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 ssid \"%s\"", intfName, rppStaHandle.addStaReq[staNum].apssid);
    //wpa_cli -i athX set_network 0 scan_ssid 1
    config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 scan_ssid 1", intfName);
    config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 disable_ht40 %d", intfName, rppStaHandle.addStaReq[staNum].disableht40M);
    config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 disable_max_amsdu %d", intfName, rppStaHandle.addStaReq[staNum].disablemaxamsdu);
    config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 ampdu_density %d", intfName, rppStaHandle.addStaReq[staNum].minampdudensity);

    // only when bssid is not empty set it.
    if(!util_is_empty_array(rppStaHandle.addStaReq[staNum].apbssid,
                sizeof(rppStaHandle.addStaReq[staNum].apbssid))) {
        /* OWE Transition: Removing BSSID check for Transition mode.
         * This step is required to avoid BSSID mismatch in
         * transition mode with that of OPEN SSID */
         if (encryption->type != ENHANCED_OPEN)
             //wpa_cli -i athX set_network 0 bssid 66:55:44:33:22:11
             config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 bssid %s", intfName, util_mac_addr_to_str(rppStaHandle.addStaReq[staNum].apbssid));

    }

    if (rppStaHandle.addStaReq[staNum].pmftype == PMF_DISABLED) {
        //Clearing out rsn capability for PMF disable case, this is neededfor mpsta when profile changes from required to disable
        system_cmd_set_f("iwpriv %s rsncaps 0x0", intfName);
    } else if (rppStaHandle.addStaReq[staNum].pmftype == PMF_OPTIONAL) {
        //wpa_cli -i athX set_network 0 ieee80211w 1
        config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 ieee80211w %d", intfName, PMF_OPTIONAL);
    } else if (rppStaHandle.addStaReq[staNum].pmftype == PMF_REQUIRED) {
        //wpa_cli -i athX set_network 0 ieee80211w 2
        config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 ieee80211w %d", intfName, PMF_REQUIRED);
    }

    switch(encryption->type) {
        case OPEN:
           {
                SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->OPEN encryption.");
                //wpa_cli -i athX set_network 0 key_mgmt NONE
                config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 key_mgmt NONE", intfName);
            }
            break;
        case PERSONAL:
            {
                if (rppStaHandle.addStaReq[staNum].pmftype != PMF_DISABLED) {
                    //wpa_cli -i athX set_network 0 key_mgmt WPA-PSK WPA-PSK-SHA256
                    config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 key_mgmt WPA-PSK WPA-PSK-SHA256", intfName);
                } else {
                    if (rppStaHandle.addStaReq[staNum].fbtcfg.enable) {
                        config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 fbt_target_set 1", intfName);
                        config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 key_mgmt WPA-PSK FT-PSK", intfName);
                    } else
                        //wpa_cli -i athX set_network 0 key_mgmt WPA-PSK
                        config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 key_mgmt WPA-PSK ", intfName);
                }
                //wpa_cli -i athX set_network 0 psk '"password"'
                config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 psk \"%s\"", intfName , rppStaHandle.encryptionPersonal[staNum].passphrase);
            }
            break;

        case ENTERPRISE:
        case WPA3_ENTERPRISE:
            {
                SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->enterprise encryption.");

                if (encryption->type == WPA3_ENTERPRISE) {
                    config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 key_mgmt WPA-EAP-SUITE-B-192", intfName);
                } else {
                    config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 key_mgmt WPA-EAP", intfName);
                }
                switch(rppStaHandle.encryptionEap[staNum].type) {
                    case EAP_TLS:
                        {
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->EAP_TLS for enterprise encryption.");
                            //wpa_cli -i athX set_network 0 eap TLS
                            config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 eap TLS", intfName);
                            //wpa_cli -i athX set_network 0 identity '"user@example.org"'
                            config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 identity \"%s\"", intfName,
                                rppStaHandle.encryptionEap[staNum].u.tls.peeridentity);

                            pStr = basename(rppStaHandle.encryptionEap[staNum].u.tls.cacertfilename);
                            util_install_certificate(phyhandle, intfName, "ca_cert", pStr);

                            pStr = basename(rppStaHandle.encryptionEap[staNum].u.tls.privkeyfilename);
                            util_install_certificate(phyhandle, intfName, "private_key", pStr);

                            pStr = basename(rppStaHandle.encryptionEap[staNum].u.tls.certfilename);
                            util_install_certificate(phyhandle, intfName, "client_cert", pStr);

                            //wpa_cli -i athX set_network 0 private_key_passwd '"password"'
                            config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 private_key_passwd \"%s\"", intfName,
                                rppStaHandle.encryptionEap[staNum].u.tls.password);
                        }
                        break;
                    case EAP_TTLS:
                        {
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->EAP_TTLS for enterprise encryption.");
                            //wpa_cli -i athX set_network 0 eap TTLS
                            config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 eap TTLS", intfName);
                            //wpa_cli -i sta0 set_network 0 anonymous_identity '"anonymous@example.org"'
                            if(strlen(rppStaHandle.encryptionEap[staNum].u.ttls.anonymousidentity))
                                config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 anonymous_identity \"%s\"", intfName,
                                        rppStaHandle.encryptionEap[staNum].u.ttls.anonymousidentity);
                            //wpa_cli -i sta0 set_network 0 identity '"bob"'
                            config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 identity \"%s\"", intfName,
                                rppStaHandle.encryptionEap[staNum].u.ttls.peeridentity);
                            //wpa_cli -i sta0 set_network 0 password '"hello"'
                            config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 password \"%s\"", intfName,
                                rppStaHandle.encryptionEap[staNum].u.ttls.password);

                            pStr = basename(rppStaHandle.encryptionEap[staNum].u.ttls.cacertfilename);
                            util_install_certificate(phyhandle, intfName, "client_cert", pStr);

                            memset (str, 0, sizeof (str));
                            if(rppStaHandle.encryptionEap[staNum].u.ttls.phase2Type == MD5) {
                                //wpa_cli -i sta0 set_network 0 phase2 '"MD5"'
                                strcpy(str, "MD5");
                            } else if(rppStaHandle.encryptionEap[staNum].u.ttls.phase2Type == MSCHAP) {
                                //wpa_cli -i sta0 set_network 0 phase2 '"MSCHAP"'
                                strcpy(str, "auth=MSCHAP");
                            } else if(rppStaHandle.encryptionEap[staNum].u.ttls.phase2Type == MSCHAPV2) {
                                //wpa_cli -i sta0 set_network 0 phase2 '"MSCHAPv2"'
                                strcpy(str, "MSCHAPv2");
                            } else if(rppStaHandle.encryptionEap[staNum].u.ttls.phase2Type == PAP) {
                                //wpa_cli -i sta0 set_network 0 phase2 '"PAP"'
                                strcpy(str, "auth=PAP");
                            } else if(rppStaHandle.encryptionEap[staNum].u.ttls.phase2Type == CHAP) {
                                //wpa_cli -i sta0 set_network 0 phase2 '"CHAP"'
                                strcpy(str, "auth=CHAP");
                            } else if(rppStaHandle.encryptionEap[staNum].u.ttls.phase2Type == GTC) {
                                //wpa_cli -i sta0 set_network 0 phase2 '"GTC"'
                                strcpy(str, "autheap=GTC");
                            } else if(rppStaHandle.encryptionEap[staNum].u.ttls.phase2Type == TLS) {
                                //wpa_cli -i sta0 set_network 0 phase2 '"TLS"'
                                strcpy(str, "autheap=TLS");
                            }

                            //wpa_cli -i sta0 set_network 0 phase2 '"<phase2 authentication string>"'
                            config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 phase2 \"%s\"", intfName, str);
                        }
                        break;
                    case EAP_PEAP:
                        {
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->EAP_PEAP for enterprise encryption.");

                            //wpa_cli -i sta0 set_network 0 eap PEAP
                            config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 eap PEAP", intfName);
                            //wpa_cli -i sta0 set_network 0 anonymous_identity '"anonymous@example.org"'
                            if(strlen(rppStaHandle.encryptionEap[staNum].u.peap.anonymousidentity))
                                config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 anonymous_identity \"%s\"", intfName,
                                        rppStaHandle.encryptionEap[staNum].u.peap.anonymousidentity);
                            //wpa_cli -i sta0 set_network 0 identity '"bob"'
                            config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 identity \"%s\"", intfName, rppStaHandle.encryptionEap[staNum].u.peap.peeridentity);
                            //wpa_cli -i sta0 set_network 0 password '"hello"'
                            config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 password \"%s\"", intfName, rppStaHandle.encryptionEap[staNum].u.peap.password);

                            pStr = basename(rppStaHandle.encryptionEap[staNum].u.peap.cacertfilename);
                            util_install_certificate(phyhandle, intfName, "client_cert", pStr);

                            //wpa_cli -i sta0 set_network 0 phase1 '"peapver=0"'
                            config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 phase1 \"peapver=0\"", intfName);
                            memset (str, 0, sizeof (str));
                            if(rppStaHandle.encryptionEap[staNum].u.peap.phase2Type == MD5) {
                                //wpa_cli -i sta0 set_network 0 phase2 '"MD5"'
                                strcpy(str, "MD5");
                            } else if(rppStaHandle.encryptionEap[staNum].u.peap.phase2Type == MSCHAP) {
                                //wpa_cli -i sta0 set_network 0 phase2 '"MSCHAP"'
                                strcpy(str, "MSCHAP");
                            } else if(rppStaHandle.encryptionEap[staNum].u.peap.phase2Type == MSCHAPV2) {
                                //wpa_cli -i sta0 set_network 0 phase2 '"MSCHAPv2"'
                                strcpy(str, "autheap=MSCHAPv2");
                            } else if(rppStaHandle.encryptionEap[staNum].u.peap.phase2Type == PAP) {
                                //wpa_cli -i sta0 set_network 0 phase2 '"PAP"'
                                strcpy(str, "PAP");
                            } else if(rppStaHandle.encryptionEap[staNum].u.peap.phase2Type == CHAP) {
                                //wpa_cli -i sta0 set_network 0 phase2 '"CHAP"'
                                strcpy(str, "CHAP");
                            } else if(rppStaHandle.encryptionEap[staNum].u.peap.phase2Type == GTC) {
                                //wpa_cli -i sta0 set_network 0 phase2 '"GTC"'
                                strcpy(str, "autheap=GTC");
                            } else if(rppStaHandle.encryptionEap[staNum].u.peap.phase2Type == TLS) {
                                //wpa_cli -i sta0 set_network 0 phase2 '"TLS"'
                                strcpy(str, "autheap=TLS");
                            }

                            //wpa_cli -i sta0 set_network 0 phase2 '"<phase2 authentication string>"'
                            config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 phase2 \"%s\"", intfName, str);

                        }
                        break;
                    case EAP_AKA:
                        {
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->EAP_AKA for enterprise encryption.");
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->subtype:%d.", rppStaHandle.encryptionEap[staNum].u.aka.subtype);
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->identity:%s", rppStaHandle.encryptionEap[staNum].u.aka.identity);
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->password:%s", rppStaHandle.encryptionEap[staNum].u.aka.password);

                            if (rppStaHandle.encryptionEap[staNum].u.aka.subtype == EAP_AKA_SUBTYPE_SIM) {
                                //wpa_cli -i sta0 set_network 0 eap SIM
                                config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 eap SIM", intfName);
                            }
                            else if (rppStaHandle.encryptionEap[staNum].u.aka.subtype == EAP_AKA_SUBTYPE_AKA) {
                                //wpa_cli -i sta0 set_network 0 eap AKA
                                config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 eap AKA", intfName);

                            } else {
                                //wpa_cli -i sta0 set_network 0 eap AKA'
                                config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 eap AKA'", intfName);
                            }

                            //wpa_cli -i sta0 set_network 0 identity '"identity@wlan.org"'
                            config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 identity \"%s\"", intfName, rppStaHandle.encryptionEap[staNum].u.aka.identity);

                            //wpa_cli -i sta0 set_network 0 password '"password"'
                            config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 password \"%s\"", intfName, rppStaHandle.encryptionEap[staNum].u.aka.password);

                        }
                        break;
                    default:
                        break;
                }
            }
            break;

        case WEP:
            {
                SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->wep encryption.");
                //wpa_cli -i athX set_network 0 key_mgmt NONE
                config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 key_mgmt NONE", intfName);

                if ( rppStaHandle.encryptionWep[staNum].format == WEP_KEY_ASCII) {
                    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->WEP encryption key format = WEP_KEY_ASCII.");

                    memset (str, 0, sizeof (str));
                    strcpy(str , (char*)rppStaHandle.encryptionWep[staNum].key);
                    strLength = strlen(str);
                    memset (formatedStr, 0, sizeof (formatedStr));
                    for (count = 0; count < strLength; count++) {
                        temp_var1 = (str[count] & 0xf0) >> 4 ;
                        temp_var2 = str[count] & 0x0f ;
                        if ((temp_var1 % 16) <= 9) {
                            formatedStr[count*2] = temp_var1 + 48 ;
                        } else {
                            formatedStr[count*2] = temp_var1 + 55 ;
                        }
                        if ((temp_var2 % 16) <= 9) {
                            formatedStr[(count*2) + 1] = temp_var2 + 48 ;
                        } else {
                            formatedStr[(count*2) + 1] = temp_var2 + 55 ;
                        }
                    }
                    //wpa_cli -i athX set_network 0 wep_key0 1234567890
                    config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 wep_key0 %s", intfName, formatedStr);
                    //wpa_cli -i athX set_network 0 wep_tx_keyidx 0
                    config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 wep_tx_keyidx 0", intfName);
                }
                else {
                    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->WEP encryption key format = WEP_KEY_HEX.");
                    //wpa_cli -i athX set_network 0 wep_key0 1234567890
                    config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 wep_key0 %s", intfName,
                        rppStaHandle.encryptionWep[staNum].key);
                    //wpa_cli -i athX set_network 0 wep_tx_keyidx 0
                    config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 wep_tx_keyidx 0", intfName);
                }
            }
            break;

        case ENHANCED_OPEN:
            {
                config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 key_mgmt OWE",intfName);
            }
            break;

        case WPA3_PERSONAL:
            {
                config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 key_mgmt SAE",intfName);
                config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 sae_password \"%s\"", intfName , rppStaHandle.encryptionPersonal[staNum].passphrase);
            }
            break;

        case WPA2_WPA3_PERSONAL:
            {
                config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 key_mgmt SAE",intfName);
                config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 psk \"%s\"", intfName , rppStaHandle.encryptionPersonal[staNum].passphrase);
                config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 sae_password \"%s\"", intfName , rppStaHandle.encryptionPersonal[staNum].passphrase);
            }
            break;
    }
    /* As we need to give the hold_bss/ unhold_bss  commands for the target APs and associated AP also..
     * Length of target AP List = number of targets from GUI + 1 (associated AP)
     */
    if ((staCfg->fbtcfg.enable) && (rppStaHandle.targetAPList[staNum] != NULL)) {
        for (uint8_t targetIndex = 0 ; targetIndex <= staCfg->fbtcfg.nbroftargets; targetIndex++) {
            system_cmd_set_f("wpa_cli -i %s -g /tmp/global%d hold_bss %s", intfName, phyhandle,
                                                  util_mac_addr_to_str((uint8_t *)&rppStaHandle.targetAPList[staNum][targetIndex]));
        }
    }

    //wpa_cli -i athX sta_autoconnect 0
    config_network_intf(phyhandle, "IFNAME=%s STA_AUTOCONNECT 0 ", intfName);
    //wpa_cli -i athX enable_network 0
    config_network_intf(phyhandle, "IFNAME=%s ENABLE_NETWORK 0 ", intfName);
    return errCode;
}
/******************************************************************************
 * Function Name    : rpp_session_cleanup
 * Description      : This Function is used to cleanup old session data.
 ******************************************************************************/
int32_t rpp_session_cleanup()
{
    int32_t     errCode = RPP_APP_RET_SUCCESS;
    int32_t     radioIndex = 0;
    uint8_t     staNum = 0;
    int32_t     ret = 0;
    int32_t     totalSta = 0;
    int32_t     stationIndex = 0;
    struct staInfo *stainfo = NULL;

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->cleanup_old_session_data()_start");

    if( cleanupProcess == false) {
        SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->No need to process the cleanup again.");
        return ret;
    }
    totalSta = rppStaHandle.totalCount;

    /*re-initialization of station association handle structure*/
    SYSLOG_PRINT(LOG_DEBUG, " DEBUG_MSG------->initialization of station association handle structure.\n");

    for (radioIndex = 0; radioIndex < rpp_num_of_radios; radioIndex++) {
        RppPhyCaptureHdl[radioIndex].gProcStatus = 0xFF;
        RppPhyCaptureHdl[radioIndex].gProcStatus_SDR = 0xFF;
        RppPhyCaptureHdl[radioIndex].captureMode = 0xFF;
        RppPhyCaptureHdl[radioIndex].snifferMode_chwidth = 0;
        RppPhyCaptureHdl[radioIndex].snifferMode_ctl_freq = 0;
        RppPhyCaptureHdl[radioIndex].snifferMode_center_freq2 = 0;
    }
    memset (RppProxyStaStatusHdl, 0, sizeof (RppProxyStaStatusStruct)*RPP_NUM_OF_RADIO);
    memset (PROXY_STA, RPP_APP_DEFNUM_ONE, sizeof (uint8_t)*RPP_NUM_OF_RADIO);
    memset (gPhyHandle, 0xFF, sizeof (uint32_t)*RPP_NUM_OF_RADIO);

    /*initialize assocstate lock per radio */
    for (radioIndex = 0; radioIndex < rpp_num_of_radios; radioIndex++) {
        pthread_mutex_lock( &assocStatLock[radioIndex] );
    }
    for (radioIndex = 0; radioIndex < rpp_num_of_radios; radioIndex++) {
        staAssocHdl[radioIndex].staCount = 0;
        stainfo = &staAssocHdl[radioIndex].staCountInfo[0];
        for (stationIndex = 0; stationIndex < RPP_MAX_STA_PER_RADIO; stationIndex++, stainfo++) {
            stainfo->assocStatus = STATE_ASSOCIATE_FAILED;
            stainfo->assocReqStatus = 0xff;
            stainfo->staStatus = RPP_STATE_STATION_NOTPRESENT;
            stainfo->deassocnotify = RPP_DEASSOC_NOTIFY_UNSET;
            stainfo->is11kNRRtriggered = false;
            stainfo->is11vBTMtriggered = false;
            stainfo->staRoamTrigger = false;
            stainfo->staRoamTrialCount = 0;
        }
    }
    for (radioIndex = 0; radioIndex < rpp_num_of_radios; radioIndex++) {
        pthread_mutex_unlock( &assocStatLock[radioIndex] );
    }
    pthread_mutex_lock( &staProcessLock );

    //Separating out deassociate/delete to improve time of cleanup during port offline
    for (stationIndex = 0; stationIndex < totalSta; stationIndex++) {
        if(rppStaHandle.staHandle[stationIndex] == -1) {
            totalSta += 1;
            continue;
        } else {
            /* Compute the station number */
            staNum = rppStaHandle.staNum[stationIndex];
            SYSLOG_PRINT(LOG_DEBUG, " DEBUG_MSG------->Disconnecting the sta%d station.\n",staNum);
            system_cmd_set_f("ifconfig sta%u down",staNum);
            system_cmd_set_f("wpa_cli -g/tmp/global%d interface_remove sta%u", rppStaHandle.phy[staNum], staNum);
        }
    }
    for (stationIndex = 0; stationIndex < totalSta; stationIndex++) {
        /* Compute the station number */
        staNum = rppStaHandle.staNum[stationIndex];
        SYSLOG_PRINT(LOG_DEBUG, " DEBUG_MSG------->Purging the sta%d station.\n",staNum);
        system_cmd_set_f("wlanconfig sta%u destroy", staNum);

        SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->sta%u going to NOT_CREATED state\n", staNum);
        rppStaHandle.staCreateStatus[staNum] = STA_NOT_CREATED;
        if (rppStaHandle.targetAPList[staNum] != NULL) {
            free(rppStaHandle.targetAPList[staNum]);
            rppStaHandle.targetAPList[staNum] = NULL;
        }
    }

    /*re-initialization of global station handle structure*/
    SYSLOG_PRINT(LOG_DEBUG, " DEBUG_MSG------->initialization of global station handle structure.\n");
    rpp_stahandle_init();

    /*re-initialization of gsetModeInfo structure*/
    /*Also checking and deleting the ath interface*/
    /*And also checking and deleting the mon interface and process*/
    for (radioIndex = 0; radioIndex < rpp_num_of_radios; radioIndex++) {
        gsetModeInfo[radioIndex].modeVal = 0;
        gsetModeInfo[radioIndex].captype = 0;
        gsetModeInfo[radioIndex].filterexplen = 0;
        gsetModeInfo[radioIndex].filterexp = '\0';

        SYSLOG_PRINT(LOG_DEBUG, " DEBUG_MSG------->Deleting ath%d.\n",radioIndex);

        rpp_delete_station(radioIndex, "ath", radioIndex);

        SYSLOG_PRINT(LOG_DEBUG, " DEBUG_MSG------->Deleting mon%d.\n",radioIndex);

        system_cmd_set_f("ifconfig mon%u down", radioIndex);
        /*re-initialization of stations_per_radio to zero*/
        system_cmd_set_f("wlanconfig mon%u destroy", radioIndex);

        /*re-initialization of stations_per_radio to zero*/
        staPerRadioHdl[radioIndex].active_stations_per_radio = 0;
        staPerRadioHdl[radioIndex].total_stations_per_radio = 0;

        /*re-initialization of staAssocHdl.associated_stations_per_radio to default value*/
        staAssocHdl[radioIndex].associated_stations_per_radio = 0;

        /*re-initialization of the RppPhyCaptureHdl.gProcStatus used in capture processing*/
        RppPhyCaptureHdl[radioIndex].gProcStatus = 0xff;

        /*re-initialization of the captureMode used in capture processing*/
        RppPhyCaptureHdl[radioIndex].captureMode = 0xff;
        RppPhyCaptureHdl[radioIndex].snifferMode_chwidth =  0;
        RppPhyCaptureHdl[radioIndex].snifferMode_ctl_freq = 0;
        RppPhyCaptureHdl[radioIndex].snifferMode_center_freq2 = 0;

        if (PROXY_STA[radioIndex]){
            /*re-initiating the proxy stations association status*/
            pthread_mutex_lock(&proxyStateLock[radioIndex]);
            RppProxyStaStatusHdl[radioIndex].proxy_sta_assoc = false;
            pthread_mutex_unlock(&proxyStateLock[radioIndex]);
            RppProxyStaStatusHdl[radioIndex].reset_assoc_trial_count_flag = false;
            RppProxyStaStatusHdl[radioIndex].previous_assoc_req_time = 0;
            pthread_mutex_lock(&proxyStateLock[radioIndex]);
            RppProxyStaStatusHdl[radioIndex].mpsta_assoc_trial_count = 0;
            pthread_mutex_unlock(&proxyStateLock[radioIndex]);
            RppProxyStaStatusHdl[radioIndex].failed_assoc_sent = 0;

            SYSLOG_PRINT(LOG_DEBUG, " DEBUG_MSG------->Deleting staX%d.\n",radioIndex);
            rpp_delete_station(radioIndex, "staX", radioIndex);

        }
        /*re-initialization of gSphyBandData structure, which contains the frequency band*/
        SYSLOG_PRINT(LOG_DEBUG, " initialization of gSphyBandData structure structure.\n");
        gSphyBandData[radioIndex].freqband = 0xff;
        gSphyBandData[radioIndex].chwidth = 0;
        gSphyBandData[radioIndex].bw160nssworkaround  = false;
        gSphyBandData[radioIndex].is11kEnable = false;
        gSphyBandData[radioIndex].is11ktriggered = false;
        gSphyBandData[radioIndex].is11vEnable = false;
        gSphyBandData[radioIndex].is11vtriggered = false;
    }

    gPMF = PMF_INVALID;
    gEncType = ENCTYPE_INVALID;

    /*Killing all the monitord process*/
    SYSLOG_PRINT(LOG_DEBUG, " Killing old session monitord process.\n");
    system_cmd("killall monitord");

    /*Killing all the supplicant process*/
    SYSLOG_PRINT(LOG_DEBUG, " Killing old session wpa_supplicant process.\n");
    system_cmd("killall wpa_supplicant");

    /*Deleting the scanlist file from /tmp folder*/
    SYSLOG_PRINT(LOG_DEBUG, " Deleting the scanlist from the /tmp folder.\n");
    system_cmd("rm -rf /tmp/scanlist.txt");

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->cleanup_old_session_data()_exit");
    pthread_mutex_unlock( &staProcessLock );

    // Close wpa control interface connection
    for (radioIndex = 0; radioIndex < rpp_num_of_radios; radioIndex++) {
        pthread_mutex_lock( &staAssocHdl[radioIndex].wpaCtrlLock);
        close_wpa_ctrl_conn(radioIndex);
        pthread_mutex_unlock( &staAssocHdl[radioIndex].wpaCtrlLock);
    }
    cleanupProcess = false;

    return errCode;
}

#if ENABLE_STATS_FROM_ETHTOOL_LIB
/******************************************************************************
 * Function Name    : rpp_send_ioctl
 * Description      : This Function is used to call the ioctl function
 ******************************************************************************/
static uint32_t rpp_send_ioctl(struct cmd_context *ctx, void *cmd)
{
    ctx->ifr.ifr_data = cmd;
    return ioctl(ctx->fd, SIOCETHTOOL, &ctx->ifr);
}

/**********************************************************************************
 * Function Name    : get_stringsetlen
 * Description      : This Function is used get stringset length.
 **********************************************************************************/
static uint32_t get_stringsetlen(struct cmd_context *ctx, ptrdiff_t drvinfo_offset)
{
    struct {
       struct ethtool_sset_info hdr;
       uint32_t buf[1];
    } sset_info;
    struct ethtool_drvinfo drvinfo;
    uint32_t len;

    sset_info.hdr.cmd = ETHTOOL_GSSET_INFO;
    sset_info.hdr.reserved = 0;
    sset_info.hdr.sset_mask = 1ULL << ETH_SS_STATS;

    if (rpp_send_ioctl(ctx, &sset_info) == 0) {
        len = sset_info.hdr.sset_mask ? sset_info.hdr.data[0] : 0;
    } else if (errno == EOPNOTSUPP && drvinfo_offset != 0) {
        /* Fallback for old kernel versions */
        drvinfo.cmd = ETHTOOL_GDRVINFO;
        if (rpp_send_ioctl(ctx, &drvinfo))
            return 0;
        len = *(uint32_t *)((char *)&drvinfo + drvinfo_offset);
    } else {
        return 0;
    }
    return len;
}
#endif

/*****************************************************************************
* Function Name    : thread_get_stats
* Description      : This thread is used to send the statistics of station to
*                    Host.
******************************************************************************/
void *thread_get_stats(void *p_threadData)
{
    uint8_t     staNum = 0;
    int32_t totalSta = 0;
    int32_t radioIndex = 0;
    int32_t stationIndex = 0;
    int32_t temp_val = 0;
    uint64_t tvalue = 0;
    int8_t rssi_staX[RPP_NUM_OF_RADIO];
    size_t     respBufSz = 0;
    char       *respBuf = NULL;
    int32_t     rssiVal = 0;
    RppMessageHead *msghdr;
    StatsUpdate* staupdt;
    StatsBulkUpdate *resp[RPP_NUM_OF_RADIO];
    char *interface_name = NULL;

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->thread_get_stats_fun()_start");
    StaStats *stats;

    memset(rssi_staX, 0, sizeof(int8_t) * RPP_NUM_OF_RADIO);
#if ENABLE_STATS_FROM_ETHTOOL_LIB
    struct ethtool_stats *ethstats;
    struct ethtool_dump *ethdump;
    struct cmd_context *ctx;
    uint32_t numOfStats;
    uint32_t nbrOfStationsPerRadio;
    int32_t err;
    uint32_t loop = 0;
    uint8_t index = 0;
    uint8_t bwIndex =0;
    uint8_t nssIndex =0;
    uint8_t giIndex =0;
    uint8_t mcsIndex = 0;
    uint64_t time_served=0;
	uint8_t rxChnBw = 0;
	uint8_t firstSMAindex = 0;

    ctx = (struct cmd_context *)malloc(sizeof(struct cmd_context));
    if(ctx == NULL)
        return NULL;

    /* Stats Socket Open */
    memset(&ctx->ifr, 0, sizeof(ctx->ifr));
    ctx->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->fd < 0) {
        free(ctx);
        perror("Cannot get control socket");
        return NULL;
    }
#endif

    while(RPP_APP_DEFNUM_ONE) {

        uint64_t current_ts = current_timestamp();
        if ( (current_ts - time_served) < RPP_STATS_TIME)
        {
            usleep(RPP_STATS_SLEEP);
            continue;
        }
        time_served = current_ts;

#if ENABLE_STATS_FROM_ETHTOOL_LIB
        /* This loop belongs to get the signal strength for mpsta and stored in local variable */
        for (radioIndex = 0; radioIndex < rpp_num_of_radios; radioIndex++) {
            pthread_mutex_lock( &staProcessLock );
            /* Find the total number of stations */
            totalSta = rppStaHandle.totalCount;
            nbrOfStationsPerRadio = staPerRadioHdl[radioIndex].total_stations_per_radio;
            if (totalSta == 0) {
                pthread_mutex_unlock( &staProcessLock );
                continue;
            }

            /*response structure size to be send on UDP socket */
            if (staPerRadioHdl[radioIndex].total_stations_per_radio == 0) {
                pthread_mutex_unlock( &staProcessLock );
                continue;
            }
            respBufSz = RPPMSG_STATS_BULK_UPDATE_RESP_SZ + sizeof(StatsUpdate);
            respBuf = (char*)calloc(1,respBufSz * sizeof(char));
            //SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->Stats Thread == after calloc memory address of radio[%d] = %p",count,respBuf
            if (respBuf == NULL)
                SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->Stats Thread == Memory not allocated.");
            msghdr = (RppMessageHead *) respBuf;
            msghdr->cat = RPP_MSG_REQ ;
            msghdr->type = RPP_MSG_STATS_UPDATE;
            msghdr->len = respBufSz - RPPMSG_HDR_SIZE;
            resp[radioIndex] = (StatsBulkUpdate*)msghdr->body;

            resp[radioIndex]->nbrofstats = 1;

            staupdt = (StatsUpdate *)resp[radioIndex]->stats;

            loop = 0;
            if (PROXY_STA[radioIndex]) {
                sprintf (ctx->ifr.ifr_name, "staX%d", radioIndex);
            } else {
                for (stationIndex = 0; stationIndex < totalSta; stationIndex++) {
                    if(rppStaHandle.phy[stationIndex] == -1) {
                        totalSta += 1;
                        continue;
                    } else if (rppStaHandle.phy[stationIndex] == radioIndex) {
                        sprintf (ctx->ifr.ifr_name, "sta%d", rppStaHandle.staNum[stationIndex]);
                        break;//only first station name is required per radio. So breaking the loop.
                    }
                }
            }

#ifndef RDP419 // RDP419 disable cca stats for now
            ethdump = calloc(1, WAL_CCA_CNTR_HIST_LEN * sizeof(pdev_stats_cca_counters) + sizeof(struct ethtool_dump));
            if (!ethdump) 
            {
                fprintf(stderr, "Failed to allocate ethdump\n");
            }
            else
            {
                ethdump->cmd = ETHTOOL_GET_DUMP_DATA;
                ethdump->len = WAL_CCA_CNTR_HIST_LEN * sizeof(pdev_stats_cca_counters);
                err = rpp_send_ioctl(ctx, ethdump);
                if (err < 0) {
                    perror("Cannot get cca stats information");
                    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->CCA Stats Failed");
                }
                else
                {
                    pdev_stats_cca_counters *counters;
                    char stats_buffer[RPPMSG_CCA_STATS_SZ];
                    RppMessageHead *hdr = (RppMessageHead *)stats_buffer;
                    PhyCcaStatsUpdate *cca_stats_update = (PhyCcaStatsUpdate *) (stats_buffer + sizeof(RppMessageHead));

                    counters = (pdev_stats_cca_counters *) ethdump->data;
                
                    hdr->cat = RPP_MSG_REQ;
                    hdr->type = RPP_MSG_CCA_STATS_UPDATE;
                    hdr->len = sizeof(PhyCcaStatsUpdate);
                
                    cca_stats_update->phyhandle = radioIndex;
                    REMAP_PHY_HANDLE(cca_stats_update->phyhandle); 
                    cca_stats_update->stat.numseconds = WAL_CCA_CNTR_HIST_LEN;
                    memcpy(cca_stats_update->stat.counters, counters, WAL_CCA_CNTR_HIST_LEN * sizeof(PhyCcaCounters));
                    if(send_eth_udp_stats_to_fpga(stats_buffer, RPPMSG_CCA_STATS_SZ) < 0) {
                        perror ("send_CCA_stats_buffer_to_host()");
                        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_CCA_stats_to_host()");
                    }
                }
                free(ethdump);
            }
#endif

            numOfStats = get_stringsetlen(ctx, offsetof(struct ethtool_drvinfo, n_stats));

            if (numOfStats < 1) {
                fprintf(stderr, "no stats available\n");
                free(respBuf);
                pthread_mutex_unlock( &staProcessLock );
                continue;
            }

            if (PROXY_STA[radioIndex]) {
                ethstats = calloc(1, ((staPerRadioHdl[radioIndex].total_stations_per_radio + 1) * numOfStats * sizeof(uint64_t)) +
                    sizeof(struct ethtool_stats));
                if (!ethstats) {
                    fprintf(stderr, "no memory available\n");
                    free(respBuf);
                    pthread_mutex_unlock( &staProcessLock );
                    continue;
                }
                ethstats->n_stats = staPerRadioHdl[radioIndex].total_stations_per_radio;
            } else {
                ethstats = calloc(1, ((staPerRadioHdl[radioIndex].total_stations_per_radio) * numOfStats * sizeof(uint64_t)) +
                    sizeof(struct ethtool_stats));
                if (!ethstats) {
                    fprintf(stderr, "no memory available\n");
                    free(respBuf);
                    pthread_mutex_unlock( &staProcessLock );
                    continue;
                }
                ethstats->n_stats = staPerRadioHdl[radioIndex].total_stations_per_radio - 1;
            }
            ethstats->cmd = ETHTOOL_GSTATS;
            err = rpp_send_ioctl(ctx, ethstats);
            pthread_mutex_unlock( &staProcessLock );

            if (err < 0) {
                perror("Cannot get stats information");
                free(ethstats);
                free(respBuf);
                continue;
            }
            //If MPSTA is not associated, no stats should be sent to host
            if( (uint8_t)(ethstats->data[loop+24]) != RPP_STA_ASSOC_STATE ) {
                free(ethstats);
                free(respBuf);
                continue;
            }
            rssi_staX[radioIndex] = (int8_t)(ethstats->data[loop+28]);//28 is the index to get rssi value from the ethtool
            gSphyBandData[rppStaHandle.phy[radioIndex]].rssi = rssi_staX[radioIndex];
            stats = (StaStats*)calloc(1, sizeof(StaStats));
            if (!stats) {
                SYSLOG_PRINT(LOG_DEBUG,"Memory allocation failed \n");
                continue;
            }

            for (stationIndex = 0; stationIndex < nbrOfStationsPerRadio;stationIndex++) {
                if (PROXY_STA[radioIndex])
                    loop = numOfStats + ( stationIndex * numOfStats );
                else
                    loop = stationIndex * numOfStats;

                staupdt->phyhandle = radioIndex;
                REMAP_PHY_HANDLE(staupdt->phyhandle);

                //SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->Stats Thread=== interface name in ethtool = %s ",&ethstats->data[loop]);
                interface_name = (char*)(&ethstats->data[loop++]);
                //SYSLOG_PRINT(LOG_DEBUG,"Interface name on radio[%d] = %s \n", radioIndex, interface_name);
                staNum = (uint8_t)atoi(interface_name+3);
                //SYSLOG_PRINT(LOG_DEBUG,"Station Number = %d \n", staNum);
                staupdt->stahandle = (uint32_t)staNum;//station handle is same as station Number

                stats->mimomode = (uint32_t)(ethstats->data[loop++]);
                temp_val = (int8_t)(ethstats->data[loop++]);
                stats->rxnss = (temp_val <= 0)? 0:temp_val;
                temp_val = (int8_t)(ethstats->data[loop++]);
                stats->txnss = (temp_val <= 0)? 0:temp_val;
                stats->freqband = (int32_t)(ethstats->data[loop++]);
                stats->freqband = gSphyBandData[rppStaHandle.phy[radioIndex]].freqband;
                //stats->chnbw = (uint32_t)(ethstats->data[loop++]);
                temp_val = (int32_t)(ethstats->data[loop++]);
	        rxChnBw = temp_val;
                stats->chnbw = temp_val + RPP_APP_DEFNUM_ONE;
                if (!IS_THREE_RADIO_PROFILE && stats->chnbw == RPP_APP_DEFNUM_FOUR) {
                    stats->chnbw = RPP_APP_DEFNUM_FIVE;  /*Report 160 instead of 80+80 */
                }
                //txmcsindex and rxmcsindex changed to default -1 as 0 is valid MCS and +1 is added to matching enum with STC
                temp_val = ethstats->data[loop++];
                stats->txmcsindex = temp_val +1;
                temp_val = ethstats->data[loop++];
                stats->rxmcsindex = temp_val +1;

                //stats->rxgi = (uint32_t)(ethstats->data[loop++]);
                temp_val = (int32_t)(ethstats->data[loop++]);
                stats->rxgi = temp_val + RPP_APP_DEFNUM_ONE;
                //stats->txgi = (uint32_t)(ethstats->data[loop++]);
                temp_val = (int32_t)(ethstats->data[loop++]);
                stats->txgi = temp_val + RPP_APP_DEFNUM_ONE;
                //stats->sectype = (uint32_t)(ethstats->data[loop++]);
                temp_val = (int32_t)(ethstats->data[loop++]);
                if (temp_val == RPP_APP_DEFNUM_ONE || temp_val == RPP_APP_DEFNUM_TWO) {
                    stats->sectype = Security_OPEN;
                } else if (temp_val == RPP_APP_DEFNUM_FIVE) {
                    stats->sectype = Security_PERSONAL;
                } else if (temp_val == RPP_APP_DEFNUM_THREE) {
                    stats->sectype = Security_ENTERPRISE;
                } else if (temp_val == RPP_APP_DEFNUM_NINE) {
                    stats->sectype = Security_WPA3_PERSONAL;
                }

                //stats->sumumode = (uint32_t)(ethstats->data[loop++]);
                temp_val = (int32_t)(ethstats->data[loop++]);

                if (temp_val == 1) {
                    stats->sumumode = 1;
                }
                else if (temp_val == 2) {
                   stats->sumumode = 0;
                   stats->rxofdmamode = 1;
                }else {
                   stats->sumumode = temp_val;
                }
                stats->groupid = (uint8_t)(ethstats->data[loop++]);
                stats->wmmstate = (uint8_t)(ethstats->data[loop++]);
                stats->mfpstatus = (uint8_t)(ethstats->data[loop++]);
                stats->tdlspeerstatus = (uint8_t)(ethstats->data[loop++]);
                tvalue = (uint64_t)(ethstats->data[loop++]);
                stats->maxrxphyrate = tvalue * pow(10,6);
                tvalue = (uint64_t)(ethstats->data[loop++]);
                stats->maxtxphyrate = tvalue * pow(10,6);
                stats->ftdelay = (uint64_t)(ethstats->data[loop++]);
                stats->ftmindelay = (uint64_t)(ethstats->data[loop++]);
                stats->ftmaxdelay = (uint64_t)(ethstats->data[loop++]);
                stats->ftavedelay = (uint64_t)(ethstats->data[loop++]);
                stats->ftsuccess = (uint64_t)(ethstats->data[loop++]);
                stats->ftfail = (uint64_t)(ethstats->data[loop++]);

                stats->stastate = (uint8_t)(ethstats->data[loop++]);
                if (stats->stastate == RPP_STA_ASSOC_STATE) {
                    /* Modifying to 5 to match with the wlan mgr expectation */
                    stats->stastate = 5; 
                    resp[radioIndex]->nbrofstats = 1;
                } else {
                    //If any station is not associated, it stats will not be sent to host, so reducing radioIndex here
                    resp[radioIndex]->nbrofstats = 0;
                    continue;
                }
                //stats->wlanmode = (uint32_t)(ethstats->data[loop++]);
                temp_val = (int32_t)(ethstats->data[loop++]);
                if (temp_val == RPP_APP_DEFNUM_ONE || temp_val == RPP_APP_DEFNUM_FIVE) {
                    stats->wlanmode = MODE_A;
                } else if (temp_val == RPP_APP_DEFNUM_TWO) {
                    stats->wlanmode = MODE_B;
                } else if (temp_val == RPP_APP_DEFNUM_THREE || temp_val == RPP_APP_DEFNUM_SIX) {
                    stats->wlanmode = MODE_G;
                } else if (temp_val >= RPP_APP_DEFNUM_SEVEN && temp_val <= 14 ) {
                    stats->wlanmode = MODE_N;
                } else if (temp_val >= 15 && temp_val <= 21 ) {
                    stats->wlanmode = MODE_AC;
                } else if (temp_val >= 22 && temp_val <= 32 ) {
                    stats->wlanmode = MODE_AX;
                }
                tvalue = (uint32_t)(ethstats->data[loop++]);
                stats->ctlfreq = tvalue/100000;

                /* bssid */
                for (index = 0; index < 6; index++) {
                    stats->bssid[index] = (uint8_t)((ethstats->data[loop] >> (index * 8)) & 0xff);
                }
                loop++;

                stats->rssi = (int8_t)(ethstats->data[loop++]);
                if (PROXY_STA[radioIndex]){
                    stats->rssi = rssi_staX[radioIndex];
                }
                stats->noisefloor = (int8_t)(ethstats->data[loop++]);
                stats->rxpkts = (uint64_t)(ethstats->data[loop++]);
                stats->rxbytes = (uint64_t)(ethstats->data[loop++]);
                stats->txpkts = (uint64_t)(ethstats->data[loop++]);
                stats->txbytes = (uint64_t)(ethstats->data[loop++]);

#ifdef ADVANCE_STATS
                // SYSLOG_PRINT(LOG_DEBUG,"RI %d, SI %d, SN %d, WF %d \n", radioIndex, stationIndex, nbrOfStationsPerRadio, wifinum);
                if (IS_THREE_RADIO_PROFILE) {
                    if(radioIndex == 2) {
                        firstSMAindex = 4;
                    }
                    else {
                        firstSMAindex = 0;
                    }
                }
                /* per nss tx counter  - ps_txpkts */
                for (nssIndex = firstSMAindex; nssIndex < RPP_NUM_OF_NSS; nssIndex++) {
                    stats->ps_txpkts[nssIndex] = (uint64_t)ethstats->data[loop++];
                }
                loop = loop + firstSMAindex;
                /* per nss rx counter - ps_rxpkts */
                for (nssIndex = firstSMAindex; nssIndex < RPP_NUM_OF_NSS; nssIndex++) {
                    stats->ps_rxpkts[nssIndex] = (uint64_t)ethstats->data[loop++];
                }
                loop = loop + firstSMAindex;
                /* per chw tx counter - pcw_txpkts */
                for (bwIndex = 0; bwIndex < RPP_NUM_OF_BW; bwIndex++) {
                    stats->pcw_txpkts[bwIndex] = (uint64_t)ethstats->data[loop++];
                }
                /* per chw rx counter - pcw_rxpkts */
                for (bwIndex = 0; bwIndex < RPP_NUM_OF_BW; bwIndex++) {
                    stats->pcw_rxpkts[bwIndex] = (uint64_t)ethstats->data[loop++];
                }
                /* per mcstype tx counter */
                for (mcsIndex = 0; mcsIndex < RPP_NUM_OF_MCS; mcsIndex++) {
                    stats->pmcs_txpkts[mcsIndex] = (uint64_t)ethstats->data[loop++];
                }
#ifndef ENABLE_MCS12_13_STATS
                loop += 2; // Driver stats already extended, skip it
#endif
                /* per mcstype rx counter */
                for (mcsIndex = 0; mcsIndex < RPP_NUM_OF_MCS; mcsIndex++) {
                    stats->pmcs_rxpkts[mcsIndex] = (uint64_t)ethstats->data[loop++];
                }
#ifndef ENABLE_MCS12_13_STATS
                loop += 2; // Driver stats already extended, skip it
#endif
                /* per mcstype tx su mcs counter */
                for (mcsIndex = 0; mcsIndex < RPP_NUM_OF_MCS; mcsIndex++) {
                    stats->pmcs_txsupkts[mcsIndex] = (uint64_t)ethstats->data[loop++];
                }
#ifndef ENABLE_MCS12_13_STATS
                loop += 2; // Driver stats already extended, skip it
#endif
                /* per mcstype rx su mcs counter */
                for (mcsIndex = 0; mcsIndex < RPP_NUM_OF_MCS; mcsIndex++) {
                    stats->pmcs_rxsupkts[mcsIndex] = (uint64_t)ethstats->data[loop++];
                }
#ifndef ENABLE_MCS12_13_STATS
                loop += 2; // Driver stats already extended, skip it
#endif
                /* per mcstype tx mu mcs counter */
                for (mcsIndex = 0; mcsIndex < RPP_NUM_OF_MCS; mcsIndex++) {
                    stats->pmcs_txmupkts[mcsIndex] = (uint64_t)ethstats->data[loop++];
                }
#ifndef ENABLE_MCS12_13_STATS
                loop += 2; // Driver stats already extended, skip it
#endif
                /* per mcstype rx mu mcs counter */
                for (mcsIndex = 0; mcsIndex < RPP_NUM_OF_MCS; mcsIndex++) {
                    stats->pmcs_rxmupkts[mcsIndex] = (uint64_t)ethstats->data[loop++];
                }
#ifndef ENABLE_MCS12_13_STATS
                loop += 2; // Driver stats already extended, skip it
#endif
                /* per GUI tx couter */
                for (giIndex = 0; giIndex < RPP_NUM_OF_GI; giIndex++) {
                    stats->pgi_txpkts[giIndex] = (uint64_t)ethstats->data[loop++];
                }
                /* per GUI rx couter */
                for (giIndex = 0; giIndex < RPP_NUM_OF_GI; giIndex++) {
                    //stats->pgi_rxpkts[index][0] = (uint64_t)ethstats->data[loop++];
                    for (mcsIndex = 0; mcsIndex < RPP_NUM_OF_MCS; mcsIndex++) {
                        stats->pgi_rxpkts[giIndex][mcsIndex] = (uint64_t)ethstats->data[loop++];
                    }
#ifndef ENABLE_MCS12_13_STATS
                    loop += 2; // Driver stats already extended, skip it
#endif
                }
                /* per stream rssi */
                for (bwIndex = 0; bwIndex < RPP_NUM_OF_BW; bwIndex++) {
                    for (nssIndex = firstSMAindex; nssIndex < RPP_NUM_OF_NSS; nssIndex++) {
					    /* The RSSI counters for the Bandwidth which is higher than the asscociated are set as default */
                        rssiVal = ethstats->data[loop++];
                        //Rssi -128 is idle/default value of rssi when no traffic so need to report it 0
                        if ((bwIndex <= rxChnBw) && (rssiVal != -RPP_DEFAULT_RSSI_VALUE) && (rssiVal != RPP_DEFAULT_RSSI_VALUE)) {
                            /* Noise floor for different channel bandwidth will be calculated as below, This calculation is used to convert the value from dB to dBm,
                            20MHz:  -95dBm  95 - (0 * 3) = -95
                            40Mhz: - 92dBm  95 - (1 * 3) = -92
                            80Mhz: - 89dBm  95 - (2 * 3) = -89
                            160Mhz: -86dBm  95 - (3 * 3) = -86 */
                            stats->ps_rssi[bwIndex][nssIndex] = (int8_t)(rssiVal - (NOISE_FLOOR - (bwIndex * RPP_BW_SHIFT_VALUE)));
                        }
		                else {
                            stats->ps_rssi[bwIndex][nssIndex] = 0;
			            }
                    }
                    loop = loop + firstSMAindex;
                }

                /* 160Mhz supports only 4 stream rssi values, making
                remaning streams rssi values as default */
                for (nssIndex = RPP_NUM_OF_NSS - 4; nssIndex < RPP_NUM_OF_NSS; nssIndex++)
                    stats->ps_rssi[BW_80P80MHz][nssIndex] = 0;

#endif //#ifdef ADVANCE_STATS

                /* OFDMA stats from ethtool */
                //stats->rxofdmamode = ethstats->data[loop++];
                temp_val = ethstats->data[loop++];
                stats->rxrutype = ethstats->data[loop++];
                stats->rxruassignmentindex = ethstats->data[loop++];
                stats->rxloruindex = ethstats->data[loop++];
                stats->rxhiruindex = ethstats->data[loop++];
                stats->rxofdmapkt = ethstats->data[loop++];
                stats->bsscolorcollisioncounter =  ethstats->data[loop++];
                stats->bsscolorcode = ethstats->data[loop++];
                /* PPDUType : SU = 0, MU-MIMO = 1, MU-OFDMA = 2, MU-MIMO-OFDMA = 3 */
	        temp_val = (int8_t)(ethstats->data[loop++]);
                stats->txppdutype = (temp_val <= 0)? 0:temp_val;
                temp_val = (int8_t)(ethstats->data[loop++]);
                stats->rxppdutype = (temp_val <= 0)? 0:temp_val;
                /* 11v BTM statistics */
                stats->btm_query_counter = ethstats->data[loop++];
                stats->btm_request_counter = ethstats->data[loop++];
                stats->btm_resp_accept_counter = ethstats->data[loop++];
                stats->btm_resp_denial_counter = ethstats->data[loop++];
                memcpy (&(staupdt->stat), stats, sizeof (StaStats));
                //staupdt++;
                //Sending stats on udp asynchronous socket
                if(send_eth_udp_stats_to_fpga(respBuf, respBufSz) < 0) {
                    perror ("send_stats_buffer_to_host()");
                    SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_stats_buffer_to_host()");
                }
                usleep(RPP_STATS_SLEEP);
            }// end of for loop for no of stations per radio
            free(stats);
            free(ethstats);
            free(respBuf);
        }//end of for loop
#endif //(#if ENABLE_STATS_FROM_ETHTOOL_LIB)
    }//end of while one loop

#if ENABLE_STATS_FROM_ETHTOOL_LIB
    free(ctx);
#endif
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->thread_get_stats_fun()_exit");
    return NULL;
}

/************************************************************************************
* Function Name    : rpp_trigger_11kv_roam
* Description      : This function is used to trigger 11k/v roaming for connected STA
*************************************************************************************/
void rpp_trigger_11kv_roam(int32_t radioIndex)
{
    uint8_t roamType = FT_ROAM_OVER_AIR;
    char ftcmd[RPP_APP_DEFNUM_SIX] = "\0";
    struct staInfo *stainfo = &staAssocHdl[radioIndex].staCountInfo[0];

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_trigger_11kv_roam_fun()_start");

    if (rppStaHandle.addStaReq[stainfo->staNum].fbtcfg.overds)
        roamType = FT_ROAM_OVER_DS;

    if (gSphyBandData[radioIndex].is11vEnable == true && gSphyBandData[radioIndex].is11vtriggered == false) {
        if (PROXY_STA[radioIndex]) {
            system_cmd_set_f("wpa_cli -i staX%d enable_kv_roam %d %u %d %u", radioIndex,
                                                                          gSphyBandData[radioIndex].scanThreshold,
                                                                          gSphyBandData[radioIndex].ftRoamThreshold,
                                                                          RSSI_THRESHOLD_FOR_11V,
                                                                          roamType);
            system_cmd_set_f("wpa_cli -i staX%d wnm_bss_query \"%d\"", radioIndex, WNM_REASON_LOW_RSSI);
        }
        for (uint8_t stationIndex = 0; stationIndex < staAssocHdl[radioIndex].staCount; stationIndex++, stainfo++) {
            if ((stainfo->assocStatus == STATE_ASSOCIATED) && (stainfo->phyHandle == radioIndex)) {
                system_cmd_set_f("wpa_cli -i sta%d enable_kv_roam %d %u %d %u", stainfo->staNum,
                                                                             gSphyBandData[radioIndex].scanThreshold,
                                                                             gSphyBandData[radioIndex].ftRoamThreshold,
                                                                             RSSI_THRESHOLD_FOR_11V,
                                                                             roamType);
                system_cmd_set_f("wpa_cli -i sta%d wnm_bss_query \"%d\"", radioIndex, WNM_REASON_LOW_RSSI);
                stainfo->is11vBTMtriggered = true;
                stainfo->staRoamTrigger = true;
                gSphyBandData[radioIndex].is11vtriggered = true;
            }
        }
    } else if (gSphyBandData[radioIndex].is11kEnable == true && gSphyBandData[radioIndex].is11ktriggered == false) {
        if (roamType == FT_ROAM_OVER_DS)
            strcpy(ftcmd, "ft_ds");
        else
            strcpy(ftcmd, "roam");
        if (PROXY_STA[radioIndex]) {
            system_cmd_set_f("wpa_cli -i staX%d enable_kv_roam %d %u %d %u", radioIndex,
                                                                          gSphyBandData[radioIndex].scanThreshold,
                                                                          gSphyBandData[radioIndex].ftRoamThreshold,
                                                                          RSSI_THRESHOLD_FOR_11K,
                                                                          roamType);
            system_cmd_set_f("wpa_cli -i staX%d %s %s", radioIndex, ftcmd, DEFAULT_WIFI_MAC_ID);
        }
        for (uint8_t stationIndex = 0; stationIndex < staAssocHdl[radioIndex].staCount; stationIndex++, stainfo++) {
            if ((stainfo->assocStatus == STATE_ASSOCIATED) && (stainfo->phyHandle == radioIndex)) {
                system_cmd_set_f("wpa_cli -i sta%d enable_kv_roam %d %u %d %u", stainfo->staNum,
                                                                             gSphyBandData[radioIndex].scanThreshold,
                                                                             gSphyBandData[radioIndex].ftRoamThreshold,
                                                                             RSSI_THRESHOLD_FOR_11K,
                                                                             roamType);
                system_cmd_set_f("wpa_cli -i sta%d %s %s", stainfo->staNum, ftcmd, DEFAULT_WIFI_MAC_ID);
                stainfo->staRoamTrigger = true;
                gSphyBandData[radioIndex].is11ktriggered = true;
            }
        }
    }
    gSphyBandData[radioIndex].roam11kv_trigger_time = time(NULL);

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_trigger_11kv_roam_fun()_exit");
}

/*****************************************************************************
* Function Name    : thread_sendKeepAlive
* Description      : This thread is used to notify the Host that rppslave is
*                    present in good health.
******************************************************************************/
void *thread_rpp_sendKeepAlive(void *p_threadData)
{
    int32_t ret = 0;
    static int32_t clearProbeCounter = 0;
    char buf[RPPMSG_KEEPALIVE_REQ_SZ + 128];
    int8_t radioIndex = 0;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->thread_rpp_sendKeepAlive_fun()_start");

    memset (buf, 0, RPPMSG_KEEPALIVE_REQ_SZ);
    RppMessageHead *msghdr = (RppMessageHead *)buf;
    msghdr->cat = RPP_MSG_REQ;
    msghdr->type = RPP_MSG_KEEPALIVE;
    msghdr->len = sizeof(KeepAlive);

    SYSLOG_PRINT(LOG_DEBUG, "keepalive Thread initiated and auto joined");
    keepAliveThread_created = true;

    while(1) {
        if(sendKeepAlive == true) {
            ret = send_eth_async_msgto_fpga(buf, sizeof (buf));
            sleep(RPP_KEEPALIVE_TIMER);
            clearProbeCounter++;
            if ( clearProbeCounter >= RPP_CLEARPROBE_TIMER) {
                probeProcess = true;
                cleanupProcess = true;

                /*Making the mpsta association trial radioIndex zero again, for trying the mpsta association again*/
                for (radioIndex = 0; radioIndex < RPP_NUM_OF_RADIO; radioIndex++){
                    if (PROXY_STA[radioIndex]){
                        if( RppProxyStaStatusHdl[radioIndex].mpsta_assoc_trial_count >= MPSTA_ASSOC_MAX_TRIAL) {
                            pthread_mutex_lock(&proxyStateLock[radioIndex]);
                            RppProxyStaStatusHdl[radioIndex].mpsta_assoc_trial_count = 0;
                            pthread_mutex_unlock(&proxyStateLock[radioIndex]);
                            SYSLOG_PRINT(LOG_DEBUG, "Resetting RppProxyStaStatusHdl.mpsta_assoc_trial_count for radio [%d] in keepalive Thread", radioIndex);
                        }
                    }
                }
                clearProbeCounter = 0;
            }
            if (ret < 0) {
                SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send keepalive notify message to rpp host failed.()");
            }
        }
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->thread_rpp_sendKeepAlive_fun()_exit");
}

/*****************************************************************************
* Function Name    : rpp_configure_max_txpower
* Description      : This thread is used to notify the Host about station
*                    state of association.
******************************************************************************/
int32_t rpp_configure_max_txpower(uint8_t staNum)
{
    char        tempBuf[8] = "\0";
    int32_t     rc = 0;
    int32_t     txMaxpwrVal = 0;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_configure_max_txpower_fun()_start");

    while(RPP_APP_DEFNUM_ONE) {
        if(setTxpowerInfo.assocStatus == STATE_ASSOCIATED) {
            sleep(2);
            rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwconfig sta%d | grep \"Tx-Power\" | cut -d \":\" -f 2 | cut -d \" \" -f 1", staNum);
            txMaxpwrVal = atoi(tempBuf);

            SYSLOG_PRINT(LOG_DEBUG,"\n DEBUG_MSG-------> max power value : %d\n", txMaxpwrVal);

            if (gTxpowerAttinution > txMaxpwrVal) {
                txMaxpwrVal = 0;
            } else {
                txMaxpwrVal -= gTxpowerAttinution;
            }

            /* To deassociate the station */
            system_cmd_set_f("ifconfig sta%d down", staNum);
            //wpa_cli -i athX disable_network 0
            system_cmd_set_f("wpa_cli -i sta%u disable_network 0", staNum);
            system_cmd_set_f("iwconfig sta%d txpower %d", staNum, txMaxpwrVal);
            system_cmd_set_f("ifconfig sta%d up", staNum);
            //wpa_cli -i athX enable_network 0
            system_cmd_set_f("wpa_cli -i sta%u enable_network 0", staNum);
            setTxpowerInfo.TxpowerStatus = RPP_APP_DEFNUM_ONE;
            break;
        }
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_configure_max_txpower_fun()_exit");
    return rc;
}


/******************************************************************************
 * Function Name    : rpp_ng_set_fixed_rate
 * Description      : This Function is used to set noise generator fixed rate
 ******************************************************************************/
void rpp_ng_set_fixed_rate(uint32_t phyhandle, uint8_t preambleType, char* intfName, uint8_t staNum)
{
    int32_t computedFixedRateVal = 0;
    uint16_t mcsVal;
    SetPhyReq *phyCfg = &addStaPhyData[phyhandle];
    if (!RPP_NG_ENABLE(phyCfg)) {
        return;
    }
    // Use vht mcs when protocol rate less than PROTO_AX
    mcsVal = preambleType<PROTO_AX?phyCfg->supportedvhtmcsset:phyCfg->supportedhemcsset;
    if (gen_fixed_rate_param(preambleType, phyCfg->cfgnss, mcsVal, &computedFixedRateVal) == RPP_APP_RET_SUCCESS) {
        system_cmd_set_f("iwpriv %s%d sta_fixed_rate 0x%x", intfName, staNum, computedFixedRateVal);
    } else {
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->generate noise generator sta fixed rate failed");
    }
}

/*****************************************************************************
* Function Name    : thread_staMonRadio
* Description      : This thread is used to notify the Host about station
*                    state of association.
******************************************************************************/
void *thread_staMonRadio(void *p_threadData)
{
    uint8_t     radioNum = 0;
    int32_t     stationIndex = 0;
    int32_t     radioIndex = 0;
    int32_t     associateState = 0;
    uint8_t     staState = 0,tempBuf[RPP_APP_BUFF_SIZE],tempstring[RPP_APP_BUFF_SIZE];
    int32_t     pre_state = 0;
    int32_t     curr_state = 0;
    bool        isRoamSuccess = false;
    int8_t         ret;
    StaStateInfo stateInfo = {0};
    struct staInfo *stainfo = NULL;
    uint32_t    assocStaErrCode = 0;
    radioNum = *((uint8_t *)p_threadData);
    radioIndex = radioNum;
    time_t currentTime = 0, rssiCheckTime = 0;
    uint8_t roamType = FT_ROAM_OVER_AIR;

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->thread_staMonRadio_fun()_start %d", radioNum);

    staAssocHdl[radioIndex].staCount = 0;
    staAssocHdl[radioIndex].pendingMsg = 0;
    stainfo = &staAssocHdl[radioIndex].staCountInfo[0];
    for (stationIndex = 0; stationIndex < RPP_MAX_STA_PER_RADIO; stationIndex++, stainfo++) {
        stainfo->assocStatus = STATE_ASSOCIATE_FAILED;
        stainfo->assocReqStatus = 0xff;
        stainfo->staStatus = RPP_STATE_STATION_NOTPRESENT;
        stainfo->deassocnotify = RPP_DEASSOC_NOTIFY_UNSET;
        stainfo->is11kNRRtriggered = false;
        stainfo->is11vBTMtriggered = false;
        stainfo->staRoamTrigger = false;
        stainfo->staRoamTrialCount = 0;
    }

    setTxpowerInfo.assocStatus = STATE_ASSOCIATE_FAILED;
    //setTxpowerInfo.TxpowerStatus = 0;//for making tx power setting disable
    setTxpowerInfo.TxpowerStatus = RPP_APP_DEFNUM_ONE;//for making tx power setting disable

    while(RPP_APP_DEFNUM_ONE) {
        /* 25 ms sleep */
        //usleep(RPP_ASSOC_TIMEOUT);
        sleep(RPP_ASSOC_TIMEOUT);
        if (PROXY_STA[radioNum]) {
            system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwpriv staX%d g_sta_state", radioNum);
            sscanf (tempBuf, "%22c%hhu", tempstring,(uint8_t *)&staState);
            curr_state = staState;
            if (staState == RPP_STA_ASSOC_STATE) {
                pre_state = staState;
            } else {
                if (pre_state == RPP_STA_ASSOC_STATE && curr_state != RPP_STA_ASSOC_STATE) {
                    SYSLOG_PRINT(LOG_DEBUG,"\n**Removing proxy station *****for Radio [%d]**in notificatioon thread*",
                        radioNum);
                    /* To deassociate the main proxy station */
                    rpp_dissociation_process(radioNum, "staX", radioNum);
                    pre_state = curr_state;

                }
                stainfo = &staAssocHdl[radioNum].staCountInfo[0];
                for (stationIndex = 0; stationIndex < staAssocHdl[radioNum].staCount; stationIndex++, stainfo++) {
                    if ((stainfo->assocStatus == STATE_ASSOCIATED) && (stainfo->phyHandle == radioNum)) {
                        /* To deassociate the regular associated station *//*TOCHECK phyHandle = staNum*/
                        rpp_dissociation_process(stainfo->phyHandle, "sta", stainfo->staNum);
		    }
                }/* End of inside for loop */
             }/* End of inside for if loop */
        }

        stainfo = &staAssocHdl[radioNum].staCountInfo[0];
        for(stationIndex = 0; stationIndex < staAssocHdl[radioNum].staCount; stationIndex++, stainfo++) {
            /* The staCount can change by msgParser thread (add/delete station request),
            but it doesn't have an effect because this loop will check staStatus and assocReqStatus */
            pthread_mutex_lock( &assocStatLock[radioNum]);
            if(staAssocHdl[radioNum].pendingMsg==1) {
                // Found pending message in message parser thread, release assocStaLock and yield process to message parser thread to work
                pthread_mutex_unlock( &assocStatLock[radioNum] );
                stationIndex--;
                stainfo--;
                sched_yield();
                continue;
            }

            if (stainfo->staStatus == RPP_STATE_STATION_PRESENT) {
                if (stainfo->assocReqStatus == RPP_SET_ASOCIATE_REQSTATE) {
                    ret = get_sta_state(&stateInfo, radioNum, "sta", stainfo->staNum);
                    staState = (ret == 0 && stateInfo.assocStatus == STATE_ASSOCIATED) ? RPP_STA_ASSOC_STATE : 0;
                    if (staState == RPP_STA_ASSOC_STATE) {
                        associateState = STATE_ASSOCIATED;
                        memset(stainfo->apbssid, 0, sizeof(uint8_t) * ETHER_MAC_ADDR_LEN);
                        /* Compute the mac address of the associated AP */
                        memcpy (stainfo->apbssid, stateInfo.bssid, sizeof(uint8_t) * ETHER_MAC_ADDR_LEN);
                        if ((stainfo->staRoamTrigger == true) && (memcmp(stainfo->apbssid, gPrevAPbssid[stainfo->staHandle].mac_address, sizeof(uint8_t) * ETHER_MAC_ADDR_LEN) != 0)) {
                            SYSLOG_PRINT(LOG_DEBUG, "STA%u Successfully roamed \n", stainfo->staNum);
                            gSphyBandData[stainfo->phyHandle].is11ktriggered = false;
                            gSphyBandData[stainfo->phyHandle].is11vtriggered = false;
                            isRoamSuccess = true;
                        }
                    } else {
                        associateState = STATE_ASSOCIATE_FAILED;
                    }

                    if ((stainfo->is11kNRRtriggered == true) || (stainfo->is11vBTMtriggered == true)) {
                        /* Incase of 11v roaming: BTM Request is sent by AP after BTM Query is triggered by STA.Hence add a delay of 2s after Query is triggered
                         *                        to get valid Neighbor info from BTM request.
                         * Incase of 11k roaming: Neighbor request is sent by STA after assoc and reassoc.Fetch the neighbor report sent by AP to STA
                         *                        2s after the roaming is triggered so that roaming will be completed.
                         */
                        currentTime = time(NULL);
                        if (currentTime - gSphyBandData[stainfo->phyHandle].roam11kv_trigger_time >= 2) { /* Delay of 2sec added to get the valid updated neighbor report */
                            ret = rpp_get_neighbor_report(stainfo->phyHandle, stainfo->staNum);
                            if (ret >= 0) {
                                SYSLOG_PRINT(LOG_DEBUG, "Neighbor report sent successfully to wlanmgr\n");
                                gSphyBandData[stainfo->phyHandle].roam11kv_trigger_time = 0;
                            }
                            stainfo->is11kNRRtriggered = false;
                            stainfo->is11vBTMtriggered = false;
                        }
                    }

                    if ((stainfo->assocStatus != associateState) || (stainfo->staRoamTrigger == true)) {
                        stainfo->assocStatus = associateState;
                        if (associateState == STATE_ASSOCIATED) {
                            if (stainfo->staRoamTrigger == true) {
                                if (isRoamSuccess == true) {
                                    isRoamSuccess = false;
                                    memset(stainfo->targetApbssid, 0, sizeof(uint8_t) * ETHER_MAC_ADDR_LEN);
                                    SYSLOG_PRINT(LOG_DEBUG, "Associated station after roaming at phyHandle %d = %d",
                                                               stainfo->phyHandle,
                                                               staAssocHdl[stainfo->phyHandle].associated_stations_per_radio);
                                    if ((gSphyBandData[stainfo->phyHandle].is11kEnable == true) && (stainfo->is11kNRRtriggered == false)) {
                                        system_cmd_set_f("wpa_cli -i sta%u neighbor_rep_request", stainfo->staNum);
                                        stainfo->is11kNRRtriggered = true;
                                    }
                                    stainfo->staRoamTrigger = false;
                                    stainfo->staRoamTrialCount = 0;
                                    rpp_send_assocstate(stainfo, STATE_ASSOCIATED, ASSOC_STATE_NOTIFICATION_SUCCESS);
                                } else {
                                    /* Once FT roaming is triggered, check if the roaming status for a maximum of 5 times
                                     * If roaming status is still fail after checking for the 5th time, then send the roaming fail notification
                                     */
                                    stainfo->staRoamTrialCount++;
                                    if (stainfo->staRoamTrialCount >= MAX_FT_ROAM_FAIL_COUNT) {
                                        SYSLOG_PRINT(LOG_ERR, "STA%u roaming failed, associated stations at phyHandle %d = %d",
                                                                   stainfo->staNum,
                                                                   stainfo->phyHandle,
                                                                   staAssocHdl[stainfo->phyHandle].associated_stations_per_radio);
                                        rpp_send_assocstate(stainfo, STATE_ASSOCIATED, ASSOC_STATE_NOTIFICATION_FTROAM_TIMEOUT);
                                        stainfo->staRoamTrialCount = 0;
                                        stainfo->staRoamTrigger = false;
                                    }
                                }
                            } else {
                                 staAssocHdl[stainfo->phyHandle].associated_stations_per_radio++;
                                 SYSLOG_PRINT(LOG_DEBUG, "Associated station at phyHandle %d = %d",
                                                             stainfo->phyHandle,
                                                             staAssocHdl[stainfo->phyHandle].associated_stations_per_radio);
                                 if ((gSphyBandData[stainfo->phyHandle].is11kEnable == true) && (stainfo->is11kNRRtriggered == false)) {
                                     //Enable roam is needed to pass to supplicant for neighbor report
                                    if (rppStaHandle.addStaReq[stainfo->staNum].fbtcfg.overds)
                                        roamType = FT_ROAM_OVER_DS;
                                    else
                                        roamType = FT_ROAM_OVER_AIR;
                                    system_cmd_set_f("wpa_cli -i sta%d enable_kv_roam %d %u %d %u", stainfo->staNum,
                                                                             gSphyBandData[stainfo->phyHandle].scanThreshold,
                                                                             gSphyBandData[stainfo->phyHandle].ftRoamThreshold,
                                                                             RSSI_THRESHOLD_FOR_11K,
                                                                             roamType);
                                     system_cmd_set_f("wpa_cli -i sta%u neighbor_rep_request", stainfo->staNum);
                                     stainfo->is11kNRRtriggered = true;
                                 }
                                 rpp_send_assocstate(stainfo, STATE_ASSOCIATED, ASSOC_STATE_NOTIFICATION_SUCCESS);
                            }
                            // Noise generator, set sta fixed rate after associated
                            rpp_ng_set_fixed_rate(radioNum, stainfo->preambleType, "sta", stainfo->staNum);
                        } else if ( associateState == STATE_ASSOCIATE_FAILED ) {
                            /* In get assoc fail reasonCode s updated from previously fetched stateInfo taken from wpa_cli -ista<num> STATUS */
                            assocStaErrCode = rpp_map_assoc_sta_errcode(stateInfo.reasonCode);
                            rpp_send_assocstate(stainfo, associateState, assocStaErrCode);
                            staAssocHdl[stainfo->phyHandle].associated_stations_per_radio--;
                            SYSLOG_PRINT(LOG_DEBUG, "Associated station at phyHandle %d = %d",
                                                             stainfo->phyHandle,
                                                             staAssocHdl[stainfo->phyHandle].associated_stations_per_radio);
                       
                            if (staAssocHdl[stainfo->phyHandle].associated_stations_per_radio == 0) {
                                gSphyBandData[stainfo->phyHandle].is11vtriggered = false;
                                gSphyBandData[stainfo->phyHandle].is11ktriggered = false;
                                if (PROXY_STA[radioNum]) {
                                    /*Dissociating the proxy station when all regular stations are already dissociated*/
                                    rpp_dissociation_process(stainfo->phyHandle, "staX", stainfo->phyHandle);
                                    pthread_mutex_lock(&proxyStateLock[stainfo->phyHandle]);
                                    RppProxyStaStatusHdl[stainfo->phyHandle].proxy_sta_assoc = false;
                                    pthread_mutex_unlock(&proxyStateLock[stainfo->phyHandle]);
                                }
                            }
                        }
                    }
                } else if (stainfo->assocReqStatus == RPP_UNSET_ASOCIATE_REQSTATE) {
                      if ((stainfo->deassocnotify != RPP_DEASSOC_NOTIFY_SET) && (stainfo->assocStatus == STATE_ASSOCIATED)) {
                        stainfo->assocStatus = STATE_ASSOCIATE_FAILED;
                        stainfo->deassocnotify = RPP_DEASSOC_NOTIFY_SET;
                        associateState = STATE_ASSOCIATE_FAILED;
                        rpp_send_assocstate(stainfo, associateState, ASSOC_STATE_NOTIFICATION_SUCCESS);
                        staAssocHdl[stainfo->phyHandle].associated_stations_per_radio--;
                        SYSLOG_PRINT(LOG_DEBUG, "Associated station at phyHandle %d = %d", stainfo->phyHandle, staAssocHdl[stainfo->phyHandle].associated_stations_per_radio);
                        if (staAssocHdl[stainfo->phyHandle].associated_stations_per_radio == 0) {
                            gSphyBandData[stainfo->phyHandle].is11vtriggered = false;
                            gSphyBandData[stainfo->phyHandle].is11ktriggered = false;
                            if (PROXY_STA[radioNum]) {
                                /*Dissociating the proxy station when all regular stations are already dissociated*/
                                rpp_dissociation_process(stainfo->phyHandle, "staX", stainfo->phyHandle);
                                pthread_mutex_lock(&proxyStateLock[stainfo->phyHandle]);
                                RppProxyStaStatusHdl[stainfo->phyHandle].proxy_sta_assoc = false;
                                pthread_mutex_unlock(&proxyStateLock[stainfo->phyHandle]);
                            }
                        }
                    }
                }  // end of assocreqstate
            }//end of outer if station not present
           pthread_mutex_unlock( &assocStatLock[radioNum] );
        }/* End of inner for loop */

        if (staAssocHdl[radioIndex].associated_stations_per_radio == 0)
            continue;

        if ((gSphyBandData[radioIndex].is11vEnable == true && gSphyBandData[radioIndex].is11vtriggered == false) || 
            (gSphyBandData[radioIndex].is11kEnable == true && gSphyBandData[radioIndex].is11ktriggered == false)) {
           currentTime = time(NULL);
           if (currentTime - rssiCheckTime <= 1) /*Time b/n consecutive RSSI checks is kept to be checked every 1 second since RSSI is updated from Stats for every 2 seconds*/
               continue;
           rssiCheckTime = time(NULL);
           if (gSphyBandData[radioIndex].rssi <= gSphyBandData[radioIndex].scanThreshold) {
               rpp_trigger_11kv_roam(radioNum);
           }
        }
    }// end of while
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->thread_staMonradio_fun()_exit %d",radioNum);
    return NULL;
}

/******************************************************************************
 * Function Name    : rpp_slave_probe_req
 * Description      : This Function is used to frame probe message and send it
 *                    to FPGA.
 ******************************************************************************/
int32_t rpp_slave_probe_req(void)
{
    char    tempBuf[RPP_APP_BUFF_SIZE] = "\0";
    char    respBuf[RPPMSG_PROB_RESP_SZ];
    int32_t ret = 0;
    pthread_t   keepAliveThread;
    int8_t noOfIntf = 0;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_slave_probe_fun()_start");

    SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_Debug");

    if( probeProcess == false) {
        SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->No need to process the probe again.");
        return ret;
    }

    RppMessageHead *msghdr = (RppMessageHead *) respBuf;
    msghdr->cat = RPP_MSG_RESP;
    msghdr->type = RPP_MSG_PROB_RESP;
    msghdr->len = sizeof(ProbeResp);
    ProbeResp *resp = (ProbeResp *)msghdr->body;
    resp->handle = 0; //mId;
    /*Hardware version will be read from the FPGA registers, Curretly
    sending the dummy value.*/
    resp->hwver = 0x1234;

    pthread_mutex_lock( &staProcessLock );
    /*Software version , reading from the /etc/ipq_image_version file*/
    ret = system_cmd_get_f(tempBuf, sizeof(tempBuf), "cat /etc/ipq_image_version | cut -d \".\" -f 1 | cut -d \" \" -f 2");
    resp->swver = (atoi(tempBuf) << 16);
    ret = system_cmd_get_f(tempBuf, sizeof(tempBuf), "cat /etc/ipq_image_version | cut -d \".\" -f 2");
    resp->swver = resp->swver | atoi(tempBuf);
    SYSLOG_PRINT(LOG_DEBUG,"\n**********************************************************");
    SYSLOG_PRINT(LOG_DEBUG,"\n RPPSLAVE Software Version  = %u.%u", ((resp->swver >> 16) & 0xFFFF), resp->swver & 0xFFFF);
    SYSLOG_PRINT(LOG_DEBUG,"\n**********************************************************\n");
    pthread_mutex_unlock( &staProcessLock );

    SYSLOG_PRINT(LOG_DEBUG," \n rppslave with ax command enabled.\n");

    /*Checking for old Session data clearance.*/
    ret = rpp_session_cleanup();
    if (ret != 0) {
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->failed to clear old session data");
        return -1;
    }

    /*initializing two client socket for sending message to host*/
    ret = init_eth_comm();
    if (ret != 0) {
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->failed to initializing sockets");
        return -1;
    }

    /*Creation of pthread for sending keep alive notification to host.*/
    if((sendKeepAlive == true) && (keepAliveThread_created == false)) {
        printf("\n Keep alive option is enabled, starting thread to send notification. \n");
        ret = pthread_create(&keepAliveThread, NULL,
                             thread_rpp_sendKeepAlive, NULL);
        if (ret != 0) {
            return -1;
        }
    }

    /*making probProcess flag false , so that it will not process the duplicate probes*/
    probeProcess = false;

    /* create dummy station interface to see driver/fw in working state and not crash/asserted*/
    system_cmd_set_f("wlanconfig ath0 create wlandev wifi0 wlanmode sta -bssid %s", DEFAULT_WIFI_MAC_ID);
    ret = system_cmd_get_f(tempBuf, sizeof(tempBuf), "ifconfig -a | grep ath0 | wc -l");
    noOfIntf = atoi(tempBuf);

    /*Send probe response only if interface is getting created */
    if (noOfIntf > 0)
    { 
       /* Delete the particular station number obtained from the api */
        system_cmd_set_f("wlanconfig ath0 destroy");
 
        /* Send the response to the FPGA */
        ret = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
        if (ret < 0) {
           perror ("send_eth_msgto_fpga()");
           SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
        }
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_slave_probe_fun()_exit");
    return ret;
}

/******************************************************************************
 * Function Name    : rpp_calculate_errcode
 * Description      : This Function is used to calculate the error code
 ******************************************************************************/
int32_t rpp_calculate_errcode(int32_t errCode, char *cmdOutput,
                            int32_t respOpt)
{
    int32_t rc = 0;
    int32_t cmdOpt = 0;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_calculate_errcode_fun()_start");

    switch (respOpt) {
        case RPP_MSG_GETPHY_REQ:
            /* Need to implement PHY NOT READY case */
            if (errCode != RPP_APP_RET_SUCCESS) {
                if (cmdOutput == NULL) {
                    rc = GET_PHY_NOT_FOUND;
                } else {
                    if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                        rc = GET_PHY_NOT_FOUND;
                    } else {
                        rc = GET_PHY_OTHERS;
                    }
                }
            } else {
                rc = RPP_APP_RET_SUCCESS;
            }
            break;

        case RPP_MSG_SETPHY_REQ:
            if (errCode != RPP_APP_RET_SUCCESS) {
                switch (cmdOpt) {
                    case PHY_INTF_CFG_REGULATORY_NOT_SUPPORTED:
                        if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                            rc = PHY_INTF_CFG_REGULATORY_NOT_SUPPORTED;
                        } else {
                            rc = PHY_INTF_CFG_UNDEFINED_ERROR;
                        }
                        break;
                    case PHY_INTF_CFG_FREQUENCY_NOT_SUPPORTED:
                        if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                            rc = PHY_INTF_CFG_FREQUENCY_NOT_SUPPORTED;
                        } else {
                            rc = PHY_INTF_CFG_UNDEFINED_ERROR;
                        }
                        break;
                    case PHY_INTF_CFG_SPATIAL_STREAM_NOT_SUPPORTED:
                        if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                            rc = PHY_INTF_CFG_SPATIAL_STREAM_NOT_SUPPORTED;
                        } else {
                            rc = PHY_INTF_CFG_UNDEFINED_ERROR;
                        }
                        break;
                    case PHY_INTF_CFG_RATE_SETTING_NOT_SUPPORTED:
                        if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                            rc = PHY_INTF_CFG_RATE_SETTING_NOT_SUPPORTED;
                        } else {
                            rc = PHY_INTF_CFG_UNDEFINED_ERROR;
                        }
                        break;
                    case PHY_INTF_CFG_HTMCS_SETTING_NOT_SUPPORTED:
                        if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                            rc = PHY_INTF_CFG_HTMCS_SETTING_NOT_SUPPORTED;
                        } else {
                            rc = PHY_INTF_CFG_UNDEFINED_ERROR;
                        }
                        break;
                    case PHY_INTF_CFG_VHTMCS_SETTING_NOT_SUPPORTED:
                        if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                            rc = PHY_INTF_CFG_VHTMCS_SETTING_NOT_SUPPORTED;
                        } else {
                            rc = PHY_INTF_CFG_UNDEFINED_ERROR;
                        }
                        break;
                    case PHY_INTF_CFG_AMSDU_DEPTH_NOT_SUPPORTED:
                        if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                            rc = PHY_INTF_CFG_AMSDU_DEPTH_NOT_SUPPORTED;
                        } else {
                            rc = PHY_INTF_CFG_UNDEFINED_ERROR;
                        }
                        break;
                    case PHY_INTF_CFG_AMPDU_DEPTH_NOT_SUPPORTED:
                        if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                            rc = PHY_INTF_CFG_AMPDU_DEPTH_NOT_SUPPORTED;
                        } else {
                            rc = PHY_INTF_CFG_UNDEFINED_ERROR;
                        }
                        break;
                }
            } else {
                rc = RPP_APP_RET_SUCCESS;
            }
            break;
        case RPP_MSG_ADDSTA_REQ:
            if (errCode != RPP_APP_RET_SUCCESS) {
               switch (cmdOpt) {
                    case ADD_STATION_INVALID_MAC:
                        if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                            rc = ADD_STATION_INVALID_MAC;
                        } else {
                            rc = ADD_STATION_UNDEFINED_ERROR;
                        }
                        break;
                    case ADD_STATION_INVALID_SSID:
                        if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                            rc = ADD_STATION_INVALID_SSID;
                        } else {
                            rc = ADD_STATION_UNDEFINED_ERROR;
                        }
                        break;
                    case ADD_STATION_INVALID_BSSID:
                        if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                            rc = ADD_STATION_INVALID_BSSID;
                        } else {
                            rc = ADD_STATION_UNDEFINED_ERROR;
                        }
                        break;
                    case ADD_STATION_INVALID_EXTRA_DATA_LEN:
                        if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                            rc = ADD_STATION_INVALID_EXTRA_DATA_LEN;
                        } else {
                            rc = ADD_STATION_UNDEFINED_ERROR;
                        }
                        break;
                    case ADD_STATION_HTMCS_SETTING_NOT_SUPPORTED:
                        if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                            rc = ADD_STATION_HTMCS_SETTING_NOT_SUPPORTED;
                        } else {
                            rc = ADD_STATION_UNDEFINED_ERROR;
                        }
                        break;
                    case ADD_STATION_VHTMCS_SETTING_NOT_SUPPORTED:
                        if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                            rc = ADD_STATION_VHTMCS_SETTING_NOT_SUPPORTED;
                        } else {
                            rc = ADD_STATION_UNDEFINED_ERROR;
                        }
                        break;
                    case ADD_STATION_AMSDU_DEPTH_NOT_SUPPORTED:
                        if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                            rc = ADD_STATION_AMSDU_DEPTH_NOT_SUPPORTED;
                        } else {
                            rc = ADD_STATION_UNDEFINED_ERROR;
                        }
                        break;
                    case ADD_STATION_AMPDU_DEPTH_NOT_SUPPORTED:
                        if (errCode != RPP_APP_RET_COMMAND_FAILED) {
                            rc = ADD_STATION_AMPDU_DEPTH_NOT_SUPPORTED;
                        } else {
                            rc = ADD_STATION_UNDEFINED_ERROR;
                        }
                        break;
                }
            } else {
                rc = RPP_APP_RET_SUCCESS;
            }
            break;
        case RPP_MSG_DELSTA_REQ:
            if (errCode != RPP_APP_RET_SUCCESS) {
            } else {
                rc = RPP_APP_RET_SUCCESS;
            }
            break;
        case RPP_MSG_SCAN_REQ:
            if (errCode != RPP_APP_RET_SUCCESS) {
            } else {
                rc = RPP_APP_RET_SUCCESS;
            }
            break;
        case RPP_MSG_ASSOC_REQ:
           if (errCode != RPP_APP_RET_SUCCESS) {
            } else {
                rc = RPP_APP_RET_SUCCESS;
            }
             break;
        case RPP_MSG_DEASSOC_REQ:
           if (errCode != RPP_APP_RET_SUCCESS) {
            } else {
                rc = RPP_APP_RET_SUCCESS;
            }
             break;
        case RPP_MSG_FBT_REQ:
           if (errCode != RPP_APP_RET_SUCCESS) {
            } else {
                rc = RPP_APP_RET_SUCCESS;
            }
             break;
        case RPP_MSG_SETMODE_REQ:
            if (errCode != RPP_APP_RET_SUCCESS) {
            } else {
                rc = RPP_APP_RET_SUCCESS;
            }
            break;
        case RPP_MSG_CLRSTATS_REQ:
           if (errCode != RPP_APP_RET_SUCCESS) {
            } else {
                rc = RPP_APP_RET_SUCCESS;
            }
             break;
        case RPP_MSG_SETLOG_REQ:
           if (errCode != RPP_APP_RET_SUCCESS) {
            } else {
                rc = RPP_APP_RET_SUCCESS;
            }
             break;
        default :
            break;
    }

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_calculate_errcode_fun()_exit");
    return rc;
}

/******************************************************************************
 * Function Name    : rpp_calculate_chwidth
 * Description      : This Function is used to calculate channel width of the radio
 ******************************************************************************/
bool rpp_calculate_chwidth(uint32_t handle, uint32_t flags)
{
    bool setChWidth = false;
    int32_t computedFlagsVal = 0;
    uint8_t bitPos = 0;

    for (bitPos = RPP_APP_DEFNUM_FOUR; bitPos > 0; bitPos--) {
        computedFlagsVal = (flags >> bitPos) & RPP_APP_DEFNUM_ONE;
        if(computedFlagsVal) {
            /* Getting Channel Width */
            gSphyBandData[handle].chwidth = (bitPos - RPP_APP_DEFNUM_ONE);
            setChWidth = true;
            break;
        } else {
	    continue;
        }
    }
    return setChWidth;
}
/******************************************************************************
 * Function Name    : rpp_get_phy_req
 * Description      : This Function is used to get the phy(radio) information
 *                    and send it to FPGA.
 ******************************************************************************/
int32_t rpp_get_phy_req (void)
{
    char    tempBuf[RPP_APP_BUFF_SIZE] = "\0";
    char    *set_phy_mode_ht = NULL;
    char    *set_phy_mode_vht = NULL;
    char    *set_phy_mode_he = NULL;
    int32_t noOfPhy = 0;
    int32_t radioIndex = 0;
    int32_t rc = 0;
    int32_t freqValue = 0;
    int32_t low_he = 0;
    int32_t high_he = 0;
    int32_t he_index = 0;
    int32_t tempRadioIndex =  0;

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_get_phy_fun()_start");

    /*Making the probeProcess flag true , so that rppslave will be ready to process probe again*/
    probeProcess = true;
    cleanupProcess = true;

    // ifconfig -a |grep wifi |wc -l
    rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "ifconfig -a | grep wifi | wc -l");
    noOfPhy = atoi(tempBuf);

    char respBuf[RPPMSG_GETPHY_RESP_SZ + sizeof(PhyIntfDesc)*noOfPhy];

    memset (respBuf, 0, sizeof (respBuf));
    RppMessageHead *msghdr = (RppMessageHead *) respBuf;
    msghdr->len = sizeof(GetPhyResp) + sizeof(PhyIntfDesc)*noOfPhy;
    msghdr->cat = RPP_MSG_RESP;
    msghdr->type = RPP_MSG_GETPHY_RESP;
    GetPhyResp *resp = (GetPhyResp*)msghdr->body;
    resp->nbrofphys = noOfPhy;
    resp->errcode = GET_PHY_SUCCESS;
    PhyIntfDesc *phys = (PhyIntfDesc *)resp->phys;

    for (radioIndex = 0; radioIndex < noOfPhy; radioIndex++) {
        tempRadioIndex = radioIndex;
        if (IS_THREE_RADIO_PROFILE) {
            if(radioIndex == 1)
                tempRadioIndex = 2;
            else if(radioIndex == 2)
                tempRadioIndex = 1;
        }
        //wlanconfig ath0 create wlandev wifi0 wlanmode sta
        system_cmd_set_f("wlanconfig staX%d create wlandev wifi%d wlanmode sta ", radioIndex, radioIndex);

         /* Up the particular interface before quering */
        system_cmd_set_f("ifconfig staX%d up", radioIndex);

        /*wpa_supplicant to be started for running wpa_cli commands*/
        //wpa_supplicant -D athr -B -g/tmp/global0 -P /var/run/global0.pid -f /tmp/global0.log
        system_cmd_set_f("wpa_supplicant -D athr -B -g/tmp/global%d -P /var/run/global%d.pid -f /tmp/global%d.log", radioIndex, radioIndex, radioIndex);

        // Open wpa control interface connection
        pthread_mutex_lock( &staAssocHdl[radioIndex].wpaCtrlLock);
        open_wpa_ctrl_conn(radioIndex);
        pthread_mutex_unlock( &staAssocHdl[radioIndex].wpaCtrlLock);

        /* Populate the phy number(0- 1st phy, 1- 2nd phy */
        phys[radioIndex].handle = radioIndex;

        /* Find supported band(for 2.4 GHz is is 0 and for 5 GHz it is 1) */
        rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwconfig staX%d | grep \"Frequency:\" | cut -d \":\" -f 3 | cut -d \" \" -f 1",radioIndex);
        freqValue = atof(tempBuf) * 1000;
        if (freqValue >= 2000 && freqValue < 3000) {
            phys[tempRadioIndex].supportedbands = FREQBAND_2_4_GHz;
            gSphyBandData[radioIndex].freqband = FREQ_BAND_2_4_GHZ;
        } else if (freqValue >= 5000 && freqValue < 5925) {
            phys[tempRadioIndex].supportedbands = FREQBAND_5_0_GHz;
            gSphyBandData[radioIndex].freqband = FREQ_BAND_5_0_GHZ;
        } else if (freqValue >= 5925 && freqValue <= 7125) {
            phys[tempRadioIndex].supportedbands = FREQBAND_6_0_GHz;
            gSphyBandData[radioIndex].freqband = FREQ_BAND_6_0_GHZ;
        } else {
            gSphyBandData[radioIndex].freqband = FREQ_BAND_AUTO;
            SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->staX%d invalid supported band for frequency: %d MHz (string: %s)", radioIndex, freqValue, tempBuf);
            continue;
        }
        SYSLOG_PRINT(LOG_DEBUG,"\nDEBUG_MSG------->staX%d supported band = %d", radioIndex, phys[tempRadioIndex].supportedbands);

        /* Find capabilities(i.e HtCapabilities) */
        set_phy_mode_ht = NULL;
        set_phy_mode_vht = NULL;
        set_phy_mode_he = NULL;
        rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwpriv staX%u %s", radioIndex, GET_PHY_MODE);
        if (phys[tempRadioIndex].supportedbands == FREQBAND_5_0_GHz) {
            if ((strstr(tempBuf,"AUTO") != NULL) || (strstr(tempBuf,"11A") != NULL)) {
                set_phy_mode_ht = "11NAHT40";
                if (IS_THREE_RADIO_PROFILE) {
                    set_phy_mode_vht = "11ACVHT80";
                    set_phy_mode_he = " 11AHE80";  //for 3-radio, 4X4 is supported
                } else {
                    set_phy_mode_vht = "11ACVHT160";
                    set_phy_mode_he = " 11AHE80_80";
                }
                he_index = RPP_APP_DEFNUM_ONE;
            }
        } else if (phys[tempRadioIndex].supportedbands == FREQBAND_2_4_GHz) {
            if ((strstr(tempBuf,"AUTO") != NULL) || (strstr(tempBuf,"11B") != NULL)) {
                set_phy_mode_ht = "11NGHT40";
                set_phy_mode_he = "11GHE40";
                he_index = 0;
            }
        } else if (phys[tempRadioIndex].supportedbands == FREQBAND_6_0_GHz) {
            if ((strstr(tempBuf,"AUTO") != NULL) || (strstr(tempBuf,"11A") != NULL)) {
                /* The wlanmgrd is no more use the capability, skip phy capability for 6 GHz radio */
                // set_phy_mode_he = AUTO_PHY_6G;
                // he_index = RPP_APP_DEFNUM_TWO;
            }
        }

        // HT capability
        if (set_phy_mode_ht != NULL) {
            system_cmd_set_f("iwpriv staX%d mode %s", radioIndex, set_phy_mode_ht);
            rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwpriv staX%d get_mode", radioIndex);
            //SYSLOG_PRINT(LOG_DEBUG, "Mode : %s\n",tempBuf);

            /* Find capabilities(i.e VhtCapabilities) */
            rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwpriv staX%d %s", radioIndex, GET_PHY_HTCAP);
            sscanf (tempBuf, "%hd", (uint16_t *)&phys[tempRadioIndex].htcap[he_index]);

            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->phys[%d].htcap[0] = 0x%x", radioIndex, phys[tempRadioIndex].htcap[0]);
            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->phys[%d].htcap[RPP_APP_DEFNUM_ONE] = 0x%x", radioIndex, phys[tempRadioIndex].htcap[RPP_APP_DEFNUM_ONE]);
        }

        // VHT capability
        if (set_phy_mode_vht != NULL) {
            system_cmd_set_f("iwpriv staX%d mode %s", radioIndex, set_phy_mode_vht);
            rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwpriv staX%d get_mode", radioIndex);
            rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwpriv staX%u %s", radioIndex, GET_PHY_VHTCAP);
            sscanf (tempBuf, "%x", &phys[tempRadioIndex].vhtcap[he_index]);

            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->phys[%d].vhtcap[0] = 0x%x", radioIndex,
                phys[tempRadioIndex].vhtcap[0]);
            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->phys[%d].vhtcap[RPP_APP_DEFNUM_ONE] = 0x%x", radioIndex,
                phys[tempRadioIndex].vhtcap[RPP_APP_DEFNUM_ONE]);
        }

        // HE capability
        if (set_phy_mode_he) {
            system_cmd_set_f("iwpriv staX%d mode %s", radioIndex, set_phy_mode_he);
            rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwpriv staX%d get_mode", radioIndex);
            //SYSLOG_PRINT(LOG_DEBUG, "Mode : %s\n",tempBuf);

            /*Getting HeMac capabilities*/
            rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwpriv staX%u g_hemac_low | grep \"g_hemac_low\" | cut -d \":\" -f 2", radioIndex);
            low_he = atoi(tempBuf);

            rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwpriv staX%u g_hemac_high | grep \"g_hemac_high\" | cut -d \":\" -f 2", radioIndex);
            high_he = atoi(tempBuf);
            /*TODO what are we doing with the high bit */

            phys[tempRadioIndex].hemaccap[he_index] = ((phys[tempRadioIndex].hemaccap[he_index] << 32) | low_he);

            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->phys[%d].hemaccap[0] = 0x%lx", radioIndex,
                phys[tempRadioIndex].hemaccap[0]);
            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->phys[%d].hemaccap[RPP_APP_DEFNUM_ONE] = 0x%lx", radioIndex,
                phys[tempRadioIndex].hemaccap[RPP_APP_DEFNUM_ONE]);

            /*Getting HePhy capabilities*/
            rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwpriv staX%u g_hephy_0 | grep \"g_hephy_0\" | cut -d \":\" -f 2", radioIndex);
            low_he = atoi(tempBuf);

            rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwpriv staX%d g_hephy_1 | grep \"g_hephy_1\" | cut -d \":\" -f 2", radioIndex);
            high_he = atoi(tempBuf);

            phys[tempRadioIndex].hephycaplow[he_index] = high_he;
            phys[tempRadioIndex].hephycaplow[he_index] = ((phys[tempRadioIndex].hephycaplow[he_index] << 32) | low_he);

            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->phys[%d].hephycaplow[0] = 0x%lx", radioIndex,
                phys[tempRadioIndex].hephycaplow[0]);
            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->phys[%d].hephycaplow[RPP_APP_DEFNUM_ONE] = 0x%lx", radioIndex,
                phys[tempRadioIndex].hephycaplow[RPP_APP_DEFNUM_ONE]);

            rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwpriv staX%u g_hephy_2 | grep \"g_hephy_2\" | cut -d \":\" -f 2", radioIndex);
            low_he = atoi(tempBuf);

            phys[tempRadioIndex].hephycaphigh[he_index] = low_he;

            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->phys[%d].hephycaphigh[0] = 0x%lx", radioIndex,
                phys[tempRadioIndex].hephycaphigh[0]);
            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->phys[%d].hephycaphigh[RPP_APP_DEFNUM_ONE] = 0x%lx", radioIndex,
                phys[tempRadioIndex].hephycaphigh[RPP_APP_DEFNUM_ONE]);
        }

        /* Find max number of spatial streams(MaxNSS) supported  */
        //iwpriv ath0 get_nss |grep "get_nss" | cut -d  ":" -f 2
        rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwpriv staX%d %s", radioIndex, GET_PHY_MAXNSS);
        phys[tempRadioIndex].maxnss = atoi(tempBuf);

        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->phys[%d].maxnss = 0x%x", radioIndex, phys[tempRadioIndex].maxnss);

        /* Find max number of stations supported */
        //iwpriv ath0 g_max_sta |grep \"g_max_sta\" | cut -d  \":\" -f 2
        rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "%s%u %s", GET_PHY_APPEND_MAXSTACMD, radioIndex, GET_PHY_NUM_OF_STA);
        phys[tempRadioIndex].maxsta = atoi(tempBuf);

        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->phys[%d].maxsta = %d", radioIndex, phys[tempRadioIndex].maxsta);
        if (IS_THREE_RADIO_PROFILE) {
            gPhyHandle[radioIndex]=phys[radioIndex].handle;
        } else {
            gPhyHandle[radioIndex] = radioIndex;
        }

        /*Enable the OL stats.*/
        //iwpriv wifi0 enable_ol_stats 1
        system_cmd_set_f("iwpriv wifi%d enable_ol_stats 1", radioIndex);

        if (PROXY_STA[radioIndex] == 0) {
            /* Destroy the particular interface after quering */
            system_cmd_set_f("ifconfig staX%d down", radioIndex);
            system_cmd_set_f("wlanconfig staX%d destroy", radioIndex);
        }
    }

    rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
    if (rc < 0) {
        perror ("send_eth_msgto_fpga()");
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
    }
    SYSLOG_PRINT(LOG_DEBUG,"ERR_MSG------->rpp_get_phy_fun()_exit");
    return 0;
}

/******************************************************************************
 * Function Name    : chainmask_config
 * Description      : This Function is used to identify the selected chainmask
		      is 1x1 or 2x2.
 ******************************************************************************/
static uint8_t chainmask_config (uint32_t phyhandle, uint8_t chainmask)
{
    switch(chainmask) {
    case SMA_1_5_CHAINMASK:
    case SMA_2_6_CHAINMASK:
    case SMA_3_7_CHAINMASK:
    case SMA_4_8_CHAINMASK:
        gSphyBandData[phyhandle].bw160nssworkaround = NSS1;
        return 1;
    case SMA_12_56_CHAINMASK:
    case SMA_34_78_CHAINMASK:
        gSphyBandData[phyhandle].bw160nssworkaround = NSS2;
        return 1;
    default:
        break;
    }
    gSphyBandData[phyhandle].bw160nssworkaround = DEFAULT_NSS;
    return 0;
}

/******************************************************************************
 * Function Name    : rpp_configure_phy_settings
 * Description      : This Function is used set the phy config coming from FPGA.
 ******************************************************************************/
int32_t rpp_configure_phy_settings(SetPhyReq *phyCfg, char *infName, int32_t staNode, uint8_t protocolrate)
{
    int32_t computedHtmcsVal=0;
    int32_t computedVhtTxmcsVal = 0;
    int32_t computedVhtRxmcsVal = 0;
    int32_t computedHeTxmcsVal = 0;
    int32_t computedHeRxmcsVal = 0;
    int32_t computedHeflagsVal = 0;
    int32_t computedFlagsVal = 0;
    int32_t count = 0;
    int8_t heDlOfdma = 0;
    int8_t numOfBwOptions = 0;
    int8_t txFixedMcs = 0;
    /*to make tx power setting for each station individual*/
    int32_t txMaxpwrVal = TX_MAX_POWER;
    uint8_t tempVar = 0;
    uint8_t nssCount = 0;
    uint8_t bw160nss = gSphyBandData[phyCfg->handle].bw160nssworkaround;
    uint8_t vhttxmcs = phyCfg->supportedvhtmcsset & HE_MCS_TX_POSN;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_configure_phy_settings_fun()_start");

    /* CfgNSS */
    //iwpriv ath0 nss 4
    tempVar = phyCfg->cfgnss;
    while (tempVar) {
        tempVar &= ( tempVar -1 ) ;
        nssCount++ ;
    }
    /*160Mhz for 1x1 and 2x2 chainmask setting not working as expected.
      Added workaround by setting chainmask as 0xFF for 1x1 & 2x2 cases.
      But nss value will be configured appropriately.
    */
    if (bw160nss != DEFAULT_NSS){
       SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->NSS Workaround, making nss %d", bw160nss);
       system_cmd_set_f("iwpriv %s%d nss %u", infName, staNode, bw160nss);
    }
    else {
       system_cmd_set_f("iwpriv %s%d nss %u", infName, staNode, nssCount);
    }
    if(gSphyBandData[phyCfg->handle].freqband != phyCfg->freqband) {
        SYSLOG_PRINT(LOG_ERR, "\n ERR_MSG------->Invalid Band Selection.. Valid band is : %d",
            gSphyBandData[phyCfg->handle].freqband);
    } else {
        /* Set frequency band and collect status : TBD */
        //iwpriv ath0 freq_band 1
        /*rpp_execute_set_cmd("ssdsssu" , "iwpriv ", infName, staNode, " ", SET_PHY_FRQBAND , " ",
            (phyCfg->freqband - RPP_APP_DEFNUM_ONE));*/
    }

    //Confugure HT MCS
    if (protocolrate == PROTO_N) {
        /* Set HT mcs setting */
        SYSLOG_PRINT(LOG_DEBUG, "\n DEBUG_MSG-------> supportedhtmcsset : 0x%x", phyCfg->supportedhtmcsset);

        rpp_set_supported_htmcs(phyCfg->supportedhtmcsset, nssCount, &computedHtmcsVal);
        
        system_cmd_set_f("iwpriv %s%d set11NRates 0x%x", infName, staNode, computedHtmcsVal);

        //Disable 256QAM support for 11n
        system_cmd_set_f("iwpriv %s%d vht_11ng 0", infName, staNode);

    } else {
        //Enable all mcs 0-31 in HT, 0 is enable, 1 bit is disable
        system_cmd_set_f("iwpriv %s%d disable11nmcs 0x%x", infName, staNode, 0x0);
        //Enable 256QAM support 
        system_cmd_set_f("iwpriv %s%d vht_11ng 1", infName, staNode);

    }

    if (protocolrate >= PROTO_AC) {
        /* Set VHT mcs setting */
        SYSLOG_PRINT(LOG_DEBUG, "\n DEBUG_MSG-------> supportedvhtmcsset : 0x%x", phyCfg->supportedvhtmcsset);

        rpp_set_supported_mcs(phyCfg->supportedvhtmcsset, nssCount, PROTO_AC, &computedVhtRxmcsVal,&computedVhtTxmcsVal, &txFixedMcs);
        system_cmd_set_f("iwpriv %s%d conf_11acmcs 0x%x", infName, staNode, computedVhtRxmcsVal);
        system_cmd_set_f("iwpriv %s%d vht_txmcsmap 0x%x", infName, staNode, computedVhtTxmcsVal);
        system_cmd_set_f("iwpriv %s%d vhtmcs %d", infName, staNode, txFixedMcs);
        if (protocolrate == PROTO_AC) {
            if (vhttxmcs == HEMCS_0_11)  {
            /* Enable VHT MCS 10-11 if TX VHTMCS is set as 0-11 in GUI, else disable. MCS 0-9 are already enabled for this case */
                system_cmd_set_f("iwpriv %s%d vhtmcs_q1011 1", infName, staNode);
                system_cmd_set_f("iwpriv %s%d vhtmcs_nq1011 1", infName, staNode);
            } else {
                system_cmd_set_f("iwpriv %s%d vhtmcs_q1011 0", infName, staNode);
                system_cmd_set_f("iwpriv %s%d vhtmcs_nq1011 0", infName, staNode);
            }
        }
    }

    if (protocolrate == PROTO_AX) {
            /* Set HE MCS setting */
        SYSLOG_PRINT(LOG_DEBUG, "\n DEBUG_MSG-------> supportedhemcsset : 0x%x", phyCfg->supportedhemcsset);
        rpp_set_supported_mcs(phyCfg->supportedhemcsset, nssCount, PROTO_AX,&computedHeRxmcsVal,&computedHeTxmcsVal, &txFixedMcs);

        system_cmd_set_f("iwpriv %s%d he_rxmcsmap 0x%x", infName, staNode, computedHeRxmcsVal);
        system_cmd_set_f("iwpriv %s%d he_txmcsmap 0x%x", infName, staNode, computedHeTxmcsVal);
        system_cmd_set_f("iwpriv %s%d he_mcs 0x%x", infName, staNode, txFixedMcs);
        
        /* Enable VHT MCS 10-11 if Supported HEMCS set as 0-11 in GUI, else disable. MCS 0-9 are already enabled in rpp_set_supported_hemcs for this case */
        /* VHT MCS 10-11 command at the driver level would enable/disable HE MCS 10-11 as well */
        if (phyCfg->supportedhemcsset >= HERxMCS_0_11) {
            system_cmd_set_f("iwpriv %s%d vhtmcs_q1011 1", infName, staNode);
            system_cmd_set_f("iwpriv %s%d vhtmcs_nq1011 1", infName, staNode);
        } else {
            system_cmd_set_f("iwpriv %s%d vhtmcs_q1011 0", infName, staNode);
            system_cmd_set_f("iwpriv %s%d vhtmcs_nq1011 0", infName, staNode);
        }
    }

    /* Set AMSDU  and AMPDU depth and collect status */
    //iwpriv ath0 amsdu 3
    system_cmd_set_f("iwpriv %s%d amsdu %u", infName, staNode, phyCfg->amsdudepth);
    //iwpriv ath0 ampdu 64
    system_cmd_set_f("iwpriv %s%d ampdu %u", infName, staNode, phyCfg->ampdudepth);

    /* Set heflags setting */
    /* Bit 11~31 reserved 10-11v,9-11k,8-BSS Color,6&7-LTF,5-RT,4-ERE,3-DCM,2-UL_MIMO,1-UL_OFDMA,0-DL_OFDMA */

    //Set DL_OFDMA(iwpriv ath0 he_dlofdma 1)
    heDlOfdma = phyCfg->heflags & 1;
    system_cmd_set_f("iwpriv %s%d he_dlofdma %d",  infName, staNode, heDlOfdma);
    system_cmd_set_f("iwpriv %s%d he_mubfee %d", infName, staNode,heDlOfdma);

    //Add support for bsscolor enable
    computedHeflagsVal = (phyCfg->heflags >> 8) & 1;
    system_cmd_set_f("iwpriv %s%d he_bssstate %d", infName, staNode, computedHeflagsVal);

   //Add support for 11k enable
    if (TEST_BIT(phyCfg->heflags, PHYFLAGS_80211K_SHIFT))
        gSphyBandData[phyCfg->handle].is11kEnable = true;
    else {
        gSphyBandData[phyCfg->handle].is11kEnable = false;
        gSphyBandData[phyCfg->handle].is11ktriggered = false;
    }

    //Add support for 11v enable
    if (TEST_BIT(phyCfg->heflags, PHYFLAGS_80211V_SHIFT))
        gSphyBandData[phyCfg->handle].is11vEnable = true;
    else {
        gSphyBandData[phyCfg->handle].is11vEnable = false;
        gSphyBandData[phyCfg->handle].is11vtriggered = false;
    }

    /* Set flags setting for subfee and mubfee*/
    computedFlagsVal = (phyCfg->flags) & 1;
    //SYSLOG_PRINT(LOG_DEBUG, "\n  DEBUG_MSG------->0th bit of flags: 0x%x", computedFlagsVal);
    if(computedFlagsVal) {
        system_cmd_set_f("iwpriv %s%d he_mubfee 1", infName, staNode);
    } else {
       /* IN SPF11 MIMO is mandatory for ofdma to work, so disabling MIMO only when ofdma is not selected */
        if (heDlOfdma == 0) {
            system_cmd_set_f("iwpriv %s%d he_mubfee 0", infName, staNode);
        }
    }

    system_cmd_set_f("iwpriv %s%d vhtsubfee 1",  infName, staNode);
    system_cmd_set_f("iwpriv %s%d he_subfee 1",  infName, staNode);

    system_cmd_set_f("iwpriv %s%d vhtsubfer 0",  infName, staNode);

    system_cmd_set_f("iwpriv %s%d he_subfer 0",  infName, staNode);
    /* Configuring RTS/CTS Values */
    if (TEST_BIT(phyCfg->flags, PHYFLAGS_RTSCTS_SHIFT))
        system_cmd_set_f("iwpriv %s%d enablertscts 0x11",  infName, staNode);
    else
        system_cmd_set_f("iwpriv %s%d enablertscts 0",  infName, staNode);

    /* BW management feature */
    int32_t bitcount = 0;
    if (phyCfg->handle == 0 || phyCfg->handle == 2){
        for (count = RPP_APP_DEFNUM_FOUR; count > 0; count--) {
            if (phyCfg->flags & (1<<count))
                bitcount++ ;
        }
        if (!IS_THREE_RADIO_PROFILE) {
           numOfBwOptions = 4;  //For 5G Radio 2 radio mode- BW 20/40/80/160
        } else {
           numOfBwOptions = 3; //For 5G Radio 3 radio mode -BW 20/40/80
        }
        if (bitcount == numOfBwOptions) {
            system_cmd_set_f("iwpriv %s%d cwmenable 1",  infName, staNode);
        }
        else {
            system_cmd_set_f("iwpriv %s%d cwmenable 0",  infName, staNode);
        }
    }

    else if (phyCfg->handle == RPP_APP_DEFNUM_ONE){
        for (count = RPP_APP_DEFNUM_TWO; count > 0; count--) {
            if (phyCfg->flags & (1<<count))
            bitcount++;
        }
        numOfBwOptions = 2; //For 2.4G Radio- 20/40
        if (bitcount == numOfBwOptions) {
            system_cmd_set_f("iwpriv %s%d cwmenable 1",  infName, staNode);
        }
        else {
            system_cmd_set_f("iwpriv %s%d cwmenable 0",  infName, staNode);
        }
    }

    system_cmd_set_f("iwpriv %s%d chwidth %u",  infName, staNode, gSphyBandData[phyCfg->handle].chwidth);

    if (gTxpowerAttinution <= txMaxpwrVal) {
        txMaxpwrVal -= gTxpowerAttinution;
    }
    system_cmd_set_f("iwconfig %s%d txpower %d", infName, staNode, txMaxpwrVal);
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_configure_phy_settings_fun()_exit");
    return 0;
}

/******************************************************************************
 * Function Name    : rpp_set_phy_req
 * Description      : This Function is used set the phy config coming from FPGA.
 ******************************************************************************/
int32_t rpp_set_phy_req (int8_t *buf)
{
    int32_t rc = 0;
    int32_t phy = 0;
    char    tempBuf[RPP_APP_BUFF_SIZE] = "\0";
    int32_t   value = 0;
    int32_t stationIndex = 0;
    uint8_t prevProxySta = 0;
    uint8_t staNum = 0;
    bool isOnlyThresholdChanged = false;
    struct staInfo *stainfo = NULL;

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_set_phy_req_fun()_start");

    RppMessageHead *msghdr = (RppMessageHead *)buf;
    SetPhyReq* phyCfg = (SetPhyReq *)msghdr->body;

    char   respBuf[RPPMSG_SETPHY_RESP_SZ];
    memset (respBuf, 0, sizeof (respBuf));
    msghdr = (RppMessageHead *) respBuf;
    msghdr->cat = RPP_MSG_RESP;
    msghdr->type = RPP_MSG_SETPHY_RESP;
    msghdr->len = sizeof(SetPhyResp);
    SetPhyResp *resp = (SetPhyResp*)msghdr->body;
    resp->errcode = PHY_INTF_CFG_SUCCESS;

    phy = phyCfg->handle;

    REMAP_PHY_HANDLE(phyCfg->handle);

    if (gPhyHandle[phy] == 0xff) {
        resp->errcode = PHY_INTF_CFG_INVALID_PHY_HANDLE;
        SYSLOG_PRINT(LOG_ERR, "\n ERR_MSG------->Invalid Phy Handle. %d", phy);
    } else {
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.handle:%d",phyCfg->handle);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.regulatory:%c%c",phyCfg->regulatory[0],phyCfg->regulatory[RPP_APP_DEFNUM_ONE]);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.freqband:%d",phyCfg->freqband);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.cfgnss:%d",phyCfg->cfgnss);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.supportedrates:0x%x",phyCfg->supportedrates);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.supportedhtmcsset:0x%x",phyCfg->supportedhtmcsset);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.supportedvhtmcsset:0x%x",phyCfg->supportedvhtmcsset);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.supportedhemcsset:0x%x",phyCfg->supportedhemcsset);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.amsdudepth:%d",phyCfg->amsdudepth);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.ampdudepth:%d",phyCfg->ampdudepth);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.txpowerattnueation:%d",phyCfg->txpowerattnueation);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.txmcsmap:%d",phyCfg->txmcsmap);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.rxmcsmap:%d",phyCfg->rxmcsmap);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.heflags:0x%x",phyCfg->heflags);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.hefrag:%d",phyCfg->hefrag);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.flags:%d",phyCfg->flags);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.noisegeneratorchannel:%d",phyCfg->noisegeneratorchannel);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.ftRoamThreshold:%d",phyCfg->ftRoamThreshold);
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->PhyCfg.scanThreshold:%d",phyCfg->scanThreshold);

        /*If 11K or 11V is enabled, to support runtime threshold configuration
        * Compare the contents of SetPhy except roaming, scanning thresholds with previous SetPhy.
        * If they are same, then just save the new threholds to be applied per STA during association and return without intf down/ vap delete
        */
        if (TEST_BIT(phyCfg->heflags, PHYFLAGS_80211K_SHIFT) || TEST_BIT(phyCfg->heflags, PHYFLAGS_80211V_SHIFT)) {
            if (memcmp(&addStaPhyData[phyCfg->handle], phyCfg, sizeof(SetPhyReq) - (sizeof(phyCfg->scanThreshold) + sizeof(phyCfg->ftRoamThreshold))) == 0) {
                isOnlyThresholdChanged = true;
            }
        }
        /* Copy all the setPhy data for station configuration */
        memcpy(&addStaPhyData[phyCfg->handle], phyCfg, sizeof(SetPhyReq));
        gSphyBandData[phyCfg->handle].ftRoamThreshold = phyCfg->ftRoamThreshold;
        gSphyBandData[phyCfg->handle].scanThreshold = phyCfg->scanThreshold;
        if (isOnlyThresholdChanged == true) {
             //Reset 11k/11v trigger when threshold are changed runtime
            gSphyBandData[phyCfg->handle].is11vtriggered = false;
            gSphyBandData[phyCfg->handle].is11ktriggered = false;
            stainfo = &staAssocHdl[phyCfg->handle].staCountInfo[0];
            for (uint8_t stationIndex = 0; stationIndex < staAssocHdl[phyCfg->handle].staCount; stationIndex++, stainfo++) {
                if (stainfo->phyHandle == phyCfg->handle) {
                    stainfo->is11vBTMtriggered = false;
                    stainfo->staRoamTrigger = false;
                }
            }
            /* Send the response to the FPGA */
            rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
            if (rc < 0) {
                perror ("send_eth_msgto_fpga()");
                SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
            }
            SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_set_phy_req_fun()_exit");
            return rc;
        }

        gTxpowerAttinution = phyCfg->txpowerattnueation;

#ifdef MUMIMO_OFDMA_PROXY_DISABLE
        prevProxySta = PROXY_STA[phyCfg->handle];
        if (((phyCfg->flags & 1) == 1) || (phyCfg->heflags & 1))
            PROXY_STA[phyCfg->handle] = 0;
        else
            PROXY_STA[phyCfg->handle] = 1;

        if (PROXY_STA[phyCfg->handle] != prevProxySta) {
            for (stationIndex = 0; stationIndex < RPP_MAX_STA_SUPPORTED; stationIndex++) {
                if (rppStaHandle.staCreateStatus[stationIndex] == STA_NOT_CREATED)
                    continue;
                if ((rppStaHandle.phy[stationIndex] == phyCfg->handle)) {
                    staNum = rppStaHandle.staNum[stationIndex];
                    SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->Purging the sta%d station.\n",staNum);
                    system_cmd_set_f("wlanconfig sta%u destroy", staNum);
                    if (rppStaHandle.staCreateStatus[staNum] == STA_ACTIVE) {
                        staPerRadioHdl[phyCfg->handle].active_stations_per_radio -= 1;
                        rppStaHandle.activeCount--;
                    }
                    staPerRadioHdl[phyCfg->handle].total_stations_per_radio -= 1;
                    rppStaHandle.totalCount--;
                    SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->sta%u going to NOT_CREATED state\n", staNum);
                    rppStaHandle.staCreateStatus[staNum] = STA_NOT_CREATED;
                }
            }
        }
	//Calculate BW before setting chainmask
        rpp_calculate_chwidth(phyCfg->handle, phyCfg->flags);

        if (PROXY_STA[phyCfg->handle] == 0) {
            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->mu-mimo bit 0 of phyCfg->flags:%d",(phyCfg->flags & 1));
            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->OFDMA bit 0 of phyCfg->heflags:%d",(phyCfg->heflags & 1));

            /*Check wheather proxy station exist, then need to delete it*/
            rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwconfig | grep staX%u | wc -l", phyCfg->handle);
            value = atoi(tempBuf);

            if (value == 1) {
                /* Delete the proxy station */
                system_cmd_set_f("wlanconfig staX%u destroy", phyCfg->handle);
            }

            /* Set regulatory info and collect status */
            // iwpriv wifi1 setCountry US  //no print
            system_cmd_set_f("iwpriv wifi%d setCountry %c%c", phyCfg->handle, phyCfg->regulatory[0], phyCfg->regulatory[1]);

            /* Set tx chainmask based on antenna positions */

            /* 160Mhz for 1x1 and 2x2 chainmask setting not working as expected.
               Added workaround by setting chainmask as 0xFF for 1x1 & 2x2 cases.
               But nss value will be configured appropriately.
            */
            if ((gSphyBandData[phyCfg->handle].chwidth == BW_80P80MHz) && chainmask_config(phyCfg->handle, phyCfg->cfgnss)) {
                // iwpriv wifi0 txchainmask 0xF
                system_cmd_set_f("iwpriv wifi%d txchainmask 0x%x", phyCfg->handle, SMA_ALL_CHAINMASK);
                system_cmd_set_f("iwpriv wifi%d rxchainmask 0x%x", phyCfg->handle, SMA_ALL_CHAINMASK);
            } else {
                 // iwpriv wifi0 txchainmask 0xF
                system_cmd_set_f("iwpriv wifi%d txchainmask 0x%x", phyCfg->handle, phyCfg->cfgnss);
                // iwpriv wifi0 rxchainmask 0xF
                system_cmd_set_f("iwpriv wifi%d rxchainmask 0x%x", phyCfg->handle, phyCfg->cfgnss);
            }
        } else {
            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->mu-mimo bit 0 of phyCfg->flags:%d",(phyCfg->flags & 1));
            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->OFDMA bit 0 of phyCfg->heflags:%d",(phyCfg->heflags & 1));

            /*Check wheather proxy station exist, if not then create it*/
            rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwconfig | grep staX%u | wc -l", phyCfg->handle);
            value = atoi(tempBuf);

            if (value == 0) {
                //wlanconfig staX0 create wlandev wifi0 wlanmode sta
                system_cmd_set_f("wlanconfig staX%d create wlandev wifi%d wlanmode sta", phyCfg->handle, phyCfg->handle);
            }
            /* This is added so chainmask other than SMA1 is allowed to set, currently with 11A mode its not allowing*/
            system_cmd_set_f("iwpriv staX%d mode AUTO", phyCfg->handle);
            /* mpsta making down before applying new phy setting currently it is commented in deassociation of mpsta*/
            system_cmd_set_f("ifconfig staX%d down", phyCfg->handle);
            /* Set regulatory info and collect status */
            // iwpriv wifi1 setCountry US  //no print
            system_cmd_set_f("iwpriv wifi%d setCountry %c%c", phyCfg->handle, phyCfg->regulatory[0], phyCfg->regulatory[1]);
            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->phyCfg->cfgnss(tx chainmask):0x%x",phyCfg->cfgnss);
            /* Set tx chainmask based on antenna positions */
            if ((gSphyBandData[phyCfg->handle].chwidth == BW_80P80MHz) && chainmask_config(phyCfg->handle, phyCfg->cfgnss)) {
                // iwpriv wifi0 txchainmask 0xF
                system_cmd_set_f("iwpriv wifi%d txchainmask 0x%x", phyCfg->handle, SMA_ALL_CHAINMASK);
                system_cmd_set_f("iwpriv wifi%d rxchainmask 0x%x", phyCfg->handle, SMA_ALL_CHAINMASK);
            } else {
               // iwpriv wifi0 txchainmask 0xF
               system_cmd_set_f("iwpriv wifi%d txchainmask 0x%x", phyCfg->handle, phyCfg->cfgnss);
               /* Set rx chainmask based on antenna positions */
               // iwpriv wifi0 rxchainmask 0xF
               system_cmd_set_f("iwpriv wifi%d rxchainmask 0x%x", phyCfg->handle, phyCfg->cfgnss);
           }
            pthread_mutex_lock( &staProcessLock );
            /*Setting all saved values to proxy stations*/
            rc = rpp_configure_phy_settings(&addStaPhyData[phyCfg->handle], "staX", phyCfg->handle, PROTO_AX);
            pthread_mutex_unlock( &staProcessLock );

            if (rc < 0) {
                SYSLOG_PRINT(LOG_ERR, "\n ERR_MSG------->Error in phy settings for proxy station");
            }

            /* mpsta making up before applying new phy setting currently it is commented in deassociation of mpsta*/
            system_cmd_set_f("ifconfig staX%d up", phyCfg->handle);
            if (rc < 0) {
                SYSLOG_PRINT(LOG_ERR, "\n ERR_MSG------->Error in ifconfig up for proxy station");
            }

            system_cmd_set_f("wpa_cli -g/tmp/global%d interface_add staX%d \"\" athr /var/run/wpa_supplicant", phyCfg->handle, phyCfg->handle);
            system_cmd_set_f("wpa_cli -g/tmp/global%d -i staX%d scan_cache flush", phyCfg->handle, phyCfg->handle);
            system_cmd_set_f("wpa_cli -i staX%d scan", phyCfg->handle);
            /*Making the mpsta association trial count zero again, for trying the mpsta association again*/
            pthread_mutex_lock(&proxyStateLock[phyCfg->handle]);
            RppProxyStaStatusHdl[phyCfg->handle].mpsta_assoc_trial_count = 0;
            pthread_mutex_unlock(&proxyStateLock[phyCfg->handle]);
        }
#endif
        // Configure noise generator channel
        system_cmd_set_f("iwpriv wifi%d set_ng_ch %d", phyCfg->handle, phyCfg->noisegeneratorchannel);
        if (RPP_NG_ENABLE(phyCfg)) {
            // No configuration for noise generator bssid yet, set default bssid
            system_cmd_set_f("iwpriv wifi%d set_ng_bssid 00:00:00:00:00:01", phyCfg->handle);
        }
    }

    /* Send the response to the FPGA */
    rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
    if (rc < 0) {
        perror ("send_eth_msgto_fpga()");
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_set_phy_req_fun()_exit");
    return rc;
}

/******************************************************************************
 * Function Name    : get_phy_mode_str
 * Description      : This Function is used to get phy mode string by phy handle and preamble type.
 ******************************************************************************/
const char *get_phy_mode_str(uint32_t phyhandle, uint8_t preambleType)
{
#ifdef RDP419
    if (phyhandle == 0) 
#else
    if ((phyhandle == 0) || (phyhandle == RPP_APP_DEFNUM_TWO)) 
#endif
        return phyMapping_5G[preambleType][gSphyBandData[phyhandle].chwidth];
    else if (phyhandle == RPP_APP_DEFNUM_ONE)
        return phyMapping_2G[preambleType][gSphyBandData[phyhandle].chwidth];
#ifdef RDP419
    else if (phyhandle == RPP_APP_DEFNUM_TWO)
        return phyMapping_6G[preambleType][gSphyBandData[phyhandle].chwidth];
#endif
    return NULL;
}

/******************************************************************************
 * Function Name    : rpp_add_station_req
 * Description      : This Function is used to add the station.
 ******************************************************************************/
int32_t rpp_add_station_req (int8_t *buf)
{
    char     iwCmd[RPP_APP_BUFF_SIZE] = "\0";
    bool     valid_req = true;
    int32_t  rc = 0;
    struct staInfo *stainfo = NULL;

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_add_station_req_fun()_start");

    RppMessageHead *msghdr = (RppMessageHead *)buf;
    AddStaReq* staCfg = (AddStaReq *)msghdr->body;

    REMAP_PHY_HANDLE(staCfg->phyhandle);

    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->StaCfg.phyhandle:%d", staCfg->phyhandle);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->StaCfg.mac: %s", util_mac_addr_to_str(staCfg->mac));
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->StaCfg.apssid:%s",staCfg->apssid);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->StaCfg.apbssid: %s", util_mac_addr_to_str(staCfg->apbssid));
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->StaCfg.protocolrate:%d",staCfg->protocolrate);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->StaCfg.gi:%d",staCfg->gi);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->StaCfg.disableht40M:%d",staCfg->disableht40M);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->StaCfg.disablemaxamsdu:%d",staCfg->disablemaxamsdu);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->StaCfg.disableldpc:%d",staCfg->disableldpc);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->StaCfg.maxampdusize:%d",staCfg->maxampdusize);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->StaCfg.minampdudensity:%d",staCfg->minampdudensity);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->StaCfg.vhtmaxampdusize:%d",staCfg->vhtmaxampdusize);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->StaCfg.fbtcfg.enable:%d",staCfg->fbtcfg.enable);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->StaCfg.fbtcfg.nbroftargets:%d",staCfg->fbtcfg.nbroftargets);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->StaCfg.pmftype: %d", staCfg->pmftype);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->StaCfg.encryption.type:%d",staCfg->encryption.type);
    switch(staCfg->encryption.type) {
        case OPEN:
        case ENHANCED_OPEN:
            {
                SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->OPEN encryption.");
            }
            break;
        case PERSONAL:
        case WPA3_PERSONAL:
        case WPA2_WPA3_PERSONAL:
            {
                SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->personal encryption.");
                EncryptionPersonal *personal = (EncryptionPersonal *)&(staCfg->exdata[staCfg->encryption.cfgoffset]);
                SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->passphrase :%s",personal->passphrase);
                /* Store the passphrase */
                memcpy (&rppStaHandle.encryptionPersonalTemp, personal,
                                sizeof (EncryptionPersonal));
            }
            break;
        case ENTERPRISE:
        case WPA3_ENTERPRISE:
            {
                SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->enterprise encryption.\n");
                EncryptionEAP *eap = (EncryptionEAP *)&(staCfg->exdata[staCfg->encryption.cfgoffset]);
                switch(eap->type) {
                    case EAP_TLS:
                        {
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->peeridentity:%s", eap->u.tls.peeridentity);
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->password:%s", eap->u.tls.password);
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->cacertfilename:%s", eap->u.tls.cacertfilename);
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->privkeyfilename:%s", eap->u.tls.privkeyfilename);
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->certfilename:%s", eap->u.tls.certfilename);
                        }
                        break;
                    case EAP_TTLS:
                        {
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->phase2Type:%d", eap->u.ttls.phase2Type);
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->peeridentity:%s", eap->u.ttls.peeridentity);
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->anonymousidentity:%s", eap->u.ttls.anonymousidentity);
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->password:%s", eap->u.ttls.password);
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->cacertfilename:%s", eap->u.ttls.cacertfilename);
                        }
                        break;
                    case EAP_PEAP:
                        {
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->phase2Type:%d", eap->u.peap.phase2Type);
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->peeridentity:%s", eap->u.peap.peeridentity);
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->password:%s", eap->u.peap.password);
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->anonymousidentity:%s", eap->u.peap.anonymousidentity);
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->cacertfilename:%s", eap->u.peap.cacertfilename);
                        }
                        break;
                    case EAP_AKA:
                        {
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->identity:%s", eap->u.aka.identity);
                            SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->password:%s", eap->u.aka.password);
                        }
                        break;
                    default:
                        valid_req = false;
                        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->unknown EAP TYPE!!!! %d", eap->type);
                        break;
                }
                /* Store the EAP data */
                memcpy (&rppStaHandle.encryptionEapTemp, eap, sizeof (EncryptionEAP));
            }
            break;
        case WEP:
            {
                SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->wep encryption.");
                EncryptionWEP *wep = (EncryptionWEP *)&(staCfg->exdata[staCfg->encryption.cfgoffset]);
                SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->format:%d",wep->format);
                SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->key:%s", wep->key);

                /* Store the WEP data */
                memcpy (&rppStaHandle.encryptionWepTemp, wep, sizeof (EncryptionWEP));
            }
            break;
        default:
              SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->unknown encryption !!!!!!!");
              valid_req = false;
             break;
    }

    if(valid_req) {
        char respBuf[RPPMSG_ADDSTA_RESP_SZ];
        RppMessageHead *msghdrResp = (RppMessageHead *) respBuf;
        msghdrResp->cat = RPP_MSG_RESP;
        msghdrResp->type = RPP_MSG_ADDSTA_RESP;
        msghdrResp->len = sizeof(AddStaResp);
        AddStaResp *resp = (AddStaResp *)msghdrResp->body;
        resp->errcode = 0;
        uint8_t sta = 0;
        int8_t  sgiForMpsta = 0;
        resp->stahandle = 0;
        pthread_mutex_lock( &staProcessLock );

        /* Frame logic for station */
        // map station number to staCfg->mac[5]
        rc = rpp_stahandle_process(resp->stahandle,
                (uint8_t)staCfg->phyhandle, (uint8_t)RPP_ADD_STA_CMD,
                &sta, staCfg);

        //SYSLOG_PRINT(LOG_DEBUG,"\n sta = %d", sta);
        resp->stahandle = (uint32_t)sta;

        /* Set MacAddress  and BSSID */
        //wlanconfig sta0 create wlandev wifi0 wlanmode sta wlanaddr 12:34:56:78:ab:cd
        if (rc != RPP_APP_RET_EXISTS)
        {
            memset (iwCmd, 0, sizeof (iwCmd));
            sprintf (iwCmd, "wlanconfig sta%u create wlandev wifi%u wlanmode sta -bssid ", sta, staCfg->phyhandle);
            sprintf (&iwCmd[strlen(iwCmd)],"%s", util_mac_addr_to_str(staCfg->mac));
            SYSLOG_PRINT(LOG_DEBUG, "iwCmd = %s\n",iwCmd);
            if (system_cmd(iwCmd) == RPP_APP_DEFNUM_ONE) {
                  rppStaHandle.staCreateStatus[sta] = STA_ACTIVE;
                  SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->sta%u going to ACTIVE state\n", sta);
            }
            /*Increment the total station count per radio */
            if (rc != RPP_APP_RET_REPLACED) /* If old STA is destroyed and new STA is added, then total station count remains same */
                  staPerRadioHdl[staCfg->phyhandle].total_stations_per_radio += 1;
        }
        //Setting default mode as auto to avoid any invalid mode configurations and falling back to 11a
        system_cmd_set_f("iwpriv sta%u mode AUTO", sta);
        //This is moved at top as chwidth gets calculated here, needed for no proxy mode
        rc = rpp_configure_phy_settings(&addStaPhyData[staCfg->phyhandle], "sta", sta, staCfg->protocolrate);
        const char *phyMode = get_phy_mode_str(staCfg->phyhandle, staCfg->protocolrate);
        if (phyMode != NULL) {
            system_cmd_set_f("iwpriv sta%u mode %s", sta, phyMode);
        }
        /* Set GIMode */
        //iwpriv sta0 shortgi 1 // 0: GI High 1: GI SHORT
        if((staCfg->protocolrate == PROTO_AX) || (staCfg->protocolrate == 0)) {
            memset (iwCmd, 0, sizeof (iwCmd));
            if (staCfg->gi == GIMODE_SHORT) {
                sgiForMpsta = 0;
            } else if (staCfg->gi == GIMODE_LONG) {
                sgiForMpsta = 2;
            } else {
                sgiForMpsta = 3;
            }
            system_cmd_set_f("iwpriv sta%u shortgi %d", sta, sgiForMpsta);
        } else {
            sgiForMpsta = staCfg->gi - 1;
            system_cmd_set_f("iwpriv sta%u shortgi %d", sta, (staCfg->gi - 1));
        }

/*Added in V2 FC release as this command throws error, need to check for valid command.*/
#if 0
        /* Set DisableLDPC */
        //iwpriv sta0 ldpc 0
        rpp_execute_set_cmd("susd", "iwpriv sta", sta, " ldpc ", !(staCfg->disableldpc));
#endif
        /* Set MaxAMPDUSize */
        //iwpriv sta0 maxampdu 2
        system_cmd_set_f("iwpriv sta%u maxampdu %u", sta, staCfg->maxampdusize);
        /* Compute VhtMaxAMPDUSize */
        //iwpriv ath0 vhtmaxampdu 5
        system_cmd_set_f("iwpriv sta%u vhtmaxampdu %u", sta, staCfg->vhtmaxampdusize);
       //Support for FT
        if (staCfg->fbtcfg.enable) {
            system_cmd_set_f("iwpriv sta%u ft 1", sta);
            /* As we need to give the hold_bss/ unhold_bss  commands for the target APs and associated AP also..
             * Length of target AP List = number of targets from GUI + 1 (associated AP)
             */
            rppStaHandle.targetAPList[sta] = (apMacAddData *)malloc ((staCfg->fbtcfg.nbroftargets + 1) * ETHER_MAC_ADDR_LEN * sizeof(uint8_t));
            if (rppStaHandle.targetAPList[sta] != NULL) {
                memcpy(&rppStaHandle.targetAPList[sta][0].mac_address, staCfg->apbssid, ETHER_MAC_ADDR_LEN * sizeof(uint8_t));
                memcpy(&rppStaHandle.targetAPList[sta][RPP_APP_DEFNUM_ONE].mac_address, &staCfg->exdata[staCfg->fbtcfg.targetsoffset],
                                                 staCfg->fbtcfg.nbroftargets * ETHER_MAC_ADDR_LEN * sizeof(uint8_t));

               for (uint8_t targetIndex = 0; targetIndex <= staCfg->fbtcfg.nbroftargets; targetIndex++)
                   SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->targetAP no %d = %s", targetIndex,
                                                                             util_mac_addr_to_str((uint8_t *)&rppStaHandle.targetAPList[sta][targetIndex]));
            } else
                SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->Failed to allocate memory for targetAPList of sta%u", sta);

            if (PROXY_STA[staCfg->phyhandle] && ( staPerRadioHdl[staCfg->phyhandle].active_stations_per_radio == 0)) {
                if (gSphyBandData[staCfg->phyhandle].is11vEnable == true)
                    system_cmd_set_f("iwpriv staX%u wnm 1", staCfg->phyhandle);
                else
                    system_cmd_set_f("iwpriv staX%u wnm 0", staCfg->phyhandle);
                if (gSphyBandData[staCfg->phyhandle].is11kEnable == true)
                    system_cmd_set_f("iwpriv staX%u rrm 1", staCfg->phyhandle);
                else
                    system_cmd_set_f("iwpriv staX%u rrm 0", staCfg->phyhandle);
            }
            if (gSphyBandData[staCfg->phyhandle].is11vEnable == true)
                system_cmd_set_f("iwpriv sta%u wnm 1", sta);
            else
                system_cmd_set_f("iwpriv sta%u wnm 0", sta);
            if (gSphyBandData[staCfg->phyhandle].is11kEnable == true)
                system_cmd_set_f("iwpriv sta%u rrm 1", sta);
            else
                system_cmd_set_f("iwpriv sta%u rrm 0", sta);
        }
        if (PROXY_STA[staCfg->phyhandle]) {
            if( staPerRadioHdl[staCfg->phyhandle].active_stations_per_radio == 0) {
                //Setting default mode as auto to avoid any invalid mode configurations and falling back to 11a
                system_cmd_set_f("iwpriv staX%u mode AUTO", staCfg->phyhandle);
                /* Setting Legacy mode for Proxy stations */
                const char *phyMode = get_phy_mode_str(staCfg->phyhandle, staCfg->protocolrate);
                if (phyMode != NULL) {
                    system_cmd_set_f("iwpriv staX%u mode %s", staCfg->phyhandle, phyMode);
                }
                /* Set GIMode for proxy station*/
                system_cmd_set_f("iwpriv staX%u shortgi %d", staCfg->phyhandle, sgiForMpsta);
#if 0
                /* Set DisableLDPC for proxy station*/
                //iwpriv sta0 ldpc 0
                rpp_execute_set_cmd("susd", "iwpriv sta", staCfg->phyhandle, " ldpc ", !(staCfg->disableldpc));
#endif
                /* Set MaxAMPDUSize for proxy station*/
                //iwpriv sta0 maxampdu 2
                system_cmd_set_f("iwpriv staX%u maxampdu %u", staCfg->phyhandle, staCfg->maxampdusize );
                /* Compute VhtMaxAMPDUSize for proxy station*/
                //iwpriv ath0 vhtmaxampdu 5
                system_cmd_set_f("iwpriv staX%u vhtmaxampdu %u", staCfg->phyhandle, staCfg->vhtmaxampdusize);
            }
        }
       /* Increment the active station count per radio */
        staPerRadioHdl[staCfg->phyhandle].active_stations_per_radio += 1;

        SYSLOG_PRINT(LOG_DEBUG,"Total & Active Stations at radio %u = %u:%u\n",staCfg->phyhandle,
            staPerRadioHdl[staCfg->phyhandle].total_stations_per_radio,
            staPerRadioHdl[staCfg->phyhandle].active_stations_per_radio);
        pthread_mutex_unlock( &staProcessLock );
        pthread_mutex_lock( &assocStatLock[staCfg->phyhandle]);
        uint32_t tempCount = staAssocHdl[staCfg->phyhandle].staCount;
        stainfo = &staAssocHdl[staCfg->phyhandle].staCountInfo[tempCount];
        stainfo->staHandle = resp->stahandle;
        stainfo->phyHandle = staCfg->phyhandle;
        stainfo->staNum = sta;
        stainfo->staStatus = RPP_STATE_STATION_PRESENT;
        stainfo->assocStatus = STATE_ASSOCIATE_FAILED;
        stainfo->preambleType = staCfg->protocolrate;
        strncpy((char *)stainfo->apbssid, (char *)staCfg->apbssid, sizeof(staCfg->apbssid));
        SYSLOG_PRINT(LOG_DEBUG,"\n DEBUG_MSG------->--Add station handle : %d - %d-- count : %d\n",
            stainfo->staHandle, resp->stahandle, tempCount);
        staAssocHdl[staCfg->phyhandle].staCount++;

        pthread_mutex_unlock( &assocStatLock[staCfg->phyhandle]);
        rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
        if (rc < 0) {
            perror ("send_eth_msgto_fpga()");
            SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
        }
    } else {
        char respBuf[RPPMSG_ADDSTA_RESP_SZ];
        RppMessageHead *msghdrResp = (RppMessageHead *) respBuf;
        msghdrResp->cat = RPP_MSG_RESP;
        msghdrResp->type = RPP_MSG_ADDSTA_RESP;
        msghdrResp->len = sizeof(AddStaResp);
        AddStaResp *resp = (AddStaResp *)msghdrResp->body;
        resp->errcode = RPP_APP_DEFNUM_ONE;

        rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
        if (rc < 0) {
            perror ("send_eth_msgto_fpga()");
            SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
        }
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_add_station_req_fun()_exit");
    return rc;
}

/******************************************************************************
 * Function Name    : rpp_delete_station_req
 * Description      : This Function is used to delete the station
******************************************************************************/
int32_t rpp_delete_station_req (int8_t *buf)
{
    char        respBuf[RPPMSG_DELSTA_RESP_SZ];
    uint8_t     staNum = 0;
    int32_t     rc = 0;
    uint32_t    staIndex = 0;
    struct staInfo *stainfo = NULL;
    FastBssTransit *fbtcfg = NULL;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_delete_station_req_fun()_start");

    RppMessageHead *msghdr = (RppMessageHead *)buf;
    DelStaReq *  delStaReq = (DelStaReq *)msghdr->body;
    DelStaReq* delstaReq = (DelStaReq *)msghdr->body;

    REMAP_PHY_HANDLE(delstaReq->phyhandle);

    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->DelStaReq.phyhandle:%d",delstaReq->phyhandle);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->DelStaReq.stahandle:%d",delstaReq->stahandle);

    pthread_mutex_lock( &staProcessLock );
    rc = rpp_stahandle_process(delStaReq->stahandle,
            (uint8_t)delStaReq->phyhandle, (uint8_t)RPP_DEL_STA_CMD,
            &staNum, NULL);
    memset (&respBuf, 0, sizeof (respBuf));
    msghdr = (RppMessageHead *) respBuf;
    msghdr->cat = RPP_MSG_RESP;
    msghdr->type = RPP_MSG_DELSTA_RESP;
    msghdr->len = sizeof(DelStaResp);
    DelStaResp *resp = (DelStaResp*)msghdr->body;
    resp->errcode = 0;

    pthread_mutex_unlock( &staProcessLock );

    pthread_mutex_lock( &assocStatLock[delStaReq->phyhandle]);
    stainfo = &staAssocHdl[delStaReq->phyhandle].staCountInfo[0];
    for (staIndex = 0; staIndex < staAssocHdl[delStaReq->phyhandle].staCount; staIndex++, stainfo++) {
        if (stainfo->staNum == staNum) {
            stainfo->staStatus = RPP_STATE_STATION_NOTPRESENT;
            memmove(stainfo, stainfo + RPP_APP_DEFNUM_ONE,
                    (staAssocHdl[delStaReq->phyhandle].staCount - staIndex - 1) * sizeof(struct staInfo));
            staAssocHdl[delStaReq->phyhandle].staCount--;
            break;
        }
    }

    /* Handle deleting an ASSOCIATED station when deassoc is not issued by User*/
    if (stainfo->assocStatus == STATE_ASSOCIATED) {
        staAssocHdl[delStaReq->phyhandle].associated_stations_per_radio--;
        /* Reset the associated state for the staIndex */
        stainfo->assocStatus = STATE_ASSOCIATE_FAILED;
        fbtcfg = &rppStaHandle.addStaReq[staNum].fbtcfg;
        if ((fbtcfg->enable) && (rppStaHandle.targetAPList[staNum] != NULL)) {
            for (uint8_t targetIndex = 0 ; targetIndex <= fbtcfg->nbroftargets; targetIndex++) {
                system_cmd_set_f("wpa_cli -i sta%u -g /tmp/global%d unhold_bss %s",
                                                                    staNum, delstaReq->phyhandle,
                                                                    util_mac_addr_to_str((uint8_t *)&rppStaHandle.targetAPList[staNum][targetIndex]));
            }
        }
        if (staAssocHdl[stainfo->phyHandle].associated_stations_per_radio == 0) {
            gSphyBandData[delStaReq->phyhandle].is11vtriggered = false;
            gSphyBandData[delStaReq->phyhandle].is11ktriggered = false;
        }
    }
    SYSLOG_PRINT(LOG_DEBUG,"Associated station at phyHandle %d = %d", delStaReq->phyhandle, staAssocHdl[delStaReq->phyhandle].associated_stations_per_radio);

    pthread_mutex_unlock( &assocStatLock[delStaReq->phyhandle]);

    if (PROXY_STA[delstaReq->phyhandle]) {
        rpp_deactivate_station(delstaReq->phyhandle, "sta", staNum);
        /*Decreasing the count in local variable maintaining the active count per radio*/
        staPerRadioHdl[delstaReq->phyhandle].active_stations_per_radio -= 1;
    } else {
        /* In case of non-Proxy mode , delete interface directly. */
        rpp_delete_station(delstaReq->phyhandle, "sta", staNum);
    }



    if (PROXY_STA[delstaReq->phyhandle]) {

        /*Clearing the proxy station association status flag when there are no active stations*/
        if(staPerRadioHdl[delstaReq->phyhandle].active_stations_per_radio == 0) {

            /* To deassociate the proxy station */
            rpp_dissociation_process(delstaReq->phyhandle, "staX", delstaReq->phyhandle);
            pthread_mutex_lock(&proxyStateLock[delstaReq->phyhandle]);
            RppProxyStaStatusHdl[delstaReq->phyhandle].proxy_sta_assoc = false;
            pthread_mutex_unlock(&proxyStateLock[delstaReq->phyhandle]);

            /*Making the mpsta association trial count zero again, for trying the mpsta association again*/
            pthread_mutex_lock(&proxyStateLock[delstaReq->phyhandle]);
            RppProxyStaStatusHdl[delstaReq->phyhandle].mpsta_assoc_trial_count = 0;
            pthread_mutex_unlock(&proxyStateLock[delstaReq->phyhandle]);
            staAssocHdl[delstaReq->phyhandle].associated_stations_per_radio = 0;
        }
    } else {
        if(staPerRadioHdl[delstaReq->phyhandle].active_stations_per_radio == 0)
            staAssocHdl[delstaReq->phyhandle].associated_stations_per_radio = 0;
    }

    SYSLOG_PRINT(LOG_DEBUG,"Total & active Stations at radio %u = %u:%u\n",delstaReq->phyhandle,
        staPerRadioHdl[delstaReq->phyhandle].total_stations_per_radio,
        staPerRadioHdl[delstaReq->phyhandle].active_stations_per_radio);

    SYSLOG_PRINT(LOG_DEBUG,"\n DEBUG_MSG------->--Del station handle : %d - %d - count : %d--\n", 
                                                        stainfo->staHandle, delStaReq->stahandle,
                                                        staAssocHdl[delstaReq->phyhandle].staCount);

    rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
    if (rc < 0) {
        perror ("send_eth_msgto_fpga()");
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
    }
    SYSLOG_PRINT(LOG_DEBUG,"rpp_delete_station_req_fun()_exit");
    return rc;
}

/******************************************************************************
 * Function Name    : rpp_scan_req
 * Description      : This Function is used to frame scan message and send it
 *                    to FPGA.
 ******************************************************************************/
int32_t rpp_scan_req (int8_t *buf)
{
    char      tempBuf[40 * RPP_APP_BUFF_SIZE] = "\0";
    char      tempstring[RPP_APP_BUFF_SIZE] = "\0";
    int32_t  totalApCount = 0;
    int32_t   rc = 0;
    int32_t   loopCount;
    ScanInfo  *apInformation = NULL;
    ScanInfo  *info = NULL;

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_scan_req_fun()_start");

    RppMessageHead *msghdr = (RppMessageHead *)buf;
    ScanReq* scanReq = (ScanReq *)msghdr->body;

    REMAP_PHY_HANDLE(scanReq->phyhandle);

    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->scanReq.phyhandle:%d",scanReq->phyhandle);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->scanReq.duration:%d",scanReq->duration);

    if (PROXY_STA[scanReq->phyhandle]) {
        uint8_t  proxyStaState = 0;
        uint8_t  staState = 0;
        uint8_t  staNum = 0;
        int32_t  count = 0;
        int32_t totalSta = 0;
        bool    staAssociated = false;
        StaStateInfo stateInfo = {0};

        /*Making the mpsta association trial count zero again, for trying the mpsta association again*/
        pthread_mutex_lock(&proxyStateLock[scanReq->phyhandle]);
        RppProxyStaStatusHdl[scanReq->phyhandle].mpsta_assoc_trial_count = 0;
        pthread_mutex_unlock(&proxyStateLock[scanReq->phyhandle]);

        /* Compute proxy station state */
        memset(&stateInfo, 0, sizeof(StaStateInfo));
        system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwpriv staX%d g_sta_state", scanReq->phyhandle);
        sscanf (tempBuf, "%22c%hhu", tempstring,(uint8_t *)&proxyStaState);

        SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG---------->In Scan request:Proxy station staX%d has state as %d\n",
            scanReq->phyhandle,proxyStaState);

        if ( proxyStaState == RPP_STA_ASSOC_STATE) {
            pthread_mutex_lock( &staProcessLock );
            /* Find the total number of stations */
            totalSta = rppStaHandle.totalCount;
            pthread_mutex_unlock( &staProcessLock );
            for (count = 0; count < totalSta; count++) {
                if ( rppStaHandle.phy[count] == scanReq->phyhandle ) {
                    /*Getting the station number*/
                    staNum = rppStaHandle.staNum[count];
                    /* Compute station state */
                    memset(&stateInfo, 0, sizeof(StaStateInfo));
                    rc = get_sta_state(&stateInfo, scanReq->phyhandle, "sta", staNum);
                    staState = (rc == 0 && stateInfo.assocStatus == STATE_ASSOCIATED) ? RPP_STA_ASSOC_STATE : 0;
                    if ( staState == RPP_STA_ASSOC_STATE) {
                       staAssociated = true;
                       break;
                    }
                } else if ( rppStaHandle.phy[count] == -1 ) {
                   totalSta += 1;
                }
            }
            if ( staAssociated == false ) {
                /*So we need to deassociate the proxy station to initiate the scan.*/
                /* To deassociate the proxy station */
                rpp_dissociation_process(scanReq->phyhandle, "staX", scanReq->phyhandle);

                pthread_mutex_lock(&proxyStateLock[scanReq->phyhandle]);
                RppProxyStaStatusHdl[scanReq->phyhandle].proxy_sta_assoc = false;
                pthread_mutex_unlock(&proxyStateLock[scanReq->phyhandle]);
            }
        }

        /* Up the particular interface before quering */
        system_cmd_set_f("ifconfig staX%d up", scanReq->phyhandle);
        //wpa_cli -g/tmp/global0 interface_add athX "" athr /var/run/wpa_supplicant
        system_cmd_set_f("wpa_cli -g/tmp/global%d interface_add staX%d \"\" athr /var/run/wpa_supplicant",
             scanReq->phyhandle, scanReq->phyhandle);
        //wpa_cli -i ath0 scan_cache flush
        system_cmd_set_f("wpa_cli -g/tmp/global%d -i staX%d  scan_cache flush", scanReq->phyhandle, scanReq->phyhandle);
        /* Populate the scan list */
        system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwlist staX%d scan > /tmp/scanlist.txt 2>&1", scanReq->phyhandle);
    } else {
        //wlanconfig ath0 create wlandev wifi0 wlanmode sta wlanaddr <mac_address>
        system_cmd_set_f("wlanconfig ath%u create wlandev wifi%u wlanmode sta wlanaddr %s", scanReq->phyhandle, scanReq->phyhandle,
            gDefAthMac[scanReq->phyhandle]);
        /* Up the particular interface before quering */
        system_cmd_set_f("ifconfig ath%d up", scanReq->phyhandle);
        //wpa_cli -g/tmp/global0 interface_add athX "" athr /var/run/wpa_supplicant
        system_cmd_set_f("wpa_cli -g/tmp/global%d interface_add ath%d \"\" athr /var/run/wpa_supplicant", scanReq->phyhandle,
            scanReq->phyhandle);
        //wpa_cli -i ath0 scan_cache flush
        system_cmd_set_f("wpa_cli -g/tmp/global%d  -i ath%d scan_cache flush", scanReq->phyhandle, scanReq->phyhandle);
        /* Populate the scan list */
        system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwlist ath%d scan > /tmp/scanlist.txt 2>&1", scanReq->phyhandle);
        system_cmd_set_f("ifconfig ath%d down", scanReq->phyhandle);
        //wpa_cli -g/tmp/global0 interface_remove ath0
        system_cmd_set_f("wpa_cli -g/tmp/global%d interface_remove ath%d", scanReq->phyhandle, scanReq->phyhandle);
        /* Destroy the particular interface after quering */
        system_cmd_set_f("wlanconfig ath%d destroy", scanReq->phyhandle);
    }

    apInformation = rpp_ap_list_builder(&totalApCount);    
    loopCount = 0;
    do{
        SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->Remaining APs = %d , Iteration = %d\n\n",
            totalApCount - loopCount, loopCount / NUMBER_OF_SCAN_RESULT);
        size_t respBufSz = RPPMSG_HDR_SIZE + sizeof(ScanResp) + NUMBER_OF_SCAN_RESULT* sizeof(ScanInfo);
        char respBuf[respBufSz];                                       

        memset(respBuf, 0, sizeof(respBuf));
        msghdr = (RppMessageHead *) respBuf;
        msghdr->cat = RPP_MSG_RESP;
        msghdr->type = RPP_MSG_SCAN_RESP;
        msghdr->len = respBufSz - RPPMSG_HDR_SIZE;
        ScanResp *resp = (ScanResp*)msghdr->body;

        resp->errcode = 0;
        resp->more = ( (totalApCount - loopCount) > NUMBER_OF_SCAN_RESULT );

        resp->nbrofresults = (totalApCount - loopCount) > NUMBER_OF_SCAN_RESULT ? NUMBER_OF_SCAN_RESULT : (totalApCount - loopCount);

        info = (ScanInfo *)resp->results;
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->number of result in this loop = %u", resp->nbrofresults);

        if (resp->nbrofresults) 
            memcpy(info, &apInformation[loopCount], resp->nbrofresults * sizeof(ScanInfo));
        
        rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
        if (rc < 0) {
            perror ("send_eth_msgto_fpga()");
            SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
        }
        loopCount += NUMBER_OF_SCAN_RESULT;
    }while (loopCount < totalApCount);

    if (apInformation != NULL)
        free(apInformation);

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_scan_req_fun()_exit");
    return rc;
}

/******************************************************************************
 * Function Name    : rpp_associate_req
 * Description      : This Function is used to associate to AP.
 ******************************************************************************/
int32_t rpp_associate_req (int8_t *buf)
{
    char     intfName[RPP_APP_DEFNUM_EIGHT] = "\0";
    uint8_t  proxyStaState = 0,tempBuf[RPP_APP_BUFF_SIZE];
    char tempstring[RPP_APP_BUFF_SIZE];

    int32_t  assoc_time = 0;
    /* allocated_assoc_time: It holds 25s if OWE Transition, 15s for other modes*/
    int32_t  allocated_assoc_time;
    Encryption *encryption = NULL;
    struct staInfo *stainfo = NULL;
    struct staInfo staInfoTemp = {0};
    StaStateInfo stateInfo = {0};
    time_t   assoc_request_time = 0;
    //char     tempBuf[RPP_APP_BUFF_SIZE] = "\0";
    int32_t  rc = 0;
    uint32_t  staNum = 0;
    uint32_t index = 0;
    uint32_t assocStaErrCode = 0;

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_associate_req_fun()_start");

    RppMessageHead *msghdr = (RppMessageHead *)buf;
    AssocReq* assocReq = (AssocReq *)msghdr->body;

    REMAP_PHY_HANDLE(assocReq->phyhandle);

    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->assocReq.phyhandle:%d",assocReq->phyhandle);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->assocReq.stahandle:0x%x",assocReq->stahandle);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->assocReq.stahandle:%d(in decimal)",assocReq->stahandle);

    assoc_request_time = time(NULL);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->Association time:%ld",assoc_request_time);

    {
        char respBuf[RPPMSG_ASSOC_RESP_SZ];
        RppMessageHead *msghdr = (RppMessageHead *) respBuf;
        msghdr->cat = RPP_MSG_RESP;
        msghdr->type = RPP_MSG_ASSOC_RESP;
        msghdr->len = sizeof(respBuf)- RPPMSG_HDR_SIZE;
        AssocResp *resp = (AssocResp*)msghdr->body;
        resp->errcode = 0;
        staNum = assocReq->stahandle;
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->staNum = %u\n",staNum);
        if (PROXY_STA[assocReq->phyhandle]) {
            /* Compute proxy station state */
            memset(&stateInfo, 0, sizeof(StaStateInfo));
            system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwpriv staX%d g_sta_state", assocReq->phyhandle);
            sscanf (tempBuf, "%22c%hhu", tempstring,(uint8_t *)&proxyStaState);

            SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG---------->Proxy station staX%d has state as %d\n",
                assocReq->phyhandle,proxyStaState);

            if (proxyStaState != RPP_STA_ASSOC_STATE){
                pthread_mutex_lock(&proxyStateLock[assocReq->phyhandle]);
                RppProxyStaStatusHdl[assocReq->phyhandle].proxy_sta_assoc = false;
                pthread_mutex_unlock(&proxyStateLock[assocReq->phyhandle]);
            }

            /*Associate the non-associated proxy station first before associating the other stations*/
            if (RppProxyStaStatusHdl[assocReq->phyhandle].proxy_sta_assoc == false && proxyStaState != RPP_STA_ASSOC_STATE && RppProxyStaStatusHdl[assocReq->phyhandle].mpsta_assoc_trial_count < MPSTA_ASSOC_MAX_TRIAL)
            {
                memset (intfName, 0, sizeof (intfName));
                sprintf (intfName, "staX%d", assocReq->phyhandle);
                system_cmd_set_f("ifconfig staX%d up", assocReq->phyhandle);
                //Doing scan cachek flush only if PMF or encryption type is changed
                if ((gPMF != rppStaHandle.addStaReq[staNum].pmftype) || (gEncType != rppStaHandle.addStaReq[staNum].encryption.type)) {
                    SYSLOG_PRINT(LOG_DEBUG, "PMF Type changed from %d to %d\n", gPMF, rppStaHandle.addStaReq[staNum].pmftype);
                    SYSLOG_PRINT(LOG_DEBUG, "Encryption Type changed from %d to %d \n", gEncType, rppStaHandle.addStaReq[staNum].encryption.type);
                    if ((gPMF != PMF_INVALID) || (gEncType != ENCTYPE_INVALID)) 
                        system_cmd_set_f("wpa_cli -g/tmp/global%d -i %s scan_cache flush", assocReq->phyhandle, intfName);
                }
                gPMF = rppStaHandle.addStaReq[staNum].pmftype;
                gEncType = rppStaHandle.addStaReq[staNum].encryption.type;
                /* mpsta was taking 2-3 attempts for association after port offline/online and AP down assoc retry for
                    5G radio association fix */
                rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
                if (rc < 0) {
                    perror ("send_eth_msgto_fpga()");
                    SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
                }

                /*Incrementing the mpsta association trial count, for trying mpsta association to perticular count.*/
                pthread_mutex_lock(&proxyStateLock[assocReq->phyhandle]);
                RppProxyStaStatusHdl[assocReq->phyhandle].mpsta_assoc_trial_count++;
                pthread_mutex_unlock(&proxyStateLock[assocReq->phyhandle]);
                //memset (intfName, 0, sizeof (intfName));
                //sprintf (intfName, "staX%d", assocReq->phyhandle);
                /* Extract encryption and psk */
                encryption = &(rppStaHandle.addStaReq[staNum].encryption);
                rc = rpp_association_process(assocReq->phyhandle, intfName, staNum);

                if (rc < 0) {
                    SYSLOG_PRINT(LOG_ERR, "\n ERR_MSG------->Error in associating proxy station");
                }

                allocated_assoc_time = (encryption->type != ENHANCED_OPEN) ? PROXY_STA_ASSOCTIME : PROXY_STA_OWE_TRANS_ASSOCTIME;

                while(1) {
                    /* Compute proxy station state */
                    system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwpriv staX%d g_sta_state", assocReq->phyhandle);
                    sscanf (tempBuf, "%22c%hhu", tempstring,(uint8_t *)&proxyStaState);

                    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG---------->Proxy station staX%d has state as %d\n",
                        assocReq->phyhandle,proxyStaState);
                    if( proxyStaState == RPP_STA_ASSOC_STATE ) {
                        pthread_mutex_lock(&proxyStateLock[assocReq->phyhandle]);
                        RppProxyStaStatusHdl[assocReq->phyhandle].proxy_sta_assoc = true;
                        RppProxyStaStatusHdl[assocReq->phyhandle].mpsta_assoc_trial_count = 0;
                        pthread_mutex_unlock(&proxyStateLock[assocReq->phyhandle]);
                        break;
                    } else {
                        assoc_time += 1;
                        sleep(1);
                        if (assoc_time == allocated_assoc_time) {
                            pthread_mutex_lock(&proxyStateLock[assocReq->phyhandle]);
                            RppProxyStaStatusHdl[assocReq->phyhandle].proxy_sta_assoc = false;
                            pthread_mutex_unlock(&proxyStateLock[assocReq->phyhandle]);
                            RppProxyStaStatusHdl[assocReq->phyhandle].failed_assoc_sent++;
                            //Checking assoc failure code for mpsta
                            memset(&stateInfo, 0, sizeof(StaStateInfo));
                            rc = get_sta_state(&stateInfo, assocReq->phyhandle, "staX", assocReq->phyhandle);
                            assocStaErrCode = rpp_map_assoc_sta_errcode(stateInfo.reasonCode);
                            staInfoTemp.staHandle = assocReq->stahandle;
                            staInfoTemp.phyHandle = assocReq->phyhandle;
                            staInfoTemp.staNum = (uint32_t)staNum;
                            memcpy(staInfoTemp.apbssid, rppStaHandle.addStaReq[staNum].apbssid, ETHER_MAC_ADDR_LEN * sizeof(uint8_t));
                            rpp_send_assocstate(&staInfoTemp, STATE_ASSOCIATE_FAILED, assocStaErrCode);

                            if (RppProxyStaStatusHdl[assocReq->phyhandle].failed_assoc_sent >= staPerRadioHdl[assocReq->phyhandle].active_stations_per_radio) {
                                RppProxyStaStatusHdl[assocReq->phyhandle].failed_assoc_sent = 0;
                                pthread_mutex_lock(&proxyStateLock[assocReq->phyhandle]);
                                RppProxyStaStatusHdl[assocReq->phyhandle].mpsta_assoc_trial_count = 0;
                                pthread_mutex_unlock(&proxyStateLock[assocReq->phyhandle]);
                            }
                            return rc;
                        }
                    }
                }
            }
            if( proxyStaState == RPP_STA_ASSOC_STATE ) {
                memset (intfName, 0, sizeof (intfName));
                sprintf (intfName, "sta%d", staNum);
                rc = rpp_association_process(assocReq->phyhandle, intfName, staNum);

                if (rc < 0) {
                    SYSLOG_PRINT(LOG_ERR, "\n ERR_MSG------->Error in associating station");
                }
            } else {
                rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
                if (rc < 0) {
                    perror ("send_eth_msgto_fpga()");
                    SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
                }

                memset(&stateInfo, 0, sizeof(StaStateInfo));
                rc = get_sta_state(&stateInfo, assocReq->phyhandle, "staX", assocReq->phyhandle);
                assocStaErrCode = rpp_map_assoc_sta_errcode(stateInfo.reasonCode);
                
                RppProxyStaStatusHdl[assocReq->phyhandle].failed_assoc_sent++;
                staInfoTemp.staHandle = assocReq->stahandle;
                staInfoTemp.phyHandle = assocReq->phyhandle;
                staInfoTemp.staNum = (uint32_t)staNum;
                memcpy(staInfoTemp.apbssid, rppStaHandle.addStaReq[staNum].apbssid, ETHER_MAC_ADDR_LEN * sizeof(uint8_t));
                rpp_send_assocstate(&staInfoTemp, STATE_ASSOCIATE_FAILED, assocStaErrCode);
                if (RppProxyStaStatusHdl[assocReq->phyhandle].failed_assoc_sent >=
                            staPerRadioHdl[assocReq->phyhandle].active_stations_per_radio) {
                    RppProxyStaStatusHdl[assocReq->phyhandle].failed_assoc_sent = 0;
                    pthread_mutex_lock(&proxyStateLock[assocReq->phyhandle]);
                    RppProxyStaStatusHdl[assocReq->phyhandle].mpsta_assoc_trial_count = 0;
                    pthread_mutex_unlock(&proxyStateLock[assocReq->phyhandle]);
                }
                RppProxyStaStatusHdl[assocReq->phyhandle].reset_assoc_trial_count_flag = true;
                RppProxyStaStatusHdl[assocReq->phyhandle].previous_assoc_req_time = assoc_request_time;
                return rc;
            }
        } else {
            memset (intfName, 0, sizeof (intfName));
            sprintf (intfName, "sta%d", staNum);
            //Doing scan cache flush only if PMF or encryption type is changed
            if ((gPMF != rppStaHandle.addStaReq[staNum].pmftype) || (gEncType != rppStaHandle.addStaReq[staNum].encryption.type)){
                SYSLOG_PRINT(LOG_DEBUG, "PMF Type changed from %d to %d\n", gPMF, rppStaHandle.addStaReq[staNum].pmftype);
                SYSLOG_PRINT(LOG_DEBUG, "Encryption Type changed from %d to %d \n", gEncType, rppStaHandle.addStaReq[staNum].encryption.type);
                if ((gPMF != PMF_INVALID)|| (gEncType != ENCTYPE_INVALID))
                    system_cmd_set_f("wpa_cli -g/tmp/global%d -i %s scan_cache flush", assocReq->phyhandle, intfName);
            }
            gPMF = rppStaHandle.addStaReq[staNum].pmftype;
            gEncType = rppStaHandle.addStaReq[staNum].encryption.type;
            rc = rpp_association_process(assocReq->phyhandle, intfName, staNum);
        }

        // Set pending message flag to notify monitor thread to release assocStatLock
        staAssocHdl[assocReq->phyhandle].pendingMsg = 1;
        pthread_mutex_lock( &assocStatLock[assocReq->phyhandle]);
        staAssocHdl[assocReq->phyhandle].pendingMsg = 0;
        stainfo = &staAssocHdl[assocReq->phyhandle].staCountInfo[0];
        for (index = 0; index < RPP_MAX_STA_SUPPORTED; index++, stainfo++) {
            if (stainfo->staNum == staNum) {
                stainfo->assocReqStatus = RPP_SET_ASOCIATE_REQSTATE;
                stainfo->deassocnotify =  RPP_DEASSOC_NOTIFY_UNSET;
                break;
            }
            //break;
        }
        pthread_mutex_unlock( &assocStatLock[assocReq->phyhandle] );
        rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
        if (rc < 0) {
            perror ("send_eth_msgto_fpga()");
            SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
        }
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_associate_req_fun()_exit");
    return rc;
}

/******************************************************************************
 * Function Name    : rpp_deassociate_req
 * Description      : This Function is used to deassociate from AP.
 ******************************************************************************/
int32_t rpp_deassociate_req (int8_t *buf)
{
    uint32_t   staNum = 0;
    int32_t   rc = 0;
    uint32_t  index = 0;
    struct staInfo *stainfo = NULL;

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_deassociate_req_fun()_start");

    RppMessageHead *msghdr = (RppMessageHead *)buf;
    DeAssocReq* deassocReq = (DeAssocReq *)msghdr->body;

    REMAP_PHY_HANDLE(deassocReq->phyhandle);

    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->deassocReq.phyhandle:%d", deassocReq->phyhandle);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->deassocReq.stahandle:0x%x", deassocReq->stahandle);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->deassocReq.stahandle:%d(in decimal)",deassocReq->stahandle);
    {
        char respBuf[RPPMSG_DEASSOC_RESP_SZ];
        RppMessageHead *msghdr = (RppMessageHead *) respBuf;
        msghdr->cat = RPP_MSG_RESP;
        msghdr->type = RPP_MSG_DEASSOC_RESP;
        msghdr->len = sizeof(respBuf)- RPPMSG_HDR_SIZE;
        DeAssocResp *resp = (DeAssocResp*)msghdr->body;
        resp->errcode = 0;

        staNum = deassocReq->stahandle;

        // Set pending message flag to notify monitor thread to release assocStatLock
        staAssocHdl[deassocReq->phyhandle].pendingMsg = 1;
        pthread_mutex_lock( &assocStatLock[deassocReq->phyhandle]);
        staAssocHdl[deassocReq->phyhandle].pendingMsg = 0;

        /* To deassociate the station */
        rpp_dissociation_process(deassocReq->phyhandle,"sta",staNum);
        stainfo = &staAssocHdl[deassocReq->phyhandle].staCountInfo[0];
        for (index = 0; index < RPP_MAX_STA_SUPPORTED; index++, stainfo++) {
            if (stainfo->staNum == staNum) {
                stainfo->assocReqStatus = RPP_UNSET_ASOCIATE_REQSTATE;
                break;
            }
        }
        pthread_mutex_unlock( &assocStatLock[deassocReq->phyhandle] );
        rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
        if (rc < 0) {
            perror ("send_eth_msgto_fpga()");
            SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
        }
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_deassociate_req_fun()_exit");
    return rc;
}

/******************************************************************************
 * Function Name    : rpp_send_assoc_state
 * Description      : This Function is used to send associate notification.
 ******************************************************************************/
int32_t rpp_send_assocstate(struct staInfo *stainfo, uint32_t associateState, uint32_t errCode)
{
    char buf[RPPMSG_ASSOCNTF_REQ_SZ];
    int32_t rc = 0;

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_send_assocstate_fun()_start");
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->phyhandle:%d", stainfo->phyHandle);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->stahandle:%d", stainfo->staHandle);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->station state:%d", associateState);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->error code:%d", errCode);

    RppMessageHead *msghdr = (RppMessageHead *)buf;
    msghdr->cat = RPP_MSG_REQ;
    msghdr->type = RPP_MSG_ASSOCSTATE_NOTF;
    msghdr->len = sizeof(AssocStateNtfy);

    if (associateState == STATE_ASSOCIATE_FAILED) {

        /* To deassociate the station -interface should not be removed as reason code need to be fetched */
       system_cmd_set_f("ifconfig sta%u down", stainfo->staNum);
       system_cmd_set_f("wpa_cli -i sta%u disable_network 0",  stainfo->staNum);
       system_cmd_set_f("wpa_cli -i sta%u remove_network 0",  stainfo->staNum);
    }

    if (stainfo->apbssid == NULL) {
        SYSLOG_PRINT(LOG_ERR, "\nERR_MSG------->Memory is not allocated");
        return -1;
    }
    /*
     After host entity received AssocStateNotification request from slave entity it look up StationMap
     according to station handle. If it’s valid station it notify host application.
     */
    AssocStateNtfy *assocState = (AssocStateNtfy *)msghdr->body;
    assocState->phyhandle = stainfo->phyHandle;
    REMAP_PHY_HANDLE(assocState->phyhandle);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->assocstate phyhandle:%d", assocState->phyhandle);

    assocState->stahandle = stainfo->staHandle;
    memcpy (assocState->bssid, stainfo->apbssid, sizeof (assocState->bssid));
    memcpy(gPrevAPbssid[stainfo->staNum].mac_address, stainfo->apbssid, ETHER_MAC_ADDR_LEN * sizeof(uint8_t));
    assocState->state = associateState;
    assocState->errcode = errCode;
    /*Notification to host with state */	
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->Notification sending for phyHndl[%d] and staHndl[%d] with state[%d].",
        assocState->phyhandle, assocState->stahandle, assocState->state);
    rc = send_eth_async_msgto_fpga(buf, sizeof(buf));
    if (rc < 0) {
        perror ("send_eth_msgto_fpga()");
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
    }

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_send_assocstate_fun()_exit");
    return rc;
}

/******************************************************************************
 * Function Name    : rpp_send_neighbor_report
 * Description      : This Function is used to send neighbor report
 ******************************************************************************/
int32_t rpp_send_neighbor_report(NeighborReportStats *NRRStats)
{
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_send_neighbor_report_fun()_start");
    int32_t rc = 0;
    size_t bufsz = RPPMSG_NEIGHBOR_REPORT_STATS_REQ_SZ + (NRRStats->nbrofneighboraps * sizeof(NeighborReport));
    char buf[bufsz];
    NeighborReportStats *NRRMsg = NULL;

    if (NRRStats == NULL) {
        SYSLOG_PRINT(LOG_ERR, "\nERR_MSG------->Neighbor report stats is NULL");
        return RPP_APP_RET_NULL_POINTER;
    }

    RppMessageHead *msghdr = (RppMessageHead *)buf;
    msghdr->cat = RPP_MSG_REQ;
    msghdr->type = RPP_MSG_NEIGHBOR_REPORT_STATS_UPDATE;
    msghdr->len = sizeof(buf)- RPPMSG_HDR_SIZE;
    NRRMsg = (NeighborReportStats *)msghdr->body;
    memcpy(NRRMsg, NRRStats, msghdr->len);
    REMAP_PHY_HANDLE(NRRMsg->phyhandle);

    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->NRRMsg phyhandle:%d", NRRMsg->phyhandle);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->NRRMsg stahandle:%d", NRRMsg->stahandle);

    rc = send_eth_async_msgto_fpga(buf, sizeof(buf));
    if (rc < 0) {
        perror ("send_eth_msgto_fpga()");
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
    }

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_send_neighbor_report_fun()_exit");
    return rc;
}

/******************************************************************************
 * Function Name    : rpp_fastBss_transit_req
 * Description      : This Function is used to manually initiate 802.11r procedure
 ******************************************************************************/
int32_t rpp_fastBss_transit_req (int8_t *buf)
{
    int32_t   rc = 0;
    char      tempBuf[RPP_APP_BUFF_SIZE] = "\0";
    char      iwCmd[RPP_APP_BUFF_SIZE] = "\0";
    uint8_t   staNum = 0;
    int8_t    staAssocFlag = 0;
    int8_t    cmpVal = -1;
    int32_t   totalSta = 0;
    int32_t   count = 0;
    int32_t   index = 0;
    uint8_t   assocAPMac[ETHER_MAC_ADDR_LEN] = "\0";
    char      respBuf[RPPMSG_FBT_RESP_SZ];
    char      ftcmd[RPP_APP_DEFNUM_SIX] = "\0";

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_fastBss_transit_req_fun()_start");

    /*
       After received FastBssTransit request slave check if station is associated.
       If station is associated and target AP is valid (not the current AP and valid
       target BSS) trigger FastBssTransit on specified station.
     */

    RppMessageHead *msghdr = (RppMessageHead *)buf;
    FBTReq* fbtReq = (FBTReq *)msghdr->body;

    RppMessageHead *respmsghdr = (RppMessageHead *) respBuf;
    respmsghdr->cat = RPP_MSG_RESP;
    respmsghdr->type = RPP_MSG_FBT_RESP;
    respmsghdr->len = sizeof(respBuf)- RPPMSG_HDR_SIZE;
    FBTResp *resp = (FBTResp *)respmsghdr->body;
    resp->errcode = 0;

    REMAP_PHY_HANDLE(fbtReq->phyhandle);

    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->fbtReq.phyhandle:%d",fbtReq->phyhandle);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->fbtReq.stahandle:%d",fbtReq->stahandle);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->fbtReq.target:%s",util_mac_addr_to_str(fbtReq->targetap));
    rc = rpp_validate_phyhandle(fbtReq->phyhandle);
    if (rc != FAST_BSS_TRANSIT_INVALID_PHY_HANDLE) {
        /* Find the total number of stations */
        totalSta = rppStaHandle.totalCount;
        /* Find the station number */
        for (count = 0; count < totalSta; count++) {
            if  (!((rppStaHandle.staHandle[count] == fbtReq->stahandle)
                        && (rppStaHandle.phy[count] == fbtReq->phyhandle))) {
                continue;
            } else {
                /* Compute the station number */
                rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwconfig sta%u |grep \"Access Point:\" |cut -d \":\" -f 4", staNum);
                char *cmd = NULL;
                cmd = strstr(tempBuf,"Not-Associated");
                if (cmd == NULL) {
                    staAssocFlag = RPP_APP_DEFNUM_ONE;
                    for (index = RPP_APP_DEFNUM_FOUR; index < RPP_APP_DEFNUM_TEN; index++) {
                        rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwconfig sta%u |grep \"Access Point:\" |cut -d \":\" -f %d", staNum, index);
                        assocAPMac[index - RPP_APP_DEFNUM_FOUR] = strtol(tempBuf, NULL, 16);
                    }
                } else {
                    SYSLOG_PRINT(LOG_INFO, "\nDEBUG_MSG------->Fastbss not possible : Station is not associated");
                    /* Give some error code value */
                }
                break;
            }
        }
       if (staAssocFlag == RPP_APP_DEFNUM_ONE) {
            cmpVal = memcmp (fbtReq->targetap, &assocAPMac[0], sizeof (fbtReq->targetap));
            if (cmpVal != 0) {
                memset(ftcmd, 0, sizeof(ftcmd));
                if (rppStaHandle.addStaReq[staNum].fbtcfg.overds)
                    strcpy(ftcmd, "ft_ds");
                else
                    strcpy(ftcmd, "roam");
                strcpy(&iwCmd[strlen(iwCmd)], util_mac_addr_to_str(fbtReq->targetap));
                system_cmd_set_f("wpa_cli -i sta%d %s %s", staNum, ftcmd, iwCmd);
                staAssocHdl[fbtReq->phyhandle].staCountInfo[fbtReq->stahandle].staRoamTrigger = true;
                memcpy(staAssocHdl[fbtReq->phyhandle].staCountInfo[fbtReq->stahandle].targetApbssid, fbtReq->targetap, sizeof(uint8_t) * ETHER_MAC_ADDR_LEN);
            }
        }
    } else {
        resp->errcode = FAST_BSS_TRANSIT_INVALID_PHY_HANDLE;
    }

    /* Give some error code value */
    rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
    if (rc < 0) {
        perror ("send_eth_msgto_fpga()");
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_fastBss_transit_req_fun()_exit");
    return rc;
}

/******************************************************************************
 * Function Name    : rpp_get_pidofprocess
 * Description      : This Function is used to get the pid of process
 ******************************************************************************/
int32_t rpp_get_pidofprocess(char *pName, char *infName, char *pidValue, char *tempPid)
{
    char    tempBuf[RPP_APP_BUFF_SIZE] = "\0";
    char*   tempStr;
    int32_t rc = 0;
    int32_t   count = 0;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_get_pidofprocess_fun()_start");

    rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "pgrep -f \"%s %s\"", pName, infName);
    tempStr = pidValue;
    for(count = 0; count < strlen(tempBuf) ; count++) {
        *tempStr = tempBuf[count];
        tempStr++;
        if(tempBuf[count] == '\n') {
            tempStr--;
            *tempStr = '\0';
            tempStr = tempPid;
        }
    }
    SYSLOG_PRINT(LOG_DEBUG,"\n DEBUG_MSG-------> for process (%s %s) pidValue is : %s\n",pName, infName, pidValue);
    SYSLOG_PRINT(LOG_DEBUG,"\n DEBUG_MSG-------> for process (%s %s) tempPid is : %s\n",pName, infName, tempPid);
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_get_pidofprocess_fun()_exit");
    return rc;
}

/*****************************************************************************
* Function Name    : rpp_get_neighbor_report
* Description      : This function is used to get the neighbor report from
*                     wpa_supplicant and send to wlanmgr
******************************************************************************/
int32_t rpp_get_neighbor_report(uint32_t phyHandle, uint32_t staHandle)
{
    char buf[RPP_APP_BUFF_SIZE];
    int32_t rc = 0;
    uint8_t nbrOfAPInList = 0;
    NeighborReportStats *NRRStats = NULL;

    /* TODO:Once the ctrl interface support is added for get_neigh_report_stats command, we plan to move to rpp_wpa_ctrl_helper.c */
    system_cmd_get_f(buf, sizeof(buf), "wpa_cli -i sta%u get_neigh_report_stats", staHandle);

    if (phyHandle > RPP_NUM_OF_RADIO) {
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->Invalid phyHandle %d", phyHandle);
        return -1;
    }

    nbrOfAPInList = atoi(buf);
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->Number of NeighborAPs in List= %d\n", nbrOfAPInList);

    if (nbrOfAPInList == 0)  {
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG-------> Not valid neighbor APs information\n"); 
        return -1;
    }

    NRRStats = malloc(sizeof(NeighborReportStats) + (nbrOfAPInList * sizeof(NeighborReport)));
    if (NRRStats == NULL) {
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->Memory allocation for Neighbor report failed\n");
        return RPP_APP_RET_MALLOC_FAILED;
    }
    memset(NRRStats, 0, sizeof(NeighborReportStats) + (nbrOfAPInList * sizeof(NeighborReport)));
    NRRStats->phyhandle = phyHandle;
    NRRStats->stahandle = staHandle;

    rc = rpp_parse_neighbor_report(buf, NRRStats, nbrOfAPInList);
    if (rc < 0) {
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->Error in parsing the neighbor report information\n");
        return rc;
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->NRRStats->nbrofneighboraps = %d\n",NRRStats->nbrofneighboraps);

    if (NRRStats->nbrofneighboraps > 0)
        rc = rpp_send_neighbor_report(NRRStats);

    free(NRRStats);
    NRRStats = NULL;

    return rc;
}

/******************************************************************************
 * Function Name    : rpp_capturemode_req
 * Description      : This Function is used to handle the options of monitor
                      daemon.
 ******************************************************************************/
int32_t rpp_capturemode_req(int8_t *buf)
{
    char    infName[RPP_INFNAME_BUFF_SIZE];
    char    tempBuf[RPP_APP_BUFF_SIZE] = "\0";
    int32_t port_to_capdaemon = 0;
    int32_t capdaemon_RGLR_port_to_host = 0;
    int32_t capdaemon_SDR_port_to_host = 0;
    int32_t staCount = 0;
    int32_t rc = 0;
    float freqValue = 0.0;
    char* tempStr = NULL;
    int32_t captureMode =0;

    char    respBuf[RPPMSG_CAPTURE_RESP_SZ];
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_capturemode_req_fun()_start");
    captureParam_t param_t;
    monitordResponse_t p_mResp;

    RppMessageHead *msghdlr = (RppMessageHead *)buf;
    CaptureControlReq *capCtrlReq = (CaptureControlReq *)msghdlr->body;

    REMAP_PHY_HANDLE(capCtrlReq->phyhandle);

    SYSLOG_PRINT(LOG_DEBUG,"\n DEBUG_MSG------->capCtrlReq->phyhandle : %d \n",capCtrlReq->phyhandle);
    SYSLOG_PRINT(LOG_DEBUG,"\n capCtrlReq->cmd : %d \n",capCtrlReq->cmd);
    SYSLOG_PRINT(LOG_DEBUG,"\n capCtrlReq->caphnd : %d \n",capCtrlReq->caphnd);
    SYSLOG_PRINT(LOG_DEBUG,"\n capCtrlReq->CapFilterLen : %d \n",capCtrlReq->CapFilterLen);
    SYSLOG_PRINT(LOG_DEBUG,"\n capCtrlReq->CapFilter : %s ",capCtrlReq->CapFilter);
    int32_t loop = 0;
    for(loop=0;loop<capCtrlReq->CapFilterLen;loop++){
        SYSLOG_PRINT(LOG_DEBUG,"%x ",capCtrlReq->CapFilter[loop]);
    }
    memset (respBuf, 0, sizeof (respBuf));
    RppMessageHead *msghdr = (RppMessageHead *) respBuf;
    msghdr->cat = RPP_MSG_RESP;
    msghdr->type = RPP_MSG_CAPCTRL_RESP;
    msghdr->len = sizeof(respBuf) - RPPMSG_HDR_SIZE;
    CaptureControlResp  *resp = (CaptureControlResp *)msghdr->body;
    resp->errcode = CAP_MODE_SUCCESS;

    rc = rpp_validate_phyhandle(capCtrlReq->phyhandle);
    if (rc != CAP_MODE_INVALID_PHY) {

        memset(infName, 0, sizeof (infName));
        sprintf(infName, "mon%d", capCtrlReq->phyhandle);

        if (infName == NULL) {
            //resp->errcode = CAP_MODE_UNDEFINED_ERROR;
        }
        captureMode= RppPhyCaptureHdl[capCtrlReq->phyhandle].captureMode;
        rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwconfig %s | wc -l", infName);
        staCount = atoi(tempBuf);

        if (staCount == 0) {
            SYSLOG_PRINT(LOG_DEBUG,"\n DEBUG_MSG------->No monitor interface is present so creating here in capture function. \n");

            /* Create the mon interface */
            system_cmd_set_f("wlanconfig %s create wlanmode monitor wlandev wifi%d", infName, capCtrlReq->phyhandle);

	    //New command added to fix issue regular capture acting as sniffer, for sniffer value is 0, regular its 1
            system_cmd_set_f("iwpriv %s set_cap_mode %d",infName,captureMode - 1);
            /* We need to make it monitor interface up */
            system_cmd_set_f("ifconfig %s up",infName);

            if( RppPhyCaptureHdl[capCtrlReq->phyhandle].captureMode == SNIFFER_MODE ) {
                system_cmd_set_f("iwpriv %s chwidth %d", infName, RppPhyCaptureHdl[capCtrlReq->phyhandle].snifferMode_chwidth);

                /* Configure the ctl_freq */
                rc = rpp_configure_freq_settings(infName, RppPhyCaptureHdl[capCtrlReq->phyhandle].snifferMode_ctl_freq, RPP_APP_DEFNUM_TWO, capCtrlReq->phyhandle);

                if (RppPhyCaptureHdl[capCtrlReq->phyhandle].snifferMode_chwidth == CBW_80P80Mhz) {
                    /* Configure the center_freq2 */
                    system_cmd_set_f("iwpriv %s mode 11AHE80_80",infName);
                    freqValue = (float)(RppPhyCaptureHdl[capCtrlReq->phyhandle].snifferMode_center_freq2/1000.0f);
                    system_cmd_set_f("iwpriv %s cfreq2 %0.3fG",infName,freqValue);
                }
            }
        }
        if ( capCtrlReq->phyhandle == 0) {
            port_to_capdaemon = CAPDAEMON_RADIO_0_PORT;
            capdaemon_RGLR_port_to_host = CAPDAEMON_PORT_NUMBER_5G;
            capdaemon_SDR_port_to_host = CAPDAEMON_SDR_PORT_NUMBER_5G;
        } else if ( capCtrlReq->phyhandle == RPP_APP_DEFNUM_ONE) {
            port_to_capdaemon = CAPDAEMON_RADIO_1_PORT;
            capdaemon_RGLR_port_to_host = CAPDAEMON_PORT_NUMBER_2G;
            capdaemon_SDR_port_to_host = CAPDAEMON_SDR_PORT_NUMBER_2G;
        } else if ( capCtrlReq->phyhandle == RPP_APP_DEFNUM_TWO) {
            port_to_capdaemon = CAPDAEMON_RADIO_2_PORT;
            capdaemon_RGLR_port_to_host = CAPDAEMON_PORT_NUMBER_5G2;
            capdaemon_SDR_port_to_host = CAPDAEMON_SDR_PORT_NUMBER_5G2;
        }
        memset(infName, 0, sizeof (infName));
        sprintf(infName, "mon%d", capCtrlReq->phyhandle);
        if (infName == NULL) {
            //resp->errcode = CAP_MODE_UNDEFINED_ERROR;
        }
        switch (capCtrlReq->cmd) {
            case CMD_START:
                SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_START Case for [%d]   <<<<< 0 - Regular , 1 - SDR >>>>>.",
                    capCtrlReq->caphnd);
                if ((RppPhyCaptureHdl[capCtrlReq->phyhandle].gProcStatus != CAP_PROCCESS_STARTED) &&
                    (RppPhyCaptureHdl[capCtrlReq->phyhandle].gProcStatus_SDR != CAP_PROCCESS_STARTED)) {
                    system_cmd_set_f("%s %d", capdaemonName, port_to_capdaemon);

                    while(1) {
                        rc = rpp_receive_datafrom_monitord(&p_mResp, capCtrlReq->phyhandle);
                        SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_   p_mResp.msgHeader = 0x%x",p_mResp.msgHeader);
                        SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_   p_mResp.msgID = 0x%x",p_mResp.msgID);
                        if(p_mResp.msgHeader != CMD_RPPS_HEADER) {
                            SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_Response is not from monitord process.");
                            resp->errcode = CAP_MODE_FAILED;
                            break;
                        }

                        if(p_mResp.msgID == CMD_MONITORD_IS_UP) {
                            SYSLOG_PRINT(LOG_INFO, "\n DEBUG_MSG------->Daemon is started for phyhandle: %d.",
                                capCtrlReq->phyhandle);
                            break;
                        }
                    }
                } else {
                    /* Daemon is Already Running */
                    SYSLOG_PRINT(LOG_DEBUG,"\n DEBUG_MSG------->Daemon is Already runnning for phyhandle: %d.",
                        capCtrlReq->phyhandle);
                }

                if (capCtrlReq->caphnd == CAP_HND_REGULAR) {
                    param_t.msgHeader = CMD_RPPS_HEADER;
                    param_t.rppsCmd = CMD_REGULAR_START;
                    strcpy(param_t.mon_interface, infName);
                    param_t.capture_mode = gsetModeInfo[capCtrlReq->phyhandle].captype;
                    param_t.overwrite_flag = gsetModeInfo[capCtrlReq->phyhandle].buffflag;
                    param_t.tcp_port_no = capdaemon_RGLR_port_to_host;
                    param_t.filter_len = (char)(gsetModeInfo[capCtrlReq->phyhandle].filterexplen);
                    tempStr = (char *) malloc (((int)param_t.filter_len + 1) * sizeof(char));
                    if (tempStr != NULL) {
                        tempStr = (char *)param_t.filter_expression;
                        strcpy(tempStr, gsetModeInfo[capCtrlReq->phyhandle].filterexp);
                        tempStr[(int)param_t.filter_len + 1] = '\0';
                    }

                    ///////////////////////////////////////////////////////////////////////////////////////
                    SYSLOG_PRINT(LOG_INFO, "\n RGLR capture Informations sent to monitord.....");
                    SYSLOG_PRINT(LOG_INFO, "\n param_t.msgHeader:0x%x",param_t.msgHeader);
                    SYSLOG_PRINT(LOG_INFO, "\n param_t.rppsCmd:0x%x",param_t.rppsCmd);
                    SYSLOG_PRINT(LOG_INFO, "\n param_t.mon_interface:%s",param_t.mon_interface);
                    SYSLOG_PRINT(LOG_INFO, "\n param_t.capture_mode:0x%x",param_t.capture_mode);
                    SYSLOG_PRINT(LOG_INFO, "\n param_t.overwrite_flag:ox%x",param_t.overwrite_flag);
                    SYSLOG_PRINT(LOG_INFO, "\n param_t.tcp_port_no:%d",param_t.tcp_port_no);
                    SYSLOG_PRINT(LOG_INFO, "\n param_t.filter_len:%d",(int)param_t.filter_len);
                    SYSLOG_PRINT(LOG_INFO, "\n param_t.filter_expression:%s",param_t.filter_expression);
                    ///////////////////////////////////////////////////////////////////////////////////////
                } else {
                    param_t.msgHeader = CMD_RPPS_HEADER;
                    param_t.rppsCmd = CMD_SDR_START;
                    //strcpy(param_t.mon_interface, infName);
                    strcpy(param_t.mon_interface, "mon0");
                    param_t.capture_mode = gsetModeInfo[capCtrlReq->phyhandle].captype;
                    param_t.overwrite_flag = gsetModeInfo[capCtrlReq->phyhandle].buffflag;
                    param_t.tcp_port_no = capdaemon_SDR_port_to_host;
                    param_t.filter_len = (char)(capCtrlReq->CapFilterLen);
                    tempStr = (char *) malloc (((int)param_t.filter_len + 1) * sizeof(char));
                    if (tempStr != NULL) {
                        tempStr = (char *)param_t.filter_expression;
                        strcpy(tempStr, capCtrlReq->CapFilter);
                        tempStr[(int)param_t.filter_len + 1] = '\0';
                    }

                    SYSLOG_PRINT(LOG_INFO, "\n SDR capture Informations sent to monitord.....");
                    SYSLOG_PRINT(LOG_INFO, "\n param_t.msgHeader:0x%x",param_t.msgHeader);
                    SYSLOG_PRINT(LOG_INFO, "\n param_t.rppsCmd:0x%x",param_t.rppsCmd);
                    SYSLOG_PRINT(LOG_INFO, "\n param_t.mon_interface:%s",param_t.mon_interface);
                    SYSLOG_PRINT(LOG_INFO, "\n param_t.capture_mode:0x%x",param_t.capture_mode);
                    SYSLOG_PRINT(LOG_INFO, "\n param_t.overwrite_flag:ox%x",param_t.overwrite_flag);
                    SYSLOG_PRINT(LOG_INFO, "\n param_t.tcp_port_no:%d",param_t.tcp_port_no);
                    SYSLOG_PRINT(LOG_INFO, "\n param_t.filter_len:%d",(int)param_t.filter_len);
                    SYSLOG_PRINT(LOG_INFO, "\n param_t.filter_expression:%s",param_t.filter_expression);
                    ///////////////////////////////////////////////////////////////////////////////////////
                }

                rc = rpp_send_datato_monitord(&param_t, capCtrlReq->phyhandle);

                while(1) {
                    rc = rpp_receive_datafrom_monitord(&p_mResp, capCtrlReq->phyhandle);
                    SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_   p_mResp.msgHeader = 0x%x",p_mResp.msgHeader);
                    SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_   p_mResp.msgID = 0x%x",p_mResp.msgID);
                    if(p_mResp.msgHeader != CMD_RPPS_HEADER) {
                        SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_Response is not from monitord process.");
                        resp->errcode = CAP_MODE_FAILED;
                        break;
                    }

                    if(p_mResp.msgID == CMD_MONITORD_ACK) {
                        if (capCtrlReq->caphnd == CAP_HND_REGULAR)
                            RppPhyCaptureHdl[capCtrlReq->phyhandle].gProcStatus = CAP_PROCCESS_STARTED;
                        if (capCtrlReq->caphnd == CAP_HND_SDR)
                            RppPhyCaptureHdl[capCtrlReq->phyhandle].gProcStatus_SDR = CAP_PROCCESS_STARTED;
                        SYSLOG_PRINT(LOG_INFO, "\n DEBUG_MSG------->Got monitord acknowledge for phyhandle: %d.",
                            capCtrlReq->phyhandle);
                        resp->errcode = CAP_MODE_SUCCESS;
                        resp->pktcount = 0;
                        resp->streamcrvport = 0;
                        break;
                    }

                    if((p_mResp.msgID == ERR_UNKNOWN_OP_CMD) || (p_mResp.msgID == ERR_INVALID_MON_INTF) ||
                            (p_mResp.msgID == ERR_INVALID_CAP_MODE) || (p_mResp.msgID == ERR_INVALID_OVR_WR_FLAG) ||
                            (p_mResp.msgID == ERR_INVALID_FILTER_EXPR) || (p_mResp.msgID == ERR_MEM_ALLOC) ||
                            (p_mResp.msgID == ERR_RPPHOST_SOC_FAIL) || (p_mResp.msgID == ERR_RPPHOST_SND_FAIL)) {
                        SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_Some Error occurred in Monitord.");
                        resp->errcode = CAP_MODE_FAILED;
                        break;
                    }
                }
                break;

            case CMD_STOP:
                SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_STOP Case for [%d]   <<<<< 0 - Regular , 1 - SDR >>>>>.",
                    capCtrlReq->caphnd);

                if (capCtrlReq->caphnd == CAP_HND_REGULAR) {
                    if (RppPhyCaptureHdl[capCtrlReq->phyhandle].gProcStatus == CAP_PROCCESS_STOPPED) {
                        SYSLOG_PRINT(LOG_INFO,"Regular_CAP_PROCESS_ALREADY_STOPPED_NO_NEED_TO_STOP_AGAIN\n");
                        return rc;
                    }
                    param_t.msgHeader = CMD_RPPS_HEADER;
                    param_t.rppsCmd = CMD_REGULAR_STOP;
                    strcpy(param_t.mon_interface, infName);
                    param_t.capture_mode = gsetModeInfo[capCtrlReq->phyhandle].captype;
                    param_t.overwrite_flag = gsetModeInfo[capCtrlReq->phyhandle].buffflag;
                    param_t.tcp_port_no = capdaemon_RGLR_port_to_host;
                    param_t.filter_len = (char)(gsetModeInfo[capCtrlReq->phyhandle].filterexplen);
                    tempStr = (char *) malloc (((int)param_t.filter_len + 1) * sizeof(char));
                    if (tempStr != NULL) {
                        tempStr = (char *)param_t.filter_expression;
                        strcpy(tempStr, gsetModeInfo[capCtrlReq->phyhandle].filterexp);
                        tempStr[(int)param_t.filter_len + 1] = '\0';
                    }

                } else {
                    if (RppPhyCaptureHdl[capCtrlReq->phyhandle].gProcStatus_SDR == CAP_PROCCESS_STOPPED){
                        SYSLOG_PRINT(LOG_INFO,"SDR_CAP_PROCESS_ALREADY_STOPPED_NO_NEED_TO_STOP_AGAIN\n");
                        return rc;
                    }
                    param_t.msgHeader = CMD_RPPS_HEADER;
                    param_t.rppsCmd = CMD_SDR_STOP;
                    //strcpy(param_t.mon_interface, infName);
                    strcpy(param_t.mon_interface, "mon0");
                    param_t.capture_mode = gsetModeInfo[capCtrlReq->phyhandle].captype;
                    param_t.overwrite_flag = gsetModeInfo[capCtrlReq->phyhandle].buffflag;
                    param_t.tcp_port_no = capdaemon_SDR_port_to_host;
                    param_t.filter_len = (char)(capCtrlReq->CapFilterLen);
                    tempStr = (char *) malloc (((int)param_t.filter_len + 1) * sizeof(char));
                    if (tempStr != NULL) {
                        tempStr = (char *)param_t.filter_expression;
                        strcpy(tempStr, capCtrlReq->CapFilter);
                        tempStr[(int)param_t.filter_len + 1] = '\0';
                    }
                }

                rc = rpp_send_datato_monitord(&param_t, capCtrlReq->phyhandle);

                while(1) {

                    rc = rpp_receive_datafrom_monitord(&p_mResp, capCtrlReq->phyhandle);
                    SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_   p_mResp.msgHeader = 0x%x",p_mResp.msgHeader);
                    SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_   p_mResp.msgID = 0x%x",p_mResp.msgID);
                    if(p_mResp.msgHeader != CMD_RPPS_HEADER) {
                        SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_Response is not from monitord process.");
                        resp->errcode = CAP_MODE_FAILED;
                        break;
                    }
                    if(p_mResp.msgID == CMD_MONITORD_ACK) {
                        if (capCtrlReq->caphnd == CAP_HND_REGULAR)
                            RppPhyCaptureHdl[capCtrlReq->phyhandle].gProcStatus = CAP_PROCCESS_STOPPED;
                        else if (capCtrlReq->caphnd == CAP_HND_SDR)
                            RppPhyCaptureHdl[capCtrlReq->phyhandle].gProcStatus_SDR = CAP_PROCCESS_STOPPED;
                        SYSLOG_PRINT(LOG_INFO, "\n DEBUG_MSG------->Daemon is stopped for phyhandle: %d.",
                            capCtrlReq->phyhandle);
                        resp->errcode = CAP_MODE_SUCCESS;
                        resp->pktcount = 0;
                        resp->streamcrvport = 0;
                        break;
                    }

                    if((p_mResp.msgID == ERR_UNKNOWN_OP_CMD) || (p_mResp.msgID == ERR_INVALID_MON_INTF) ||
                            (p_mResp.msgID == ERR_INVALID_CAP_MODE) || (p_mResp.msgID == ERR_INVALID_OVR_WR_FLAG) ||
                            (p_mResp.msgID == ERR_INVALID_FILTER_EXPR) || (p_mResp.msgID == ERR_MEM_ALLOC) ||
                            (p_mResp.msgID == ERR_RPPHOST_SOC_FAIL) || (p_mResp.msgID == ERR_RPPHOST_SND_FAIL)) {
                        SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_Some Error occurred in Monitord in STOP.");
                        resp->errcode = CAP_MODE_FAILED;
                        break;
                    }
                }
                break;

            case CMD_RETRIEVE:
                SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_RETRIEVE Case for [%d]   <<<<< 0 - Regular , 1 - SDR >>>>>.",capCtrlReq->caphnd);

                if (capCtrlReq->caphnd == CAP_HND_REGULAR) {
                    if (RppPhyCaptureHdl[capCtrlReq->phyhandle].gProcStatus == CAP_PROCCESS_RETRIEVED){
                        SYSLOG_PRINT(LOG_INFO,"REGULAR_RETRIEVE_PROCESS_ALREADY_STOPPED_NO_NEED_TO_STOP_AGAIN\n");
                        return rc;
                    }
                    param_t.msgHeader = CMD_RPPS_HEADER;
                    param_t.rppsCmd = CMD_REGULAR_RETRIVE;
                    strcpy(param_t.mon_interface, infName);
                    param_t.capture_mode = gsetModeInfo[capCtrlReq->phyhandle].captype;
                    param_t.overwrite_flag = gsetModeInfo[capCtrlReq->phyhandle].buffflag;
                    param_t.tcp_port_no = capdaemon_RGLR_port_to_host;
                    param_t.filter_len = (char)(gsetModeInfo[capCtrlReq->phyhandle].filterexplen);
                    tempStr = (char *) malloc (((int)param_t.filter_len + 1) * sizeof(char));
                    if (tempStr != NULL) {
                        tempStr = (char *)param_t.filter_expression;
                        strcpy(tempStr, gsetModeInfo[capCtrlReq->phyhandle].filterexp);
                        tempStr[(int)param_t.filter_len + 1] = '\0';
                    }
                } else {
                    if (RppPhyCaptureHdl[capCtrlReq->phyhandle].gProcStatus_SDR == CAP_PROCCESS_RETRIEVED){
                        SYSLOG_PRINT(LOG_INFO,"SDR_RETRIEVE_PROCESS_ALREADY_STOPPED_NO_NEED_TO_STOP_AGAIN\n");
                        return rc;
                    }
                    param_t.msgHeader = CMD_RPPS_HEADER;
                    param_t.rppsCmd = CMD_SDR_RETRIVE;
                    //strcpy(param_t.mon_interface, infName);
                    strcpy(param_t.mon_interface, "mon0");
                    param_t.capture_mode = gsetModeInfo[capCtrlReq->phyhandle].captype;
                    param_t.overwrite_flag = gsetModeInfo[capCtrlReq->phyhandle].buffflag;
                    param_t.tcp_port_no = capdaemon_SDR_port_to_host;
                    param_t.filter_len = (char)(capCtrlReq->CapFilterLen);
                    tempStr = (char *) malloc (((int)param_t.filter_len + 1) * sizeof(char));
                    if (tempStr != NULL) {
                        tempStr = (char *)param_t.filter_expression;
                        strcpy(tempStr, capCtrlReq->CapFilter);
                        tempStr[(int)param_t.filter_len + 1] = '\0';
                    }
                }
                rc = rpp_send_datato_monitord(&param_t, capCtrlReq->phyhandle);
                while(1) {
                    rc = rpp_receive_datafrom_monitord(&p_mResp, capCtrlReq->phyhandle);
                    SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_   p_mResp.msgHeader = 0x%x",p_mResp.msgHeader);
                    SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_   p_mResp.msgID = 0x%x",p_mResp.msgID);
                    if(p_mResp.msgHeader != CMD_RPPS_HEADER) {
                        SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_Response is not from monitord process.");
                        resp->errcode = CAP_MODE_FAILED;
                        break;
                    }
                    if(p_mResp.msgID == CMD_MONITORD_PKT_CNT) {
                        SYSLOG_PRINT(LOG_INFO,"\n DEBUG_MSG------->Got Messae id : 0x%x\n", p_mResp.msgID);
                        if (capCtrlReq->caphnd == CAP_HND_REGULAR) {
                            RppPhyCaptureHdl[capCtrlReq->phyhandle].gProcStatus = CAP_PROCCESS_RETRIEVED;
                            resp->streamcrvport = capdaemon_RGLR_port_to_host;
                        }
                        if (capCtrlReq->caphnd == CAP_HND_SDR) {
                            RppPhyCaptureHdl[capCtrlReq->phyhandle].gProcStatus_SDR = CAP_PROCCESS_RETRIEVED;
                            resp->streamcrvport = capdaemon_SDR_port_to_host;
                        }
                        resp->pktcount = p_mResp.packetCount;
                        SYSLOG_PRINT(LOG_INFO,"\n DEBUG_MSG------->Port Number : %d\n", resp->streamcrvport);
                        SYSLOG_PRINT(LOG_INFO,"\n DEBUG_MSG------->pkt Count : %d\n", resp->pktcount);

                        msghdr->cat = RPP_MSG_RESP;
                        msghdr->type = RPP_MSG_CAPCTRL_RESP;
                        msghdr->len = sizeof(respBuf) - RPPMSG_HDR_SIZE;
                        resp->errcode = CAP_MODE_SUCCESS;
                        rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
                        if (rc < 0) {
                            perror ("send_eth_msgto_fpga()");
                            SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
                        }
                        packetSent = RPP_APP_DEFNUM_ONE;
                    } else if(p_mResp.msgID == CMD_MONITORD_COMPLETE) {
                        /* Got COMPLETE STRING Message */
                        /* 1. Kill the capture daemon */
                        SYSLOG_PRINT(LOG_INFO,"\n DEBUG_MSG------->Got Messae id : 0x%x\n", p_mResp.msgID);
                        break;
                    }
                    if((p_mResp.msgID == ERR_UNKNOWN_OP_CMD) || (p_mResp.msgID == ERR_INVALID_MON_INTF) ||
                            (p_mResp.msgID == ERR_INVALID_CAP_MODE) || (p_mResp.msgID == ERR_INVALID_OVR_WR_FLAG) ||
                            (p_mResp.msgID == ERR_INVALID_FILTER_EXPR) || (p_mResp.msgID == ERR_MEM_ALLOC) ||
                            (p_mResp.msgID == ERR_RPPHOST_SOC_FAIL) || (p_mResp.msgID == ERR_RPPHOST_SND_FAIL)) {
                        SYSLOG_PRINT(LOG_INFO, "\n INFO_MSG_Some Error occurred in Monitord while retrieving the packets.");
                        resp->errcode = CAP_MODE_FAILED;
                        break;
                    }

                }
                if( RppPhyCaptureHdl[capCtrlReq->phyhandle].captureMode == REGULAR_CAP_MODE ) {
                    /* Down the mon interface */
                    system_cmd_set_f("ifconfig %s down",infName);
                    /* Deleting the mon interface */
                    system_cmd_set_f("wlanconfig %s destroy",infName);
                }
                break;
            default:
                SYSLOG_PRINT(LOG_ERR, "\n ERR_MSG------->Invalid command");
                break;
        }
    } else {
        SYSLOG_PRINT(LOG_ERR,"\n ERR_MSG------->Invalid PHY Handle\n");
        resp->errcode = CAP_MODE_INVALID_PHY;
    }
    if(packetSent == RPP_APP_DEFNUM_ONE) {
        packetSent = 0;
        return rc;
    }
    msghdr->cat = RPP_MSG_RESP;
    msghdr->type = RPP_MSG_CAPCTRL_RESP;
    msghdr->len = sizeof(respBuf) - RPPMSG_HDR_SIZE;
    SYSLOG_PRINT(LOG_INFO,"\n DEBUG_MSG------->Information carried in respBuf to fpga socket msghdr->type: %d\n",
        msghdr->type );
    rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
    if (rc < 0) {
        perror ("send_eth_msgto_fpga()");
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_capturemode_req_fun()_exit");
    return rc;
}

/******************************************************************************
 * Function Name    : rpp_calculate_prevchannel_value
 * Description      : This Function is used to get the pre frequency value
 ******************************************************************************/
int32_t rpp_calculate_prevchannel_value(int32_t fValue, uint8_t phyHandle)
{
    int32_t channelNum = 0;
    int32_t bwIndex = 0;
    int32_t channelIndex = 0;
    uint8_t setChannelIdx = 0;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_calculate_prevchannel_value_fun()_start");

    if (phyHandle == RPP_APP_DEFNUM_ONE) {
        channelNum = ((fValue - 5000) / 5);
        for (bwIndex = 0; bwIndex < WIFI5G_MAX; bwIndex++) {
            for (channelIndex = 0; channelIndex < wifi5Garrsize[bwIndex]; channelIndex++) {
                if(channelNum == wifi2_4gbw[bwIndex][channelIndex]) {
                    setChannelIdx = RPP_APP_DEFNUM_ONE;
                    break;
                }
            }
            if (setChannelIdx)
                break;
        }
        channelNum = wifi2_4gbw[bwIndex][channelIndex - RPP_APP_DEFNUM_ONE];
        if (channelNum != 0) {
            return ((channelNum * 5) + 5000);
        }
    } else {
        channelNum = (fValue - 2412) / 5;
        channelNum -= 5;
        for (bwIndex = 0; bwIndex < WIFI2_4G_MAX; bwIndex++) {
            for (channelIndex = 0; channelIndex < wifi2_4Garrsize[bwIndex]; channelIndex++) {
                if(channelNum == wifi2_4gbw[bwIndex][channelIndex]) {
                    setChannelIdx = RPP_APP_DEFNUM_ONE;
                    break;
                }
            }
            if (setChannelIdx) {
                break;
            }
        }
        channelNum = wifi2_4gbw[bwIndex][channelIndex - RPP_APP_DEFNUM_ONE];
        if (channelNum != 0) {
            return (((channelNum - 1) * 5) + 2412);
        }
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_calculate_prevchannel_value_fun()_exit");
    return 0;
}

/******************************************************************************
 * Function Name    : rpp_configure_freq_settings
 * Description      : This Function is used to configure the frequency value
 ***************************rpp_configure_freq_settings***************************************************/
int32_t rpp_configure_freq_settings(char *infName, int32_t freqValue, uint32_t index,
                                    uint32_t phyHandle)
{
    char    iwCmd[RPP_APP_BUFF_SIZE] = "\0";
    char    tempBuf[RPP_APP_BUFF_SIZE] = "\0";
    int32_t rc = 0;
    float   frequency = 0.0, cfgValue = 0.0;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_configure_freq_settings_fun()_start");

    if (!index) {
            return -1;
    } else {
        memset (iwCmd, 0, sizeof (iwCmd));
        frequency = (float)(freqValue/1000.0f);
        //sprintf (iwCmd, "iwconfig %s freq %0.3fG", infName, frequency);
        /* Used to set the frequency for specific mon device */
        rc = system_cmd_set_f("iwconfig %s freq %0.3fG", infName, frequency);
        freqValue = frequency * 1000;
        rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwconfig %s |grep Frequency |cut -d \":\" -f 3 |cut -d \" \" -f 1", infName);
        cfgValue = atof(tempBuf) * 1000;

        if (freqValue != cfgValue) {
            if (rpp_configure_freq_settings(infName, rpp_calculate_prevchannel_value(freqValue, phyHandle), (index - 1), phyHandle) < 0) {
                rc = -1;
            }
        }
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_configure_freq_settings_fun()_exit");
    return rc;
}
/******************************************************************************
 * Function Name    : rpp_setmode_req
 * Description      : This Function is used to set the mode request.
 ******************************************************************************/
int32_t rpp_setmode_req (int8_t *buf)
{
    char    iwCmd[RPP_APP_BUFF_SIZE] = "\0";
    char    respBuf[RPPMSG_SETMODE_RESP_SZ];
    char    tempBuf[RPP_APP_BUFF_SIZE] = "\0";
    char    infName[RPP_INFNAME_BUFF_SIZE];
    int32_t rc = 0;
    int32_t staCount = 0;
    char pidValue[15];
    char tempPid[15];
    float freqValue = 0.0;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_setmode_req_fun()_start");
    eCaptureType capType;

#ifdef DEBUG
    SYSLOG_PRINT(LOG_DEBUG,"\n DEBUG_MSG------->Received Buffer : \n");
    for (index = 0; index < 1024; index++) {
        if (i==15) {
            SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->");
            i = 0;
        }
        SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->0x%x  ", 0xff & buf[index]);
        i++;
    }
#endif

    RppMessageHead *msghdlr = (RppMessageHead *)buf;
    SetModeReq     *setmodeReq = (SetModeReq *)msghdlr->body;
    RppMessageHead *msghdr = (RppMessageHead *) respBuf;
    SetModeResp    *resp = (SetModeResp *)msghdr->body;

    REMAP_PHY_HANDLE(setmodeReq->phyhandle);

    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->setmodeReq.phyhandle:%d",setmodeReq->phyhandle);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->setmodeReq.mode:%d",setmodeReq->mode);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->setmodeReq.bw:%d",setmodeReq->bw);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->setmodeReq.ctl_freq:%d",setmodeReq->ctl_freq);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->setmodeReq.center_freq1:%d",setmodeReq->center_freq1);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->setmodeReq.center_freq2:%d",setmodeReq->center_freq2);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->setmodeReq.buffAction:%d",setmodeReq->buffaction);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->setmodeReq.capfilterlen:%d",setmodeReq->capfilterlen);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->setmodeReq.capfilter:%s",setmodeReq->capfilter);

    msghdr->cat = RPP_MSG_RESP;
    msghdr->type = RPP_MSG_SETMODE_RESP;
    msghdr->len = sizeof(respBuf)- RPPMSG_HDR_SIZE;
    resp->errcode = 0;
    capType = RPP_CAPTURE_TYPE_OFFLINE;

    rc = rpp_validate_phyhandle(setmodeReq->phyhandle);
    if (rc != SET_MODE_INVALID_PHY_HANDLE) {
        memset(infName, 0, sizeof (infName));
        sprintf(infName, "mon%d", setmodeReq->phyhandle);
        gsetModeInfo[setmodeReq->phyhandle].buffflag = setmodeReq->buffaction;
        gsetModeInfo[setmodeReq->phyhandle].captype = capType;
        gsetModeInfo[setmodeReq->phyhandle].filterexplen = setmodeReq->capfilterlen;
        gsetModeInfo[setmodeReq->phyhandle].filterexp = (char *) malloc ((setmodeReq->capfilterlen + 1) * sizeof(char));
        if (gsetModeInfo[setmodeReq->phyhandle].filterexp != NULL) {
            strcpy(gsetModeInfo[setmodeReq->phyhandle].filterexp, setmodeReq->capfilter);
            gsetModeInfo[setmodeReq->phyhandle].filterexp[setmodeReq->capfilterlen + 1] = '\0';
        }
        if (setmodeReq->mode == SNIFFER_MODE) {
            /* TBD - if Regular capture mode packet comes */
            /* 1. Check already station is available or not */
            if (setmodeReq->phyhandle == 0) {
                memset (iwCmd, 0, sizeof (iwCmd));
                rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwconfig | grep -A 2 \"sta\" | grep \"ESSID\" | cut -d \" \" -f 1 | grep \"staX%d\"| wc -l", setmodeReq->phyhandle);
                staCount = atoi(tempBuf);
                if (staCount != 0) {
                    //resp->errcode = SET_MODE_CANNOT_CHANGE_TO_SNIFFER_MODE;
                    //setErr = RPP_APP_DEFNUM_ONE;
                }
            } else if (setmodeReq->phyhandle == 1) {
                rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwconfig | grep -A 2 \"sta\" | grep \"ESSID\" | cut -d \" \" -f 1 | grep \"staX%d\"| wc -l", setmodeReq->phyhandle);
                staCount = atoi(tempBuf);
                if (staCount != 0) {
                    //resp->errcode = SET_MODE_CANNOT_CHANGE_TO_SNIFFER_MODE;
                    //setErr = RPP_APP_DEFNUM_ONE;
                }
            } else if (setmodeReq->phyhandle == 2) {
                rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwconfig | grep -A 2 \"sta\" | grep \"ESSID\" | cut -d \" \" -f 1 | grep \"staX%d\"| wc -l", setmodeReq->phyhandle);
                staCount = atoi(tempBuf);
                if (staCount != 0) {
                    //resp->errcode = SET_MODE_CANNOT_CHANGE_TO_SNIFFER_MODE;
                    //setErr = RPP_APP_DEFNUM_ONE;
                }
            }
            /* End of station check */
            if (staCount <= RPP_APP_DEFNUM_ONE) {
                rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwconfig %s | wc -l", infName);
                staCount = atoi(tempBuf);

                if (staCount == 0) {
                    /* 2. Create the mon interface */
                    memset (iwCmd, 0, sizeof (iwCmd));
                system_cmd_set_f("wlanconfig %s create wlanmode monitor wlandev wifi%d", infName, setmodeReq->phyhandle);
                }
            }
            //New command added to fix issue regular capture acting as sniffer, for sniffer value is 0, regular its 1
            system_cmd_set_f("iwpriv %s set_cap_mode %d",infName,setmodeReq->mode - 1);
            /* We need to make it monitor interface up */
            system_cmd_set_f("ifconfig %s up", infName);
            system_cmd_set_f("iwpriv %s chwidth %d", infName, setmodeReq->bw);
            RppPhyCaptureHdl[setmodeReq->phyhandle].snifferMode_chwidth = setmodeReq->bw;
            RppPhyCaptureHdl[setmodeReq->phyhandle].snifferMode_ctl_freq = setmodeReq->ctl_freq;
            RppPhyCaptureHdl[setmodeReq->phyhandle].snifferMode_center_freq2 = setmodeReq->center_freq2;

            /* 4. Configure the ctl_freq */
            rc = rpp_configure_freq_settings(infName, setmodeReq->ctl_freq, RPP_APP_DEFNUM_TWO, setmodeReq->phyhandle);

            if (setmodeReq->bw == CBW_80P80Mhz) {
                /* 5. Configure the center_freq2 */
                system_cmd_set_f("iwpriv %s mode 11AHE80_80", infName);
                freqValue = (float)(setmodeReq->center_freq2/1000.0f);
                memset (iwCmd, 0, sizeof (iwCmd));
                sprintf (iwCmd, "iwpriv %s cfreq2 %0.3fG", infName, freqValue);
                system_cmd_set_f("%s", iwCmd);
            }
            RppPhyCaptureHdl[setmodeReq->phyhandle].captureMode = SNIFFER_MODE;
        } else if (setmodeReq->mode == REGULAR_CAP_MODE) {

            if ( staPerRadioHdl[setmodeReq->phyhandle].active_stations_per_radio > 0) {
                rc = system_cmd_get_f(tempBuf, sizeof(tempBuf), "iwconfig %d | wc -l",infName);
                staCount = atoi(tempBuf);

                if (staCount == 0) {
                    /* 2. Create the mon interface */
                    system_cmd_set_f("wlanconfig %s create wlanmode monitor wlandev wifi%d", infName, setmodeReq->phyhandle);
                }
                //New command added to fix issue regular capture acting as sniffer, for sniffer value is 0, regular its 1
                system_cmd_set_f("iwpriv %s set_cap_mode %d",infName,setmodeReq->mode - 1);
                RppPhyCaptureHdl[setmodeReq->phyhandle].captureMode = 0xff;//setting it default value to skip operation in capture function
            } else {
                RppPhyCaptureHdl[setmodeReq->phyhandle].captureMode = REGULAR_CAP_MODE;
            }
        } else if (setmodeReq->mode == STATION_MODE) {
            /* 1. Deleting the mon interface */
			system_cmd_set_f("ifconfig %s down", infName);
            system_cmd_set_f("wlanconfig %s destroy", infName);
            /* 2. Kill the deamon */
            /* Get the pid of daemon */
            rc = rpp_get_pidofprocess(capdaemonName, infName, &pidValue[0], &tempPid[0]);
            if ((strcmp(gPidValInfo[setmodeReq->phyhandle].pidVal, &pidValue[0]) == 0) ||
                    (strcmp(gPidValInfo[setmodeReq->phyhandle].pidVal, &tempPid[0]) == 0)){
                memset (iwCmd, 0, sizeof (iwCmd));
                if (strcmp(gPidValInfo[setmodeReq->phyhandle].pidVal, &pidValue[0]) == 0) {
                    system_cmd_set_f("kill -9 %s", pidValue);
                } else if (strcmp(gPidValInfo[setmodeReq->phyhandle].pidVal, &tempPid[0]) == 0) {
                    system_cmd_set_f("kill -9 %s", tempPid);
                }
            }
            RppPhyCaptureHdl[setmodeReq->phyhandle].captureMode = STATION_MODE;
        }
    } else {
        resp->errcode = SET_MODE_INVALID_PHY_HANDLE;
    }
    rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
    if (rc < 0) {
        perror ("send_eth_msgto_fpga()");
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_setmode_req_fun()_exit");
    return rc;
}
/******************************************************************************
 * Function Name    : rpp_clear_station_stats_req
 * Description      : This Function is used to clear the stats for specified
 *                    station.
 ******************************************************************************/
int32_t rpp_clear_station_stats_req (int8_t *buf)
{
    int32_t rc = 0;
    char respBuf[RPPMSG_CLRSTAT_RESP_SZ];
    uint8_t  staNum = 0;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_clear_station_stats_req_fun()_start");
    RppMessageHead *msghdr = (RppMessageHead *)buf;
    ClearStatsReq* clrstatsReq = (ClearStatsReq *)msghdr->body;

    msghdr = (RppMessageHead *) respBuf;
    msghdr->cat = RPP_MSG_RESP;
    msghdr->type = RPP_MSG_CLRSTATS_RESP;
    msghdr->len = sizeof(respBuf)- RPPMSG_HDR_SIZE;
    ClearStatsResp *resp = (ClearStatsResp*)msghdr->body;
    resp->errcode = 0;

    REMAP_PHY_HANDLE(clrstatsReq->phyhandle);

    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->clrstatsReq.phyhandle:%d",clrstatsReq->phyhandle);
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->clrstatsReq.stahandle:%d",clrstatsReq->stahandle);
    if(clrstatsReq->stahandle == -1) {
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->Invalid Station!!!");
    } else {
        /* Compute the station number */
        staNum = rppStaHandle.staNum[clrstatsReq->stahandle];
        /*Clear the statistics for perticular station*/
        /*iwpriv sta0 txrx_stats 257*/
        system_cmd_set_f("iwpriv sta%d txrx_stats %d", staNum, RPP_CLEAR_STATS_REQ);
    }
    rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
    if (rc < 0) {
        perror ("send_eth_msgto_fpga()");
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_clear_station_stats_req_fun()_exit");
    return rc;
}

/******************************************************************************
 * Function Name    : rpp_set_log_level_req
 * Description      : This Function is used to change slave entity’s log level.
 *                    station.
 ******************************************************************************/
int32_t rpp_set_log_level_req (int8_t *buf)
{
    int32_t rc = 0;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_set_log_level_req_fun()_start");
    RppMessageHead *msghdr = (RppMessageHead *)buf;
    SetLogLevelReq* setlogReq = (SetLogLevelReq *)msghdr->body;
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->setlogReq.severity:%d",setlogReq->severity);
    {
        char respBuf[RPPMSG_SETLOG_RESP_SZ];
        RppMessageHead *msghdr = (RppMessageHead *) respBuf;
        msghdr->cat = RPP_MSG_RESP;
        msghdr->type = RPP_MSG_SETLOG_RESP;
        msghdr->len = sizeof(respBuf)- RPPMSG_HDR_SIZE;
        SetLogLevelResp *resp = (SetLogLevelResp *)msghdr->body;

        /*
         From the code, set log level need to be done. It can be
         either kernel log, syslog or any other log.
         */
        resp->errcode = 0;
        rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
        if (rc < 0) {
            perror ("send_eth_msgto_fpga()");
            SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
        }
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_set_log_level_req_fun()_exit");
    return rc;
}

/******************************************************************************
 * Function Name    : rpp_send_log_Report_req
 * Description      : This Function is used to send log report to FPGA.
 *                    station.
 ******************************************************************************/
int32_t rpp_send_log_Report_req (int8_t *buf)
{
    int32_t rc = 0;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_send_log_Report_req_fun()_start");
    /*
     For diagnostics purpose RPP slave entity need to report log messages that
     RPP host interested on to RPP host through LogReport message. Each log
     message should be less than 256 bytes and should be terminated by ‘\0’.
     */
    RppMessageHead *msghdr = (RppMessageHead *)buf;
    SetLogLevelReq* setlogReq = (SetLogLevelReq *)msghdr->body;
    SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->setlogReq.severity:%d",setlogReq->severity);
    {
        char respBuf[RPPMSG_SETLOG_RESP_SZ];
        RppMessageHead *msghdr = (RppMessageHead *) respBuf;
        msghdr->cat = RPP_MSG_RESP;
        msghdr->type = RPP_MSG_SETLOG_RESP;
        msghdr->len = sizeof(respBuf)- RPPMSG_HDR_SIZE;
        SetLogLevelResp *resp = (SetLogLevelResp *)msghdr->body;
        resp->errcode = 0;
        rc = send_eth_msgto_fpga(respBuf, sizeof(respBuf));
        if (rc < 0) {
            perror ("send_eth_msgto_fpga()");
            SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->send_eth_msgto_fpga()");
        }
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_send_log_Report_req_fun()_exit");
    return rc;
}

