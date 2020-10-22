#include "rpp_core.h"
#include "rpp_message.h"
#include "rpp_wpactrl_helper.h"
#include "common.h"
#include "common/wpa_ctrl.h"
#include <stdarg.h>

// Construct command from format and arguments
#define CONSTRUCT_CMD_FORMAT(cmd, cmdLen, cmdFormat)    \
                                                        if (cmdFormat != NULL) { \
                                                            va_list args; \
                                                            va_start(args, cmdFormat); \
                                                            vsnprintf(cmd, cmdLen, cmdFormat, args); \
                                                            va_end(args); \
                                                        }

extern staAssocInfo staAssocHdl[RPP_NUM_OF_RADIO];

/*****************************************************************************
* Function Name    : _open_wpa_ctrl_conn
* Description      : Open wpa_ctrl connection of radio index
* Returns          : Status 0 on success otherwise on failure
******************************************************************************/
static struct wpa_ctrl *_open_wpa_ctrl_conn(int32_t radioIndex)
{
    struct wpa_ctrl *wpaCtrl = NULL;
    char path[64] = "\0";

    /* Open wpa control interface */
    sprintf(path, "/tmp/global%d", radioIndex);
    do {
        wpaCtrl = wpa_ctrl_open(path);
        if (wpaCtrl == NULL) {
            // Failed to open wpa control interface, sleep 1 second and retry
            SYSLOG_PRINT(LOG_INFO, "\nDEBUG_INFO------->failed to open wpa control interface for control path: %s", path);
            sleep(1);
        } else {
            break;
        }
    } while (1);
    return wpaCtrl;
}

/*****************************************************************************
* Function Name    : open_wpa_ctrl_conn
* Description      : Open wpa_ctrl connection of radio index (for both monitor and message parser thread)
* Returns          : Status 0 on success otherwise on failure
******************************************************************************/
int open_wpa_ctrl_conn(int32_t radioIndex)
{
    struct wpa_ctrl *wpaCtrl = NULL;
    char path[64] = "\0";

    close_wpa_ctrl_conn(radioIndex);

    // Open wpa control interface for monitor thread 
    wpaCtrl = _open_wpa_ctrl_conn(radioIndex);
    if (wpaCtrl == NULL) {
        SYSLOG_PRINT(LOG_ERR, "\nERR_MSG------->open monitor thread wpa control interface for control path: %s failed", path);
        return 1;
    } else {
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->open monitor thread wpa control interface (%p) for control path: %s succeeded", wpaCtrl, path);
        staAssocHdl[radioIndex].monIntf = wpaCtrl;
    }

    // Open wpa control interface for message parser thread
    wpaCtrl = _open_wpa_ctrl_conn(radioIndex);
    if (wpaCtrl == NULL) {
        SYSLOG_PRINT(LOG_ERR, "\nERR_MSG------->open message parser thread wpa control interface for control path: %s failed", path);
        return 2;
    } else {
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->open message parser thread wpa control interface (%p) for control path: %s succeeded", wpaCtrl, path);
        staAssocHdl[radioIndex].msgParserIntf = wpaCtrl;
    }
    return 0;
}

/*****************************************************************************
* Function Name    : close_wpa_ctrl_conn
* Description      : Close wpa_ctrl connection of radio index and unset to array
******************************************************************************/
void close_wpa_ctrl_conn(int32_t radioIndex)
{
    // Close wpa control interface for monitor thread 
    if (staAssocHdl[radioIndex].monIntf != NULL) {
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->close monitor thread wpa control interface (%p) of radio index: %d", staAssocHdl[radioIndex].monIntf, radioIndex);
        wpa_ctrl_close(staAssocHdl[radioIndex].monIntf);
        staAssocHdl[radioIndex].monIntf = NULL;
    }

    // Close wpa control interface for message parser thread 
    if (staAssocHdl[radioIndex].msgParserIntf != NULL) {
        SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->close message parser thread wpa control interface (%p) of radio index: %d", staAssocHdl[radioIndex].msgParserIntf, radioIndex);
        wpa_ctrl_close(staAssocHdl[radioIndex].msgParserIntf);
        staAssocHdl[radioIndex].msgParserIntf = NULL;
    }
}

/*****************************************************************************
* Function Name    : wpa_msg_parser
* Description      : Parse wpa control replay message
* Returns          : Status 0 on success otherwise on failure
******************************************************************************/
static int wpa_msg_parser(StaStateInfo *stateInfo, const char *buf)
{
#define PARAM_REASON_CODE "reason_code = "
#define PARAM_WPA_STATE "wpa_state="
#define PARAM_BSSID "bssid="

    // Reply message example: reason_code= 0 bssid=14:59:c0:4e:c6:f7 freq=5540 ssid=Revanche_AX12_AP_5G id=0 mode=station pairwise_cipher=NONE group_cipher=NONE key_mgmt=NONE wpa_state=COMPLETED
    // Parse station state
    char *c_Ptr = strstr(buf, PARAM_WPA_STATE);
    if (c_Ptr == NULL) {
        return 1;
    }

    int ret = 0;
    c_Ptr += strlen(PARAM_WPA_STATE);
    if (memcmp(c_Ptr, "COMPLETED", 9) == 0) {
        stateInfo->assocStatus = STATE_ASSOCIATED;
        // Parse bssid
        c_Ptr = strstr(buf, PARAM_BSSID);
        if (c_Ptr == NULL) {
            // Failure, invalid bssid after associated
            ret = 1;
        } else {
            c_Ptr += strlen(PARAM_BSSID);
            sscanf(c_Ptr, MAC_STRING_FORMAT, (char*)&stateInfo->bssid[0], (char*)&stateInfo->bssid[1], (char*)&stateInfo->bssid[2],
                                             (char*)&stateInfo->bssid[3], (char*)&stateInfo->bssid[4], (char*)&stateInfo->bssid[5]);
        }
    } else {
        //Assoc failure reason code is getting updated properly only in these 2 stats
        if ((memcmp(c_Ptr, "DISCONNECTED", 12) == 0) || (memcmp(c_Ptr, "SCANNING", 8) == 0)){
            stateInfo->assocStatus = STATE_ASSOCIATE_FAILED;
            c_Ptr = strstr(buf, PARAM_REASON_CODE);
            if (c_Ptr == NULL) {
                //Failure, reason code parameter not found
                SYSLOG_PRINT(LOG_DEBUG, "\nDEBUG_MSG------->Failure: Reason code parameter missing");
                ret = 1;
            } else {
                c_Ptr += strlen(PARAM_REASON_CODE);
                stateInfo->reasonCode = atoi((char*)c_Ptr);
            }
        }   
    }
    return ret;
}

/*****************************************************************************
* Function Name    : get_sta_state
* Description      : Use monitor thread wpa control interface to get station 
*                    state from wpa control reply message.
* Returns          : Status 0 on success otherwise on failure
******************************************************************************/
int get_sta_state(StaStateInfo *stateInfo, int radioIndex, char *intfName, uint8_t staIndex)
{
    if (staAssocHdl[radioIndex].monIntf == NULL) {
        SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->invalid monitor thread wpa control interface for radio#%d", radioIndex);
        return 1;
    }
    
    char cmd[64];
    char buf[4096];
    size_t len = sizeof(buf) - 1;
    sprintf(cmd, "IFNAME=%s%u STATUS", intfName, staIndex);
    pthread_mutex_lock( &staAssocHdl[radioIndex].wpaCtrlLock );
    int ret = wpa_ctrl_request(staAssocHdl[radioIndex].monIntf, cmd, strlen(cmd), buf, &len, NULL);
    if (ret != 0) {
        pthread_mutex_unlock( &staAssocHdl[radioIndex].wpaCtrlLock );
        SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->command: %s failed", cmd);
        return ret;
    }
    pthread_mutex_unlock( &staAssocHdl[radioIndex].wpaCtrlLock );

    buf[len] = '\0';
    //SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->wpa control request command: %s succeed with reply: %s", cmd, buf);
    return wpa_msg_parser(stateInfo, buf);
}

/*****************************************************************************
* Function Name    : config_network_intf 
* Description      : Use message parser thread wpa control interface to configure 
*                    network interface via wpa control interface
* Returns          : Status 0 on success otherwise on failure
* Note             : The command format can be found in wpa_cli.c file
******************************************************************************/
int config_network_intf(uint32_t radioIndex, const char *cmdFormat, ...)
{
    if (staAssocHdl[radioIndex].msgParserIntf == NULL) {
        SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->invalid message parser thread wpa control interface for radio#%d", radioIndex);
        return 1;
    }

#define CTRL_CMD_LEN 256

    char cmd[CTRL_CMD_LEN];
    char buf[4096];
    size_t len = sizeof(buf) - 1;
    // Example command: IFNAME=staX0 SET_NETWORK 0 bssid "Revanche_AX12_AP"
    CONSTRUCT_CMD_FORMAT(cmd, CTRL_CMD_LEN, cmdFormat);
    pthread_mutex_lock( &staAssocHdl[radioIndex].wpaCtrlLock );
    int ret = wpa_ctrl_request(staAssocHdl[radioIndex].msgParserIntf, cmd, strlen(cmd), buf, &len, NULL);
    if (ret != 0) {
        pthread_mutex_unlock( &staAssocHdl[radioIndex].wpaCtrlLock );
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->command: %s failed", cmd);
        return ret;
    }

    pthread_mutex_unlock( &staAssocHdl[radioIndex].wpaCtrlLock );
    buf[len] = '\0';
    if (os_memcmp(buf, "FAIL", 4) == 0 || os_memcmp(buf, "UNKNOWN COMMAND", 15) == 0) {
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->command: %s failed with reply: %s", cmd, buf);
        return 1;
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->command: %s succeed with reply: %s", cmd, buf);
    return ret;
}
