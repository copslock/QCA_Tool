#include "rpp_dataparsing.h"
#include "rpp_core.h"

RppStaHandleStruct rppStaHandle;
float supportedratetable [] = {1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54};

/******************************************************************************
 * Function Name    : rpp_stahandle_init
 * Description      : This Function is used to initialize rppStaHandle structure.
 ******************************************************************************/
void rpp_stahandle_init(void)
{
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_stahandle_init_fun()_start");
    memset (&rppStaHandle, 0, sizeof (rppStaHandle));
    memset (&rppStaHandle.phy[0], -1, sizeof (rppStaHandle.phy));
    memset (&rppStaHandle.staNum[0], -1, sizeof (rppStaHandle.staNum));
    for (uint8_t stationIndex = 0; stationIndex < RPP_MAX_STA_SUPPORTED; stationIndex++)
        rppStaHandle.targetAPList[stationIndex] = NULL;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_stahandle_init_fun()_exit");
}

/******************************************************************************
 * Function Name    : rpp_sta_create_handler
 * Description      : This Function is used to handle STA creation for all cases
 ******************************************************************************/
bool rpp_sta_create_handler(uint8_t staHandleCase, uint8_t* addStaMac)
{
    bool isSuccess = false;
    uint8_t loopCount = 0;

    switch (staHandleCase) {
        case HANDLE_STA_DUPLICATE:
            while (loopCount != RPP_MAX_STA_SUPPORTED) { /* Check if a STA with same MAC address is already created and in DORMANT state to reuse */
                if ((rppStaHandle.staCreateStatus[loopCount] == STA_DORMANT) &&
                          (!memcmp (&rppStaHandle.addStaReq[loopCount].mac, addStaMac, sizeof(uint8_t) * 6))) {
                    SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->STA Entry already exists at %d, no need to create again \n", loopCount);
                    rppStaHandle.nextPos = loopCount;
                    rppStaHandle.staCreateStatus[loopCount] = STA_ACTIVE;
                    SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->STA%d going from DORMANT to ACTIVE state\n", loopCount);
                    isSuccess = true;
                    break;
                } else
                    loopCount++;
            }
            break;
        case HANDLE_STA_NEW:
            while (loopCount != RPP_MAX_STA_SUPPORTED) { /* Check for staIndex which is unused or empty slot */
                if (rppStaHandle.staCreateStatus[loopCount] == STA_NOT_CREATED) {
                    SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->Found STA%d index which is NOT_CREATED\n", loopCount);
                    rppStaHandle.nextPos = loopCount;
                    isSuccess = true;
                    break;
                } else
                    loopCount++;
            }
            break;
         case HANDLE_STA_COUNT_EXHAUST:
             while (loopCount != RPP_MAX_STA_SUPPORTED) {
                 if (rppStaHandle.staCreateStatus[loopCount] == STA_DORMANT) {
                     SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->Selected DORMANT STA%d for deletion \n", loopCount);
                     rppStaHandle.nextPos = loopCount;
                     system_cmd_set_f("wlanconfig sta%u destroy", loopCount);
                     rppStaHandle.staCreateStatus[loopCount] = STA_NOT_CREATED;
                     isSuccess = true;
                     break;
                 } else
                    loopCount++;
             }
             break;
         default:
             SYSLOG_PRINT(LOG_ERR, "ERROR_MSG------->Invalid option\n");
             break;
    }
    return isSuccess;
}

/******************************************************************************
 * Function Name    : rpp_stahandle_process
 * Description      : This Function is used to compute station number.
 ******************************************************************************/
int32_t rpp_stahandle_process(uint32_t staHandle, uint8_t phy, uint8_t command,
        uint8_t *staNum, AddStaReq *addStaReq)
{
    uint32_t loopCount = 0;
    int32_t errCode = RPP_APP_RET_SUCCESS;
    bool isSuccess = false;

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_stahandle_process_fun()_start");

    debug_print(DEBUG_DATA, "%s(): phy = %u Station handle = 0x%x\n", __func__, phy, staHandle);
    SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->%s(): phy = %u Station handle = 0x%x\n", __func__, phy, staHandle);

    if (staNum == NULL) {
        debug_print(DEBUG_INFO, "Invalid memory for station number \n");
        SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Invalid memory for station number \n");
        errCode = RPP_APP_RET_NULL_POINTER;
    }

    /* Command is add station */
    if (command == RPP_ADD_STA_CMD) {
        if (addStaReq == NULL) {
            debug_print(DEBUG_INFO, "Memory is invalid for addStaReq \n");
            SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Memory is invalid for addStaReq \n");
            errCode = RPP_APP_RET_NULL_POINTER;
        } else {
            SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->Check for DORMANT STA with matching MAC address\n");
            isSuccess = rpp_sta_create_handler(HANDLE_STA_DUPLICATE, addStaReq->mac);                           
            if (isSuccess)
                errCode = RPP_APP_RET_EXISTS;
            else {
                SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->No DORMANT STA with matching MAC found, need to find new empty slot\n");
                isSuccess = rpp_sta_create_handler(HANDLE_STA_NEW, NULL);
                if (isSuccess)
                    errCode = RPP_APP_RET_SUCCESS;
                else {
                    SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->STA entries exhausted, delete a DORMANT STA \n");
                    isSuccess = rpp_sta_create_handler(HANDLE_STA_COUNT_EXHAUST, NULL);
                    if (isSuccess)
                        errCode = RPP_APP_RET_REPLACED;
                    else {
                        SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->DORMANT STA not found!!! \n");
                        errCode = RPP_APP_RET_COMMAND_FAILED;
                    }
                }
            }
            memcpy (&rppStaHandle.addStaReq[rppStaHandle.nextPos], addStaReq, sizeof (AddStaReq));
        }
        rppStaHandle.phy[rppStaHandle.nextPos] = phy;
        *staNum = rppStaHandle.nextPos;
        rppStaHandle.staNum[rppStaHandle.nextPos] = *staNum;
        rppStaHandle.staHandle[rppStaHandle.nextPos] = (uint32_t)*staNum;

        switch (rppStaHandle.addStaReq[rppStaHandle.nextPos].encryption.type) {
            case OPEN :
            case ENHANCED_OPEN :
                 break;

            case PERSONAL :
            case WPA3_PERSONAL :
            case WPA2_WPA3_PERSONAL :

                /* Store the passphrase */
                memcpy (&rppStaHandle.encryptionPersonal[rppStaHandle.nextPos],
                        &rppStaHandle.encryptionPersonalTemp, sizeof (EncryptionPersonal));
                break;

            case ENTERPRISE :
            case WPA3_ENTERPRISE :
                /* Store the EAP data */
                memcpy (&rppStaHandle.encryptionEap[rppStaHandle.nextPos],
                        &rppStaHandle.encryptionEapTemp, sizeof (EncryptionEAP));
                break;

            case WEP :
                /* Store the WEP data */
                memcpy (&rppStaHandle.encryptionWep[rppStaHandle.nextPos],
                        &rppStaHandle.encryptionWepTemp, sizeof (EncryptionWEP));
                break;
        }

        if ((rppStaHandle.totalCount != rppStaHandle.nextPos) &&
                (rppStaHandle.staNum[rppStaHandle.nextPos] == -1)) {
            rppStaHandle.nextPos++;
        } else {
            if ((errCode != RPP_APP_RET_REPLACED) && (errCode != RPP_APP_RET_EXISTS))
                rppStaHandle.totalCount++;
            rppStaHandle.activeCount++;
            rppStaHandle.nextPos = rppStaHandle.totalCount;
        }

    } /* Command is delete station */
    else if (command == RPP_DEL_STA_CMD) {
        if (staHandle == (uint32_t)(-1)) {
            /* Re-initalize the rpp station handle structure */
            rpp_stahandle_init();
            errCode = RPP_APP_RET_NULL_POINTER;
        }
        /* Search for staHandle  and compute the rppStaHandle.nextPos*/
        while (loopCount != RPP_MAX_STA_SUPPORTED) {
            if ((rppStaHandle.staHandle[loopCount] == (uint32_t)staHandle) &&
                    (rppStaHandle.phy[loopCount] == (int8_t)phy)) {
                *staNum = loopCount; /* Returning the Station Number */
                rppStaHandle.nextPos = loopCount;
                break;
            } else {
                loopCount++;
            }
        }

        if (rppStaHandle.totalCount != rppStaHandle.nextPos) {
             rppStaHandle.activeCount--;
        } else {
            /* nextPos will give the station number */
            rppStaHandle.nextPos--;
            rppStaHandle.activeCount--;
        }
    } else {
        debug_print(DEBUG_INFO, "Invalid command \n");
        SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Invalid command \n");
    }

    debug_print(DEBUG_DATA, "%s(): Station Number = %d Station handle = 0x%x\n", __func__, *staNum, staHandle);
    SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->%s(): Station Number = %d Station handle = 0x%x\n", __func__, *staNum, staHandle);
    SYSLOG_PRINT(LOG_DEBUG,"rpp_stahandle_process_fun()_exit");
    return errCode;
}

/******************************************************************************
 * Function Name    : rpp_fetch_string_output_from_cmd
 * Description      : This Function is used to fetch command output from console
 ******************************************************************************/
int32_t rpp_fetch_string_output_from_cmd(char *cmdInput, char *cmdOutput,
        int32_t cmdOutputSize, char *debugStr)
{
    char  *tempBuf = NULL;
    char  *str = NULL;
    FILE  *fp = NULL;
    int32_t errCode = RPP_APP_RET_SUCCESS;

    if ( (cmdInput == NULL) || (cmdOutput == NULL) || (cmdOutputSize <=0) ) {
        debug_print(DEBUG_INFO, "Invalid input argument \n");
        SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Invalid input argument \n");
        errCode = RPP_APP_RET_NULL_POINTER;
    } else {
        memset (cmdOutput, 0, cmdOutputSize);
        tempBuf = (char *) malloc(cmdOutputSize * sizeof (char));
        if (tempBuf == NULL) {
            debug_print(DEBUG_INFO, "Memory allocation failed\n" );
            SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Memory allocation failed\n" );
            errCode = RPP_APP_RET_MALLOC_FAILED;
        }
    }

    /* Open the command for reading. */
    fp = popen(cmdInput, "r");
    if (fp == NULL) {
        debug_print(DEBUG_INFO, "Failed to run command\n" );
        SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Failed to run command\n" );
        errCode = RPP_APP_RET_COMMAND_FAILED;
    }

    /* Read the output a line at a time - output it. */
    while (RPP_APP_DEFNUM_ONE) {
        str = fgets(tempBuf, cmdOutputSize -1 , fp);
        if (str == NULL) {
            errCode = RPP_APP_RET_READ_FAILED;
            //debug_print(DEBUG_DATA, "errCode = %d\n",errCode );
            //SYSLOG_PRINT(LOG_DEBUG, "errCode = %d\n",errCode );
            break;
        }
        strcat(cmdOutput, tempBuf);
    }

    free(tempBuf);
    /* close */
    pclose(fp);
    fflush(NULL);
    return errCode;
}

/******************************************************************************
 * Function Name    : rpp_set_supported_htmcs
 * Description      : This Function is used to set supported htmcs value.
 ******************************************************************************/
int32_t rpp_set_supported_htmcs(uint16_t htmcsVal,  uint8_t nssCount, int32_t *computedHtmcsVal)
{
    int32_t errCode = RPP_APP_RET_SUCCESS;
    uint8_t mcsVal = 0;
    uint8_t mcsIndex = 0;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_set_supported_htmcs_fun()_start");

    if (computedHtmcsVal == NULL) {
        debug_print(DEBUG_INFO, "%s() : Memory is not allocated\n", __func__);
        SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->%s() : Memory is not allocated\n", __func__);
        errCode = RPP_APP_RET_NULL_POINTER;
    }

    for (mcsIndex = 0; mcsIndex < HT_MCS_COUNT; mcsIndex++) {
        if ((htmcsVal >> mcsIndex) & RPP_APP_DEFNUM_ONE)
            mcsVal = mcsIndex;
    }

    //For 11n, nss 4 is max supported
    if (nssCount > HT_MAX_SMA_SUPPORT)
        nssCount = HT_MAX_SMA_SUPPORT;

    //Below value is needed for set11Nrates command, for 11ax device 11N Rates: 0x80-0x9F for HT MCS0..31
    *computedHtmcsVal = HT_MCS_START_INDEX + (HT_MCS_COUNT * (nssCount-1)) + mcsVal;
 
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_set_supported_htmcs_fun()_exit");
    return errCode;
}

/******************************************************************************
 * Function Name    : rpp_set_supported_mcs
 * Description      : This Function is used to set supported hemcs value and vhtmcs
 * Same function has been used to calculate for HE and VHT as inputs are coming similar, 
 * Based on mode differences are handled in calculation
******************************************************************************/
int32_t rpp_set_supported_mcs(uint16_t mcsVal, uint8_t nssCount, int8_t protocolMode, int8_t mcsIdMax, int32_t *computedRxmcsVal, int32_t *computedTxmcsVal,int8_t *txFixedMcs)
{
    int32_t errCode = RPP_APP_RET_SUCCESS;
    uint8_t streamNum = 0;
    uint8_t perSSHETxMCSVal = HEMCS_PER_STREAM_0_11;
    uint8_t perSSHERxMCSVal = HEMCS_PER_STREAM_0_11;

    uint16_t heTxmcs =0;
    uint16_t heRxmcs =0;
    uint16_t heTxmcsVal =0;
    uint16_t heRxmcsVal =0;
    bool ulMcsSet = false;
    //Default value to disable fixed transmisison
    *txFixedMcs = mcsIdMax;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_set_supported_mcs_fun()_start");

    //As per new implementation of UI, Upper 6 bits will have Rxmcs and lower 6 will have Tx mcs, enums define din rpp_message.g
    heTxmcs = mcsVal & HE_MCS_TX_POSN;
    heRxmcs = mcsVal & HE_MCS_RX_POSN;

    if ((computedTxmcsVal == NULL) || (computedRxmcsVal == NULL)){
        debug_print(DEBUG_INFO, "%s() : Memory is not allocated\n", __func__);
        SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->%s() : Memory is not allocated\n", __func__);
        errCode = RPP_APP_RET_NULL_POINTER;
    }

    if(heTxmcs == HEMCS_NONE) {
        perSSHETxMCSVal = HEMCS_PER_STREAM_NONE;
    } else if(heTxmcs == HEMCS_0_7) {
        perSSHETxMCSVal = HEMCS_PER_STREAM_0_7;
    } else if(heTxmcs == HEMCS_0_8) {
        perSSHETxMCSVal = VHTMCS_PER_STREAM_0_8;
    } else if (heTxmcs == HEMCS_0_9) {
        if (protocolMode == PROTO_AX)
           perSSHETxMCSVal = HEMCS_PER_STREAM_0_9;
        else 
           perSSHETxMCSVal = VHTMCS_PER_STREAM_0_9;
    } else if (heTxmcs == HEMCS_0_11) {
        perSSHETxMCSVal = HEMCS_PER_STREAM_0_11;
    //Uplink transmission is set for specific enum starting from 12
    } else if (heTxmcs > HEMCS_0_11 && heTxmcs<= HE_TX_TYPE_11) {
        ulMcsSet = true;
        *txFixedMcs = heTxmcs-HE_MCS_ID_MAX;
    }

    if(heRxmcs == HERxMCS_NONE) {
        perSSHERxMCSVal = HEMCS_PER_STREAM_NONE;
    } else if(heRxmcs == HERxMCS_0_7) {
        perSSHERxMCSVal = HEMCS_PER_STREAM_0_7;
    } else if(heRxmcs == HERxMCS_0_8) {
        perSSHERxMCSVal = VHTMCS_PER_STREAM_0_8;
    } else if (heRxmcs == HERxMCS_0_9) {
       if (protocolMode == PROTO_AX)
           perSSHERxMCSVal = HEMCS_PER_STREAM_0_9;
        else
           perSSHERxMCSVal = VHTMCS_PER_STREAM_0_9;
    } else if (heRxmcs == HERxMCS_0_11) {
        perSSHERxMCSVal = HEMCS_PER_STREAM_0_11;
    }

    for (streamNum = 0; streamNum < RPP_MAX_SPATIAL_STREAMS; streamNum++) {
        if (streamNum < nssCount) {
            heTxmcsVal = heTxmcsVal | (perSSHETxMCSVal << (streamNum * RPP_APP_DEFNUM_TWO));
            heRxmcsVal = heRxmcsVal | (perSSHERxMCSVal << (streamNum * RPP_APP_DEFNUM_TWO));

        } else {
            heTxmcsVal = heTxmcsVal | (HEMCS_PER_STREAM_NONE << (streamNum * RPP_APP_DEFNUM_TWO));
            heRxmcsVal = heRxmcsVal | (HEMCS_PER_STREAM_NONE << (streamNum * RPP_APP_DEFNUM_TWO));
        }
    }

    if (protocolMode == PROTO_AX) {
       *computedRxmcsVal = ((heRxmcsVal << 16) | heRxmcsVal);
       *computedTxmcsVal = ((heTxmcsVal << 16) | heTxmcsVal);
    }
    else {
        //VHTMCS value need to have 0xFFFF as 1st 16bits
        *computedRxmcsVal =  heRxmcsVal |= VHTMCS_RESERVED_FIELDS;
        *computedTxmcsVal =  heTxmcsVal |= VHTMCS_RESERVED_FIELDS;

    }

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_set_supported_mcs_fun()_exit");

    return errCode;
}

/******************************************************************************
 * Function Name    : gen_fixed_rate_param
 * Description      : This Function is used to parse parse mcs rate (base on phy mode)
 ******************************************************************************/
int32_t gen_fixed_rate_param(uint8_t preambleType, uint8_t nssVal, uint16_t mcsVal, int32_t *fixedRateVal)
{
    int32_t errCode = RPP_APP_RET_SUCCESS;
    uint8_t preambleTypeNum = 0;
    int32_t nssCount = 0;
    uint8_t txMcsVal = 0;

    if (fixedRateVal == NULL) {
        SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->%s() : Memory is not allocated", __func__);
        return RPP_APP_RET_NULL_POINTER;
    }

    // Parameter for iwpriv sta_fixed_rate construct from: (preamble_type << 8) | (nss_minus_1 << 5) | (mcs)
    // where preamble_type: 0-OFDM, 1-CCK, 2-HT, 3-VHT, 4-HE

    // Preamble type
    switch(preambleType) {
        case PROTO_A:
        case PROTO_G:
            preambleTypeNum = 0; // OFDM
            break;
        case PROTO_B:
            preambleTypeNum = 1; // CCK
            break;
        case PROTO_N:
            preambleTypeNum = 2; // HT
            break;
        case PROTO_AC:
            preambleTypeNum = 3; // VHT
            break;
        default:
        case PROTO_AX:
            preambleTypeNum = 4; // HE
            break;
    }

    // NSS count
    while (nssVal) {
        nssVal &= ( nssVal -1 ) ;
        nssCount++ ;
    }

    // Tx mcs value
    txMcsVal = mcsVal & HE_MCS_TX_POSN; // Tx mcs is lower 6 bits
    if (txMcsVal >= HE_MCS_ID_MAX) { // Individual mcs configuration
        txMcsVal -= HE_MCS_ID_MAX;
    }
    *fixedRateVal = (preambleTypeNum << 8) | ((nssCount-1) << 5) | txMcsVal;
    return errCode;
}

/******************************************************************************
 * Function Name    : * p_keyword
 * Description      : This Function is used to return pointer of keyword in buf 
 ******************************************************************************/
char * p_keyword(const char * buf, const char * kw) {
    uint8_t kw_len;
    char * msg;

    kw_len = strlen(kw);
    msg = strstr(buf,kw);
    if (!msg) {
        return NULL;
    }

    msg += kw_len;
    return msg;
}
/******************************************************************************
 * Function Name    : rpp_get_ap_count
 * Description      : This Function is used to get ap count from scan message.
 ******************************************************************************/
uint8_t rpp_get_ap_count(const char * msg) {
    char * msg_end;

    if (!msg) {
        return 0;
    }

    while (strstr(msg,"Cell ")) {
        //scope the ap for parsing.
        msg = p_keyword(msg,"Cell ");
        msg_end = strstr(msg,"Cell ");
        if (!msg_end) {
            return atoi(msg);
        }
    }

    return 0;
}
/******************************************************************************
 * Function Name    : rpp_parser_ap_list
 * Description      : This Function is used to parse apinfo in to struct for sending to wlanmgrd
 ******************************************************************************/
uint8_t rpp_parser_ap_list(char * msg , ScanInfo * info ) {
	uint8_t i=0;
    char * msg_end;
    char * s_ptr;
    char * e_ptr;
    char * parsing_info;
    char * parsing_phymode;
    uint8_t msg_len;

    if (!msg) {
        SYSLOG_PRINT(LOG_DEBUG,"ap_info-----Buf is null");
        return APINFO_FAILURE;
    }
    
    if (!(strstr(msg,"Cell "))) {
        return APINFO_NOTFOUND;
    }
    while (strstr(msg,"Cell ")) {
        //scope the ap for parsing.
        msg = p_keyword(msg,"Cell ");
        msg_end = strstr(msg,"Cell ");
        if (!msg_end) {
            msg_end = strlen(msg) + msg;
        }
        msg[msg_end-msg-1] = '\0';
        parsing_info = msg;

        //Clear info data
        memset(info,0,sizeof(ScanInfo));

        //bssid
        if ( strstr(parsing_info,"Address: ") != NULL ) {
            s_ptr = p_keyword(parsing_info,"Address: ");
            sscanf(s_ptr, MAC_STRING_FORMAT,(char *)&info->bssid[0],
                                            (char *)&info->bssid[1],
                                            (char *)&info->bssid[2],
                                            (char *)&info->bssid[3],
                                            (char *)&info->bssid[4],
                                            (char *)&info->bssid[5]);
        } 
        SYSLOG_PRINT(LOG_DEBUG,"ap_in-----%s",util_mac_addr_to_str(info->bssid));

        //ESSID
        if ( strstr(parsing_info,"ESSID:\"") != NULL ) {
            s_ptr = p_keyword(parsing_info,"ESSID:\"");
            e_ptr = strstr(s_ptr,"\"");
            if (!e_ptr)
                e_ptr = s_ptr;

            msg_len = e_ptr-s_ptr;
            memset(info->ssid,0,sizeof(info->ssid));
            memcpy((char *)info->ssid,s_ptr,msg_len);
        } else 
            msg_len = 0;

        SYSLOG_PRINT(LOG_DEBUG,"ap_in-----%s",info->ssid);

        //ssidlen
        info->ssidlen = msg_len;

        //Frequency
        if ( strstr(parsing_info,"Frequency:") != NULL ) {
            s_ptr = p_keyword(parsing_info,"Frequency:");
            info->freq = (uint32_t)(atof(s_ptr) * 1000);
        }
        SYSLOG_PRINT(LOG_DEBUG,"ap_in-----freq =%d",info->freq);

        //rssi
        if ( strstr(parsing_info,"Signal level=") != NULL ) {
            s_ptr = p_keyword(parsing_info,"Signal level=");
            info->rssi = atoi(s_ptr);
        }
        SYSLOG_PRINT(LOG_DEBUG,"ap_in-----rssi =%d",info->rssi);

        //ht,vht,he capability
        if ( strstr(parsing_info,"phy_mode=") != NULL ) {
            s_ptr = p_keyword(parsing_info,"phy_mode=");

            e_ptr = strstr(s_ptr,"\n");
            if (!e_ptr)
                e_ptr = s_ptr;
            parsing_phymode = s_ptr;
            s_ptr[e_ptr-s_ptr] = '\0';
            info->vhtcap = 0;
            info->htcap = 0;
            info->hecap = 0;

            if ( strstr(parsing_phymode,"VHT") != NULL ) {
                info->vhtcap = RPP_APP_DEFNUM_ONE;
                info->htcap = RPP_APP_DEFNUM_ONE;
                SYSLOG_PRINT(LOG_DEBUG,"ap_in-----phy_mode VHT from the message %s",strstr(parsing_phymode,"VHT"));
            }
            else if ( strstr(parsing_phymode,"HT") != NULL ) {
                info->htcap = RPP_APP_DEFNUM_ONE;
                SYSLOG_PRINT(LOG_DEBUG,"ap_in-----phy_mode HT from the message %s",strstr(parsing_phymode,"HT"));
            }
            else if ( strstr(parsing_phymode,"HE") != NULL ) {
                info->vhtcap = RPP_APP_DEFNUM_ONE;
                info->htcap = RPP_APP_DEFNUM_ONE;
                info->hecap = RPP_APP_DEFNUM_ONE;
                SYSLOG_PRINT(LOG_DEBUG,"ap_in-----phy_mode HE from the message %s",strstr(parsing_phymode,"HE"));
            }
            else {
                SYSLOG_PRINT(LOG_DEBUG, "\nINFO_MSG_Station is not cable of HT/VHT/HE");
            }
            s_ptr[e_ptr-s_ptr] = '\n';
        }

        //phy_rate
        if ( strstr(parsing_info,"phyrate=") != NULL ) {
            s_ptr = p_keyword(parsing_info,"phyrate=");
            info->maxphyrate = atoi(s_ptr);
        }
        SYSLOG_PRINT(LOG_DEBUG,"ap_in-----Phyrate = %d",info->maxphyrate);

         //channel_width
        if ( strstr(parsing_info,"channel bandwidth:") != NULL ) {
            s_ptr = p_keyword(parsing_info,"channel bandwidth:");
            info->chnbw = atoi(s_ptr);
        }
        SYSLOG_PRINT(LOG_DEBUG,"ap_in-----Ch Width = %d",info->chnbw);

        //sgi
        if ( strstr(parsing_info,"=supported") == NULL )
            info->sgi = 0;
        else
            info->sgi = RPP_APP_DEFNUM_ONE;
        SYSLOG_PRINT(LOG_DEBUG,"ap_in-----SGI is %s",info->sgi ? "support" : "not support");

        //Manufacturer
        if ( strstr(parsing_info,"Manufacturer=") != NULL ) {
            s_ptr = p_keyword(parsing_info,"Manufacturer=");
            e_ptr = strstr(s_ptr,"\n");
            if (e_ptr)
                msg_len = e_ptr - s_ptr;
            else
                msg_len = 0;

            memcpy(info->manufacturer,s_ptr,msg_len);
            info->manufacturer[msg_len] = '\0';
        }
        SYSLOG_PRINT(LOG_DEBUG,"ap_in-----Model is %s",info->modelname[0] != '\0' ? info->modelname : (uint8_t *)"Not found" );

        //Medel
        if ( strstr(parsing_info,"Model Name=") != NULL ) {
            s_ptr = p_keyword(parsing_info,"Model Name=");
            e_ptr = strstr(s_ptr,"\n");
            msg_len = e_ptr - s_ptr;
            memcpy(info->modelname,s_ptr,msg_len);
            info->modelname[msg_len] = '\0';
        }
        SYSLOG_PRINT(LOG_DEBUG,"ap_in-----Model is %s",info->modelname[0] != '\0' ? info->modelname : (uint8_t *)"Not found" );

        //Encryption
        if ( strstr(parsing_info,"Encryption key:") == NULL ) {                 // Open. No key found, assuming this is open mode
            info->enctype = OPEN;
            info->encinfo[0]='\0';
        } else {
            s_ptr = p_keyword(parsing_info,"Encryption key:");                  // Open
            if ( strstr(s_ptr,"off") != NULL ) {
                info->enctype = OPEN;
                info->encinfo[0]='\0';
            }
            else if ( strstr(s_ptr,"on") != NULL ) {                            // Encrypt
                s_ptr = p_keyword(parsing_info,"Authentication Suites");
                if ( s_ptr == NULL) {                                           // No PSK, no 802.1x, no unknown 8 , no unknown 18, no unknown 12, no unknown 4
                    info->enctype = WEP;
                    strcpy((char *)info->encinfo,"WEP");
                }
                else if ( strstr(s_ptr,"PSK") != NULL ) {                       // PSK
                    s_ptr = p_keyword(parsing_info,"PSK");
                    if ( strstr(s_ptr,"unknown (8)") != NULL ) {                // PSK, unknown 8
                        info->enctype = WPA2_WPA3_PERSONAL;
                        strcpy((char *)info->encinfo, "CCMP-PSK SAE");
                    }
                    else {
                        info->enctype = PERSONAL;                               // PSK, no unknown 8
                        strcpy((char *)info->encinfo, "Personal");
                    }
                }
                else if ( strstr(s_ptr,"802.1x") != NULL ) {                    // no PSK 802.1x
                    info->enctype = ENTERPRISE;
                    strcpy((char *)info->encinfo, "Enterprise");
                }
#ifdef RDP419
                else if ( strstr(s_ptr,"SAE") != NULL ) {               // No PSK, no 802.1x, SAE (Supported in spf11.2)
                    info->enctype = WPA3_PERSONAL;
                    strcpy((char *)info->encinfo, "CCMP-SAE");
                }
#endif
                else if ( strstr(s_ptr,"unknown (8)") != NULL ) {               // No PSK, no 802.1x, unknown 8
                    s_ptr = p_keyword(parsing_info,"unknown (8)");
                    if ( strstr(s_ptr,"unknown (6)") != NULL ) {                // No PSK, no 802.1x, unknown 8, unknown 6
                        info->enctype = WPA2_WPA3_PERSONAL;
                        strcpy((char *)info->encinfo, "CCMP-PSK SAE");
                    }
                    else {                                                      // No PSK, no 802.1x, unknown 8, no unknown 6
                        info->enctype = WPA3_PERSONAL;
                        strcpy((char *)info->encinfo, "CCMP-SAE");
                    }
                }
                else if ( strstr(s_ptr,"unknown (18)") != NULL ) {              // No PSK, no 802.1x, no unknown 8 , unknown 18
                    info->enctype = ENHANCED_OPEN;
                    strcpy((char *)info->encinfo, "CCMP-OWE");
                }
#ifdef RDP419
                else if ( strstr(s_ptr,"8021X_SUITE_B_192") != NULL ) {               // No PSK, no 802.1x, 8021X_SUITE_B_192 (Supported in spf11.2)
                    info->enctype = WPA3_ENTERPRISE;
                    strcpy((char *)info->encinfo, "WPA3 Enterprise");
                }
#endif
                else if ( strstr(s_ptr,"unknown (12)") != NULL ) {              // No PSK, no 802.1x, no unknown 8 , no unknown 18, unknown 12
                    info->enctype = WPA3_ENTERPRISE;
                    strcpy((char *)info->encinfo, "WPA3 Enterprise");
                }
                else if ( strstr(s_ptr,"unknown (4)") != NULL ) {               // No PSK, no 802.1x, no unknown 8 , no unknown 18, no unknown 12, unknown 4
                    info->enctype = PERSONAL;
                    strcpy((char *)info->encinfo, "Personal");
                }
                else {                                                          // No PSK, no 802.1x, no unknown 8 , no unknown 18, no unknown 12, no unknown 4
                    info->enctype = WEP;
                    strcpy((char *)info->encinfo,"WEP");
                }
            }
        }

        SYSLOG_PRINT(LOG_DEBUG,"ap_in-----Encryption type= %d",info->enctype);
        SYSLOG_PRINT(LOG_DEBUG,"ap_in-----Encryption info= %s",info->encinfo);

        //Increase pointer
        info++;
        msg=msg_end;
        i++;
    }

    return APINFO_SUCCESS;
}

/******************************************************************************
 * Function Name    : rpp_ap_list_builder
 * Description      : This Function is used to build ap list for sending to wlanmgrd.
 ******************************************************************************/
ScanInfo * rpp_ap_list_builder( int32_t * totalAp ) {
    char    *apBuf = NULL;
    ScanInfo *apInfo = NULL;
    struct  stat st;
    if (!totalAp)
        return NULL;

    *totalAp = 0;

    if (stat("/tmp/scanlist.txt", &st)) {
        SYSLOG_PRINT(LOG_ERR, "\nERR_MSG------->Cannot get scan result size.");
        return NULL;
    }

    if ( st.st_size == 0) {
        SYSLOG_PRINT(LOG_ERR, "\nERR_MSG------->/tmp/scanlist.txt is empty.");
        return NULL;
    }

    apBuf = (char *)malloc(st.st_size+1);
    if (!apBuf) {
        SYSLOG_PRINT(LOG_ERR, "\nERR_MSG------->Failed to allocate buffer to process scan results.");
        return NULL;
    }
    apBuf[st.st_size] = '\0';
    
    FILE *fptr;
    if ((fptr = fopen("/tmp/scanlist.txt", "r")) == NULL){
        SYSLOG_PRINT(LOG_ERR, "\nERR_MSG------->Failed to read scan results.");
        free(apBuf);
        return NULL;
    }
    fread(apBuf, st.st_size, 1, fptr);
    fclose(fptr);
    
    *totalAp = rpp_get_ap_count(apBuf);

    if (*totalAp == 0) {
        SYSLOG_PRINT(LOG_ERR, "\nERR_MSG------->No ap information in /tmp/scanlist.txt.");
        free(apBuf);
        return NULL;
    }

    apInfo = (ScanInfo *)calloc(*totalAp, sizeof(ScanInfo));
    if (!apInfo) {
        SYSLOG_PRINT(LOG_ERR, "\nERR_MSG------->Failed to allocate apInformation to process scan results.");
        free(apBuf);
        return NULL;
    }

    if (rpp_parser_ap_list(apBuf, apInfo)) {
        SYSLOG_PRINT(LOG_ERR, "\nERR_MSG------->Failed to parse apInformation to process scan results.");
        free(apBuf);
        free(apInfo);
        *totalAp = 0;
        return NULL;
    }
    free(apBuf);
    return apInfo;
}

/******************************************************************************
 * Function Name    : rpp_parse_neighbor_report
 * Description      : This Function is used to parse Neighbor report from 
 *                    wpa_supplicant output for sending to wlanmgrd.
 ******************************************************************************/
int32_t rpp_parse_neighbor_report(char * buf, NeighborReportStats *NRRStats, uint8_t nbrOfAPInList)
{
    char *token = NULL;
    uint8_t apIndexInStats = 0;

    if (buf == NULL) {
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->Invalid/empty neighbor report buffer\n");
        return RPP_APP_RET_NULL_POINTER;
    }

    token = strtok(buf, "\n");  /*Added to skip the number of AP in Neighbor List*/
    if (NRRStats == NULL) {
        SYSLOG_PRINT(LOG_ERR,"ERR_MSG------->Invalid/empty neighbor report information\n");
        return RPP_APP_RET_NULL_POINTER;
    }

    token = strtok(NULL, "\n"); /*Added to Skip the heading line "SSID	BSSID	RSSI" in the neighbor report shared by supplicant*/
    for (uint8_t apIndexInList = 0; apIndexInList < nbrOfAPInList; apIndexInList++) {
        token = strtok(NULL, "\t");
        if (token == NULL) {
            SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->AP%d SSID is NULL\n", apIndexInList);
            token = strtok(NULL, "\n");
            continue;
        }
        strcpy(NRRStats->roamingaps[apIndexInStats].apssid, token);
        token = strtok(NULL, "\t");
        if (token == NULL) {
            SYSLOG_PRINT(LOG_ERR, "ERR_MSG-------> AP%d BSSID is NULL\n", apIndexInList);
            memset(&NRRStats->roamingaps[apIndexInStats], 0, sizeof(NeighborReport));
            token = strtok(NULL, "\n");
            continue;
        }
        util_str_to_mac_addr(token, NRRStats->roamingaps[apIndexInStats].apbssid);
        token = strtok(NULL, "\n");
        sscanf(token, "\t%hhd", &NRRStats->roamingaps[apIndexInStats].rssi);
        SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->AP%d SSID:%s\tBSSID:%s\tRSSI:%hhd\n",apIndexInStats,
                                                                                      NRRStats->roamingaps[apIndexInStats].apssid,
                                                                                      util_mac_addr_to_str(NRRStats->roamingaps[apIndexInStats].apbssid),
                                                                                      NRRStats->roamingaps[apIndexInStats].rssi);
        apIndexInStats++;
    }
    NRRStats->nbrofneighboraps = apIndexInStats;

    return RPP_APP_RET_SUCCESS;
}
