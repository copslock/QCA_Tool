
/* Header Inclusion */

#include "rpp_core.h"
#include "rpp_ethcomm.h"
#include "rpp_dataparsing.h"
#include "rpp_message.h"
#include "rpp_header.h"
#include <sys/stat.h>
#include <stdarg.h>

#define     RPP_HIGH_PRIORITY_THREAD 0

bool sendKeepAlive = false;
bool probeProcess = true;
bool cleanupProcess = true;

char* sourceIp = NULL;
char* gnetInfName = NULL;
int32_t createClientSocket = 0;
//Seaparte lock for three staMonitor threads
pthread_mutex_t assocStatLock[RPP_NUM_OF_RADIO] =  {PTHREAD_MUTEX_INITIALIZER,PTHREAD_MUTEX_INITIALIZER ,PTHREAD_MUTEX_INITIALIZER};
pthread_mutex_t proxyStateLock[RPP_NUM_OF_RADIO] =  {PTHREAD_MUTEX_INITIALIZER,PTHREAD_MUTEX_INITIALIZER ,PTHREAD_MUTEX_INITIALIZER};
pthread_mutex_t staProcessLock =  PTHREAD_MUTEX_INITIALIZER;
#ifdef THREE_RADIO
   uint8_t radio[RPP_NUM_OF_RADIO] = {FIVE_G_RADIO_0,TWO_G_RADIO_1,FIVE_G_RADIO_2};
#else
   uint8_t radio[RPP_NUM_OF_RADIO] ={FIVE_G_RADIO_0,TWO_G_RADIO_1};
#endif

/******************************************************************************
 * Function Name    : thread_msgParserFromFpga
 * Description      : This Function used to receive from FPGA and parse
 *                    it for subsequent processing.
 ******************************************************************************/
void * thread_msgParserFromFpga(void *p_threadData)
{
    int32_t ret = 0;
    int8_t  msgType = 0;
    int8_t  msgCategory = 0;
    int8_t  recvBuf[RPP_MAX_RECV_SIZE];
    int32_t bufLen = 0;
    SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->Thread_msgParserFromFpga_fun_Start");
    RppMesgMapToDataStruct rppMesgMapToDataStruct;

    while (RPP_APP_DEFNUM_ONE) {
        memset (recvBuf, 0, sizeof (recvBuf));
        memset (&rppMesgMapToDataStruct, 0, sizeof (rppMesgMapToDataStruct));

        /* Extract the data */
        bufLen = 0;
        bufLen = recv_eth_msgfrom_fpga ((char *)recvBuf, sizeof (recvBuf));
        if(bufLen > 0) {
              //debug_print(DEBUG_DATA, "<<<< Client received %d bytes.\n",bufLen);
              //SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG-------><<<< Client received %d bytes.\n",bufLen);
        } else {
              //debug_print(DEBUG_DATA, "Client failed to read message %s.\n",strerror(errno));
              //SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Client failed to read message %s.\n",strerror(errno));

        }

        memcpy (&rppMesgMapToDataStruct.rppNonPayloadStruct, recvBuf,
                sizeof (rppMesgMapToDataStruct.rppNonPayloadStruct));
        msgCategory = rppMesgMapToDataStruct.rppNonPayloadStruct.MessageCat;
        msgType = rppMesgMapToDataStruct.rppNonPayloadStruct.MessageType;

        /* Validate the message category */
        if ( msgCategory == RPP_MSG_REQ) {

            /* Validate the message type */
            if ( (msgType < RPP_MSG_PROB_REQ) || (msgType > RPP_MSG_MAX_REQ)) {
                debug_print(DEBUG_INFO, "Invalid message type \n");
                SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Invalid message type \n");
            } else {
                if( msgType != RPP_MSG_GETSTATS_REQ) {
                    debug_print(DEBUG_DATA, "\n msg type : %d , Macro : %d", msgType, msgCategory);
                    SYSLOG_PRINT(LOG_DEBUG, "\n DEBUG_MSG------->msg type : %d , Macro : %d", msgType, msgCategory);
                }

                switch (msgType) {
                    case RPP_MSG_PROB_REQ :
                        ret = rpp_slave_probe_req();
                        break;

                    case RPP_MSG_GETPHY_REQ :
                        ret = rpp_get_phy_req();
                        break;

                    case RPP_MSG_SETPHY_REQ :
                        ret = rpp_set_phy_req(recvBuf);
                        break;

                    case RPP_MSG_ADDSTA_REQ :
                        ret = rpp_add_station_req(recvBuf);
                        break;

                    case RPP_MSG_DELSTA_REQ :
                        ret = rpp_delete_station_req(recvBuf);
                        break;

                    case RPP_MSG_SCAN_REQ :
                        ret = rpp_scan_req(recvBuf);
                        break;

                    case RPP_MSG_ASSOC_REQ :
                        ret = rpp_associate_req(recvBuf);
                        break;

                    case RPP_MSG_DEASSOC_REQ :
                        ret = rpp_deassociate_req(recvBuf);
                        break;

                    case RPP_MSG_FBT_REQ :
                        ret = rpp_fastBss_transit_req(recvBuf);
                        break;

                    case RPP_MSG_SETMODE_REQ :
                        ret = rpp_setmode_req(recvBuf);
                        break;

                    case RPP_MSG_CLRSTATS_REQ :
                        ret = rpp_clear_station_stats_req(recvBuf);
                        break;

                    case RPP_MSG_SETLOG_REQ :
                        ret = rpp_set_log_level_req(recvBuf);
                        break;

                    case RPP_MSG_LOGGER_REQ:
                        ret = rpp_send_log_Report_req(recvBuf);
                        break;
                    case RPP_MSG_CAPCTRL_REQ:
                        ret = rpp_capturemode_req(recvBuf);
                        break;
                    case RPP_MSG_REBOOT:
                        ret = rpp_session_cleanup();
                        break;
                    default :
                        break;
                }
            }
        } else {
            debug_print(DEBUG_INFO, "Invalid Message category \n");
            SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Invalid Message category \n");
        }

        if (ret < 0 ) {
            debug_print(DEBUG_DATA, "Message response failed for message id: %d\n", msgType);
            SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Message response failed for message id: %d\n", msgType);
        }
    }

    SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->Thread_msgParserFromFpga_fun_Exit");
    return 0;
}

/******************************************************************************
 * Function Name    : rpp_slave_init
 * Description      : This Function used to initialize rpp slave.
 ******************************************************************************/
int32_t rpp_slave_init()
{
    int32_t     ret = 0;
    SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->rppslave_slave_init_fun()_start");
    pthread_t   msgPaserThreadId;
    unsigned char p_ecode;
    int32_t radioIndex= 0;
#ifdef RPP_HIGH_PRIORITY_THREAD
    pthread_attr_t attr;
    struct sched_param param;

    ret = pthread_attr_init (&attr);
    ret = pthread_attr_getschedparam (&attr, &param);
    (param.sched_priority)++;
    ret = pthread_attr_setschedparam (&attr, &param);
#endif

    /* This will be responsible for handling the command packet coming from
     * x86 through FPGA(SGMII). Function of this thread will be to parse the
     * packet, validate it for one of the available commands from iw command
     * lookup  table, then frame the correct command and finally send it to
     * the wifi module. Once the response comes from wifi module in the form
     * of iw command output, accordingly response packet will be framed and
     * sent it back.
     */
    ret = pthread_create(&msgPaserThreadId, NULL,
                         thread_msgParserFromFpga, NULL);
    if (ret != 0) {
        SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->failure in creating thread_msgParserFromFpga:%d", ret);
        return -1;
    }

    //Separate thread for each radio for stamon

    for (radioIndex = 0; radioIndex < RPP_NUM_OF_RADIO; radioIndex++) {
        ret = pthread_create(&staMonThreadId[radioIndex], &attr,
        thread_staMonRadio, (void *)&radio[radioIndex]);
        if (ret != 0) {
            SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->failure in creating thread_staMonRadio:%d", ret);
            return -1;
        }
        SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->thread created %d", radioIndex);
    }

    /*Initializing the Statistics thread*/
    ret = pthread_create(&staStatsThreadId, NULL,
            thread_get_stats, NULL);
    if (ret != 0) {
        SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->failure in creating thread_get_stats:%d", ret);
        return -1;
    }

    if(set_ipq_appln_bootup_status(0) == REVANCHE_IRET_SUCCESS) {        
        SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->Writing ipq appln boot status success");
    } else {
        SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Writing ipq appln boot status failed:%d",
            set_ipq_appln_bootup_status(0));
    }

    if(revanche_update_boot_count((revanche_inf_ecode_et *)&p_ecode) == REVANCHE_IRET_SUCCESS) {
        SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->Writing ipq appln boot status success");
    } else {
        SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Boot Count Write FAIL%d",
            revanche_update_boot_count((revanche_inf_ecode_et *)&p_ecode));
    }


    /* Initalize the rpp station handle structure */
    rpp_stahandle_init();

    pthread_join(msgPaserThreadId,NULL);
    for (radioIndex = 0; radioIndex < RPP_NUM_OF_RADIO; radioIndex++) {
        pthread_join(staMonThreadId[radioIndex],NULL);
    }
    pthread_join(staStatsThreadId,NULL);
    SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->rppslave_slave_init_fun()_Exit");
    return ret;
}

void rpp_syslog_init()
{
    openlog("Rppslave_Syslog",LOG_PID,LOG_DAEMON);
    SYSLOG_PRINT(LOG_DEBUG,"Rppslave start running\n");
}

void rpp_sigint_handler(int signal)
{

    system_cmd("killall wpa_supplicant\n");
    closelog();
    system_cmd("killall monitord\n");
    system_cmd("killall syslogd\n");
    /*Freeing the memory allocated to gnetInfName*/
    free(gnetInfName);

    exit(0);
}

int32_t main(int32_t argc, char** argv)
{
    char  ipAddress[32] = RPP_LOCAL_HOST_IP_ADDRESS;
    int32_t choice;
    int32_t ret = 0;
    int32_t noOfEthInterface = 0;
    char    tempBuf[RPP_APP_BUFF_SIZE] = "\0";
    rpp_syslog_init();
    SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->Main_fun()_Start");

    signal(SIGINT, rpp_sigint_handler);
    signal(SIGTERM, rpp_sigint_handler);

    while ((choice = getopt (argc, argv, "l:hk:")) != -1) {
        switch (choice) {
            case 'l':
                {
                    memset (ipAddress, 0, sizeof (ipAddress));
                    strcpy (ipAddress, optarg) ;
                    break;
                }
            case 'k':
                {
                    sendKeepAlive = true;
                    break;
                }
            case 'h':
                {
                    printf("usage:\n");
                    printf("Run rppslave by default this option:-> ./rppslave\n");
                    printf("Run rppslave with -k option for keepalive :-> ./rppslave -k\n");
                    return 0;
                }
        }
    }

    // ifconfig -a |grep eth |wc -l
    ret = system_cmd_get_f(tempBuf, sizeof(tempBuf), "ifconfig -a | grep eth | wc -l");
    noOfEthInterface = atoi(tempBuf);
    gnetInfName = (char *) calloc(5, sizeof(char));
    if (noOfEthInterface == RPP_APP_DEFNUM_TWO)
        gnetInfName = strcpy(gnetInfName , "eth0");
    else
        gnetInfName = strcpy(gnetInfName,"eth1");
    gnetInfName[4] = '\0';

    /* Initialize the socket communication */
    ret = init_eth_comm();
    if (ret != 0) {
        SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->failure in initialising ethernet communication:%d", ret);
        return -1;
    }

    ret = rpp_slave_init();
    if (ret != 0) {
        SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->failure in initialising rppslave:%d", ret);
        return -1;
    }

    SYSLOG_PRINT(LOG_DEBUG, "DEBUG_MSG------->Main_fun()_Exit");
    return 0;
}
