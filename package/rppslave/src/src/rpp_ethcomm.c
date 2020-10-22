#include "rpp_ethcomm.h"
#include "rpp_message.h"

enum {
    RPP_SYNC_MSG_SEND_SOCKFD_INDEX = 0,
    RPP_ASYNC_MSG_SEND_SOCKFD_INDEX,
    RPP_UDP_STATS_SEND_SOCKFD_INDEX,
    CLIENT_SEND_SOCK = RPP_UDP_STATS_SEND_SOCKFD_INDEX,
    RPP_SYNC_MSG_RECV_SOCKFD_INDEX,
    RPP_NUM_OF_UDP_CONNECTION
};

extern char* gnetInfName;

struct sockaddr_in si_me[RPP_NUM_OF_UDP_CONNECTION], si_other;
int32_t socketFd[RPP_NUM_OF_UDP_CONNECTION];
int32_t socketPort[RPP_NUM_OF_UDP_CONNECTION] = {RPP_HOST_SOCK_RECV_PORT_SYNC_MSG,
        RPP_HOST_SOCK_RECV_PORT_ASYNC_MSG, RPP_HOST_UDP_STATS_RECV_PORT, RPP_HOST_SOCK_SEND_PORT_SYNC_MSG};

struct sockaddr_in capPortAddr;
int32_t capPortFd, newCapPortsocket;
int32_t capPortAddrlen;;
extern char* sourceIp;
static int32_t createServerSocket = 0;
extern int32_t createClientSocket;
#ifdef THREE_RADIO
int32_t capSocketPort_perRadio[RPP_NUM_OF_RADIO] = {CAPDAEMON_RADIO_0_PORT, CAPDAEMON_RADIO_1_PORT,CAPDAEMON_RADIO_2_PORT};
#else
int32_t capSocketPort_perRadio[RPP_NUM_OF_RADIO] = {CAPDAEMON_RADIO_0_PORT, CAPDAEMON_RADIO_1_PORT};
#endif
/******************************************************************************
 * Function Name    : rpp_get_system_interfaceIp
 * Description      : This Function used to get the ip address of the interface
 ******************************************************************************/
int32_t rpp_get_system_interfaceIp(char *infName, char *ipAddr)
{
    int socFd = 0;
    struct ifreq ifr;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_get_system_interfaceIp_fun()_start");

    socFd = socket(AF_INET, SOCK_STREAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, infName, IFNAMSIZ - RPP_APP_DEFNUM_ONE);
    ioctl(socFd, SIOCGIFADDR, &ifr);
    close(socFd);

    strcpy(ipAddr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_get_system_interfaceIp_fun()_exit");
    return 0;
}

/******************************************************************************
 * Function Name    : init_eth_comm
 * Description      : This Function used to initialize the UDP communication
 ******************************************************************************/
int32_t init_eth_comm(void)
{
    int32_t connNum = 0;
    int32_t errCode = RPP_APP_RET_SUCCESS;
    char capPortipaddr[20] = "\0";
    char serverPortipaddr[20] = "\0";

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->init_eth_comm_fun()_start");

    for (connNum = 0; connNum < RPP_NUM_OF_UDP_CONNECTION; connNum++) {
        if(createServerSocket == RPP_APP_DEFNUM_ONE)
            break;
        //create a UDP socket
        if ((socketFd[connNum]=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
            errCode = RPP_APP_RET_FILEOPEN_FAILED;
        }
    }

    for (connNum = 0; connNum < RPP_NUM_OF_UDP_CONNECTION; connNum++) {
        if(connNum == RPP_SYNC_MSG_RECV_SOCKFD_INDEX && createServerSocket == RPP_APP_DEFNUM_ONE)
        break;

        if (socketPort[connNum] != RPP_HOST_SOCK_SEND_PORT_SYNC_MSG) {
            if((createServerSocket != 0) && (createClientSocket  <= CLIENT_SEND_SOCK)) {
                SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG-------> IP address of host machine = %s \n", sourceIp);
                // zero out the structure
                memset((char *) &si_me[connNum], 0, sizeof(si_me[connNum]));
                si_me[connNum].sin_family = AF_INET;
                si_me[connNum].sin_port = htons(socketPort[connNum]);
                si_me[connNum].sin_addr.s_addr = inet_addr(sourceIp);
                createClientSocket += 1;
            }
        } else {
              if(createServerSocket == 0) {

                  if (rpp_get_system_interfaceIp(gnetInfName, serverPortipaddr) < 0) {
                      debug_print(DEBUG_INFO, " Get IP failed");
                      SYSLOG_PRINT(LOG_CRIT, " CRIT_MSG_Get IP failed");
                      errCode = RPP_APP_RET_FILEOPEN_FAILED;
                  }
                  // zero out the structure
                  memset((char *) &si_me[connNum], 0, sizeof(si_me[connNum]));
                  si_me[connNum].sin_family = AF_INET;
                  si_me[connNum].sin_port = htons(socketPort[connNum]);
                  si_me[connNum].sin_addr.s_addr = inet_addr(serverPortipaddr);

                  //bind socket to port
                  if( bind(socketFd[connNum] , (struct sockaddr*)&si_me[connNum], sizeof(si_me[connNum]) ) == -1) {
                      debug_print(DEBUG_INFO, "bind failed in Server Socket");
                      SYSLOG_PRINT(LOG_CRIT, "CRIT_MSG_bind failed in Server Socket");
                      errCode = RPP_APP_RET_FILEOPEN_FAILED;
                  }
                  createServerSocket = RPP_APP_DEFNUM_ONE;
            }
        }
    }

    if((createServerSocket == RPP_APP_DEFNUM_ONE) && (createClientSocket == 0)) {

    if (rpp_get_system_interfaceIp(gnetInfName, capPortipaddr) < 0) {
            debug_print(DEBUG_INFO, " Get IP failed");
            SYSLOG_PRINT(LOG_CRIT, " CRIT_MSG_Get IP failed");
            errCode = RPP_APP_RET_FILEOPEN_FAILED;
        }

        if ((capPortFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
            debug_print(DEBUG_INFO, " Socket creation failed");
            SYSLOG_PRINT(LOG_CRIT, " CRIT_MSG_Socket creation failed");
            errCode = RPP_APP_RET_FILEOPEN_FAILED;
        }

        capPortAddrlen = sizeof(capPortAddr);

        memset(&capPortAddr, 0, sizeof(capPortAddr));

        capPortAddr.sin_family = AF_INET;
        capPortAddr.sin_port = htons(CAPDAEMON_PORT_NUM);
        capPortAddr.sin_addr.s_addr = inet_addr(capPortipaddr);

        if (bind(capPortFd, (struct sockaddr *)&capPortAddr, sizeof(capPortAddr)) < 0) {
            debug_print(DEBUG_INFO, "bind failed in Capture Socket");
            SYSLOG_PRINT(LOG_CRIT, "CRIT_MSG_bind failed in Capture Socket");
            errCode = RPP_APP_RET_FILEOPEN_FAILED;
        }

        for (connNum = 0; connNum < RPP_NUM_OF_RADIO; connNum++) {

            if ((capPortFd_perRadio[connNum] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
                debug_print(DEBUG_INFO, "\n Socket creation failed for capPortFd_perRadio[%d]",connNum);
                SYSLOG_PRINT(LOG_CRIT, " CRIT_MSG_Socket creation failed for capPortFd_perRadio[%d]",connNum);
                errCode = RPP_APP_RET_FILEOPEN_FAILED;
            }

            // zero out the structure
            memset(&capPortAddr_perRadio[connNum], 0, sizeof(capPortAddr_perRadio[connNum]));
            capPortAddr_perRadio[connNum].sin_family = AF_INET;
            capPortAddr_perRadio[connNum].sin_port = htons(capSocketPort_perRadio[connNum]);
            capPortAddr_perRadio[connNum].sin_addr.s_addr = inet_addr(capPortipaddr);

            if (bind(capPortFd_perRadio[connNum], (struct sockaddr *)&capPortAddr_perRadio[connNum], sizeof(capPortAddr_perRadio[connNum])) < 0) {
                debug_print(DEBUG_INFO, "bind failed in Capture Socket for capPortFd_perRadio[%d]",connNum);
                SYSLOG_PRINT(LOG_CRIT, "CRIT_MSG_bind failed in Capture Socket for capPortFd_perRadio[%d]",connNum);
                errCode = RPP_APP_RET_FILEOPEN_FAILED;
            }
        }
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->init_eth_comm_fun()_exit");
    return errCode;
}
/******************************************************************************
 * Function Name    : deinit_eth_comm
 * Description      : This Function used to deinitialize the UDP communication
 ******************************************************************************/
int32_t deinit_eth_comm(void)
{
    int32_t connNum = 0;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->deinit_eth_comm_fun()_start");

    for (connNum = 0; connNum < RPP_NUM_OF_UDP_CONNECTION; connNum++) {
        /* Close the IPC socket */
        close(socketPort[connNum]);
    }

    close(capPortFd);

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->deinit_eth_comm_fun()_exit");
    return 0;
}

/******************************************************************************
 * Function Name    : send_eth_msgto_fpga
 * Description      : This Function used to send command message over UDP
 *                    port(port num-7098) to FPGA
 ******************************************************************************/
int32_t send_eth_msgto_fpga(const char *buf, int32_t len)
{
    const int32_t errstr_len = 80;
    char errstr[errstr_len];
    int32_t slen = sizeof (si_me[RPP_SYNC_MSG_SEND_SOCKFD_INDEX]);
    int32_t rc = 0;
    //SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->send_eth_msgto_fpga_fun()_start");

    rc = sendto(socketFd[RPP_SYNC_MSG_SEND_SOCKFD_INDEX], buf, len, 0,
            (const struct sockaddr *) &si_me[RPP_SYNC_MSG_SEND_SOCKFD_INDEX],
            slen);
    if (rc == -1) {
        strerror_r(errno, errstr, errstr_len);
          debug_print(DEBUG_DATA, "Error: 'send' [%d-%s]\n", errno, errstr);
          SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Error: 'send' [%d-%s]\n", errno, errstr);
    }

    RppMessageHead *msghdr = (RppMessageHead *)buf;
    if(msghdr->type != RPP_MSG_GETSTATS_RESP) {
        debug_print(DEBUG_DATA,"\nResponse sent to host for message type = %d (rc = %d)", msghdr->type, rc);
        SYSLOG_PRINT(LOG_DEBUG,"\nResponse sent to host for message type = %d (rc = %d)", msghdr->type, rc);
    }
    //SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->send_eth_msgto_fpga_fun()_exit");
    return rc;
}

/******************************************************************************
 * Function Name    : send_eth_msgto_fpga
 * Description      : This Function used to send command message over UDP
 *                    port(port num-7099) to FPGA
 ******************************************************************************/
int32_t send_eth_async_msgto_fpga(const char *buf, int32_t len)
{

    const int32_t errstr_len = 80;
    char errstr[errstr_len];
    int32_t rc = 0;
    int32_t slen = sizeof (si_me[RPP_ASYNC_MSG_SEND_SOCKFD_INDEX]);

    rc = sendto(socketFd[RPP_ASYNC_MSG_SEND_SOCKFD_INDEX], buf, len, 0,
            (const struct sockaddr *) &si_me[RPP_ASYNC_MSG_SEND_SOCKFD_INDEX],
                slen);
    if (rc == -1) {
        strerror_r(errno, errstr, errstr_len);
        debug_print(DEBUG_DATA, "Error: 'send' [%d-%s]\n", errno, errstr);
        SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Error: 'send' [%d-%s]\n", errno, errstr);
    }
#if 0
    RppMessageHead *msghdr = (RppMessageHead *)buf;
    if(msghdr->type == RPP_MSG_ASSOCSTATE_NOTF) {
        char iwCmd[1024] = "\0";
        AssocStateNtfy *assocState = (AssocStateNtfy *)msghdr->body;
        memset (iwCmd, 0, sizeof (iwCmd));
        sprintf (iwCmd, "echo Notification sending for phyHndl[%d] and staHndl[%d] with state[%d]. and return value from socket [rc = %d]", assocState->phyhandle,assocState->stahandle,assocState->state,rc);
        debug_print(DEBUG_DATA,"iwCmd = %s\n",iwCmd);
        SYSLOG_PRINT(LOG_DEBUG,"iwCmd = %s\n",iwCmd);
        if(system (iwCmd) < 0) {
        }
    }
#endif
    return rc;
}

ssize_t send_eth_udp_stats_to_fpga(const char *buf, int32_t len)
{

    ssize_t nbytes = 0;
    socklen_t slen = sizeof(struct sockaddr_in);

    nbytes = sendto(socketFd[RPP_UDP_STATS_SEND_SOCKFD_INDEX], buf, len, 0,
            (const struct sockaddr *) &si_me[RPP_UDP_STATS_SEND_SOCKFD_INDEX],
                slen);
    if (nbytes < 0)
        SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Error: 'send' [%d-%s]\n", errno, strerror(errno));
    return nbytes;
}

/******************************************************************************
 * Function Name    : recv_eth_msgfrom_fpga
 * Description      : This Function used to receive normal message over UDP
 *                    port(port num-8098) from FPGA
 ******************************************************************************/
int32_t recv_eth_msgfrom_fpga(char *buf, int32_t len)
{
    int32_t rc = 0;
    int32_t slen = sizeof (struct sockaddr_in);
    const int32_t errstr_len = 80;
    char errstr[errstr_len];
    //SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->recv_eth_msgfrom_fpga_fun()_start");

    /* Receive the CLI command execution response string from FPGA over UDP socket */
    rc = recvfrom(socketFd[RPP_SYNC_MSG_RECV_SOCKFD_INDEX], buf, len, 0,
            (struct sockaddr*) &si_other,
            (socklen_t*) &slen);
    if (rc == -1) {
        strerror_r(rc, errstr, errstr_len);
          debug_print(DEBUG_DATA, "Error: 'recv' [%d-%s]\n", rc, errstr);
          SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Error: 'recv' [%d-%s]\n", rc, errstr);
    }

    sourceIp = inet_ntoa(si_other.sin_addr);

    //SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->recv_eth_msgfrom_fpga_fun()_exit");
    return rc;
}

/******************************************************************************
 * Function Name    : rpp_reeieve_datafrom_monitord
 * Description      : This Function used to receive data from monitor daemon
 ******************************************************************************/
int32_t rpp_receive_datafrom_monitord(monitordResponse_t *p_mResp, uint32_t phyhandle)
{
    char buf[1024] = { 0 };
    int32_t rc = 0;
    int32_t slen = sizeof (capPortAddr_perRadio[phyhandle]);
    const int32_t errstr_len = 80;
    char errstr[errstr_len];
    debug_print(DEBUG_DATA,"rpp_receive_datafrom_monitord()_start");
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_receive_datafrom_monitord()_start");

    /* Receive the CLI command execution response string from FPGA over UDP socket */
    rc = recvfrom(capPortFd_perRadio[phyhandle], buf, sizeof(buf), 0,
            (struct sockaddr*) &capPortAddr_perRadio[phyhandle],
            (socklen_t*) &slen);

    if (rc == -1) {
        strerror_r(rc, errstr, errstr_len);
           debug_print(DEBUG_DATA, "Error: 'recv' [%d-%s]\n", rc, errstr);
           SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Error: 'recv' [%d-%s]\n", rc, errstr);
    }

    memcpy(p_mResp, buf, sizeof(monitordResponse_t));

    debug_print(DEBUG_DATA,"rpp_receive_datafrom_monitord()_exit");
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_receive_datafrom_monitord()_exit");
    return rc;
}

/******************************************************************************
 * Function Name    : rpp_send_datato_monitord
 * Description      : This Function used to send data to monitor daemon
 ******************************************************************************/
int32_t rpp_send_datato_monitord(captureParam_t *param_t, uint32_t phyhandle)
{
    const int32_t errstr_len = 80;
    char errstr[errstr_len];
    int32_t slen = sizeof (capPortAddr_perRadio[phyhandle]);
    int32_t rc = 0;
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_send_datato_monitord()_start");

    rc = sendto(capPortFd_perRadio[phyhandle], (char*)param_t, 1024, 0,
            (const struct sockaddr *) &capPortAddr_perRadio[phyhandle],
            slen);
    if (rc == -1) {
        strerror_r(errno, errstr, errstr_len);
            debug_print(DEBUG_DATA, "Error: 'send' [%d-%s]\n", errno, errstr);
            SYSLOG_PRINT(LOG_ERR, "ERR_MSG------->Error: 'send' [%d-%s]\n", errno, errstr);
    }

    debug_print(DEBUG_DATA,"\nData sent to monitor daemon in byte = %d",  rc);
    SYSLOG_PRINT(LOG_DEBUG,"\nData sent to monitor daemon in byte = %d",  rc);

    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_send_datato_monitord()_exit");
    return rc;
}
