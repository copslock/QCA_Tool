#include "monitor_mode.h"

#define IEEE_80211_MAX_FRAME         11 * 1024   /* Largest possible 802.11 frame */

// Capture control block
typedef struct captureCtrlBlock{
    int cb_capacity;
    int cb_full;
    ringbuf_t cb_ring;
    int isCapRunning;
    uint packetCount;
    char *filt_exp;
    monitorParam_t mParam;
    captureParam_t cParam;
    pthread_t tid;
    monitordResponse_t mResp;
} CCB;

CCB regularCcb={0};
CCB sdrCcb={0};
/* Global variables */
int rppSport = 0;

int sockfd;
struct sockaddr_in servaddr;

/*****************************************************************************
 *  Function Name          : response_to_rppslave
 *  Description            : This function is used to send response message to
 *                           rppslave
 *  Input(s)               : response message
 *  Output(s)              : NIL
 *  Returns                : NIL
 * ***************************************************************************/
void response_to_rppslave(monitordResponse_t *mResp)
{
    sendto(sockfd, (char *)mResp, 128, 0, (struct sockaddr *)NULL, sizeof(servaddr));
}

/*****************************************************************************
 *  Function Name          : send_packet_eth_interface
 *  Description            : This function is used to send the packet to
 *                           ethernet interface
 *  Input(s)               : packet, packet length
 *  Output(s)              : packets will be sent to ethernet interface
 *  Returns                : EXIT_SUCCESS/EXIT_FAILURE
 * ***************************************************************************/
int send_packet_eth_interface(u_char *sendPacket, int packetLength, CCB *ccb)
{
    int ret = 0;

    //MONITOR_MODE_PRINT(LOG_INFO, "Sending data to ethernet : len %d\n",
    //packetLength);

    ret = send(ccb->mParam.connSocketFd, sendPacket, packetLength, 0);

    //MONITOR_MODE_PRINT(LOG_DEBUG, "\n Actual Pkt length = %d Sent Pkt
    //length = %d\n", packetLength, ret);

    if (ret <= 0) {
        MONITOR_MODE_PRINT(LOG_ERR, "\nSending data to ethernet interface"
                                    " failed - err %s\n",
                           strerror(errno));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/*****************************************************************************
 *  Function Name          : send_offlinedata_to_host
 *  Description            : This function is used to send offline data
			                 to host
 *  Input(s)               : packet count, ringbuffer struct
 *  Output(s)              : NIL
 *  Returns                : NIL
 * ***************************************************************************/
#ifdef MONITOR_MODE_WRAP_ENABLE
void send_offlinedata_to_host(unsigned int *tempPktCount, CCB *ccb)
{
	unsigned long packetLength;
	struct pcap_pkt_usrhdr pkt_hdr_usr;
	u_char *sendPacket;

	*tempPktCount = 0;
	do {
			if (!ringbuf_read_buffer(ccb->cb_ring, (void *)&pkt_hdr_usr, sizeof(pkt_hdr_usr)))
					break;
			packetLength = pkt_hdr_usr.caplen + sizeof(struct pcap_pkt_usrhdr);
			sendPacket = malloc(packetLength);
			if (sendPacket == NULL) {
					ringbuf_discard(ccb->cb_ring, pkt_hdr_usr.caplen);
					break;
			}
			if (!ringbuf_read_buffer(ccb->cb_ring, sendPacket + sizeof(struct pcap_pkt_usrhdr), pkt_hdr_usr.caplen))
					break;

			/* copying pcap packet header */
			memcpy(sendPacket, &pkt_hdr_usr, sizeof(struct pcap_pkt_usrhdr));

			if (send_packet_eth_interface(sendPacket, packetLength, ccb) == EXIT_SUCCESS) {
					/* Increment temporary packet count variable to
					   validate packetCount */
					(*tempPktCount)++;
			}
			free(sendPacket);
	} while (1);
}
#endif

/*****************************************************************************
 *  Function Name          : monitor_mode_packet_handler
 *  Description            : This function is used as handler for processing
 *                           pcap packets for capture and live mode.
 *  Input(s)               : args, packet header, packet
 *  Output(s)              : pcap packets will be captured and processed.
 *  Returns                : void
 * ***************************************************************************/
void monitor_mode_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	CCB  *ccb = (CCB *)args;
	u_char *sendPacket = NULL;
	unsigned int packetLength = 0;
	struct pcap_pkt_usrhdr pkt_hdr_usr;

	/* copying pcap packet header */
	pkt_hdr_usr.ts = (uint64_t)(header->ts.tv_sec * 1000000) + (uint64_t)(header->ts.tv_usec);
	pkt_hdr_usr.caplen = header->caplen;
	pkt_hdr_usr.len = header->len;

	/* Add the length of packet and header */
	packetLength = header->caplen + sizeof(struct pcap_pkt_usrhdr);

	if (ccb->mParam.cParam.capture_mode == OFFLINE_MODE) {
			/* Sending packets in size(256 -1K) to avoid packet send failure */
			if (ccb->cb_full)
					return;

			// overwrite_flag = 0 -> Wrap mode (currently value is not passed correctly from wlanmgrd)
			if (ccb->mParam.cParam.overwrite_flag && (packetLength > ringbuf_bytes_free(ccb->cb_ring)))
			{
					ccb->cb_full = true;
					return;
			}
			// Do we have required space in ring buffer?
			while (packetLength > ringbuf_bytes_free(ccb->cb_ring)) {
					struct pcap_pkt_usrhdr temp_pkt_hdr_usr;
					// If not, throw away older frame
					if(!ringbuf_read_buffer(ccb->cb_ring, (uint8_t *)&temp_pkt_hdr_usr, sizeof(struct pcap_pkt_usrhdr)))
							return;
					ringbuf_discard(ccb->cb_ring, temp_pkt_hdr_usr.caplen);
					ccb->packetCount--;
			}
			if(!ringbuf_write_buffer(ccb->cb_ring, (uint8_t *)&pkt_hdr_usr, sizeof(struct pcap_pkt_usrhdr)))
					return;
			if(!ringbuf_write_buffer(ccb->cb_ring, (uint8_t *)packet, pkt_hdr_usr.caplen))
					return;
			ccb->packetCount++;
	} else {
			sendPacket = malloc(packetLength);
			if (sendPacket == NULL)
					return;

			/* copying pcap packet header */
			memcpy(sendPacket, &pkt_hdr_usr, sizeof(struct pcap_pkt_usrhdr));

			/* appending packet to frame whole packet with pcap header */
			memcpy((sendPacket + sizeof(struct pcap_pkt_usrhdr)), packet, pkt_hdr_usr.caplen);

			/* inject packets in eth1 interfacte */
			if (send_packet_eth_interface(sendPacket, packetLength, ccb) != EXIT_SUCCESS) {
					MONITOR_MODE_PRINT(LOG_ERR, "\nSending Packet to Ethernet interface Failed\n");
					/* Report error to rpp-slave */
			}
			free(sendPacket);
	}
	return;
}

/*****************************************************************************
 *  Function Name          : do_pcapCapture
 *  Description            : This function is used to prepare the pcap and
 *                           capture the packet in given interface.
 *  Input(s)               : pIdx (param index)
 *  Output(s)              : NIL
 *  Returns                : EXIT_SUCCESS/EXIT_FAILURE
 * ***************************************************************************/
int do_pcapCapture(CCB *ccb)
{
	char errorBuffer[PCAP_ERRBUF_SIZE];

	int timeout_limit = TIMEOUT_LIMIT; /* 10000 In milliseconds */

	/* Open monitor device for live capture */
	ccb->mParam.monHandle = pcap_open_live(ccb->mParam.cParam.mon_interface, IEEE_80211_MAX_FRAME,
					0, // 0 for pcap_loop
					timeout_limit, errorBuffer);

	if (ccb->mParam.monHandle == NULL) {
			MONITOR_MODE_PRINT(LOG_ERR, "Could not open device %s: %s.\n", ccb->mParam.cParam.mon_interface, errorBuffer);

			/* Report ERR_INVALID_MON_INTF error to rpp-slave */
			ccb->mResp.msgID = ERR_INVALID_MON_INTF;
			response_to_rppslave(&ccb->mResp);

			MONITOR_MODE_PRINT(LOG_ERR, "\n>>---ERR_INVALID_MON_INTF---\n>");
			return EXIT_FAILURE;
	}

	MONITOR_MODE_PRINT(LOG_DEBUG, "\nPcap capture is successfully opened for %s\n", ccb->mParam.cParam.mon_interface);
	pcap_set_buffer_size(ccb->mParam.monHandle, 32*1024*1024);

	if (ccb->mParam.cParam.filter_len > 0) {
			memset(&ccb->mParam.filterHandle, 0, sizeof(struct bpf_program));
			MONITOR_MODE_PRINT(LOG_DEBUG, "\nPreparing capture filter:(%s)\n", ccb->filt_exp);
			/* Parsing the filter expression */
			if (pcap_compile(ccb->mParam.monHandle, &ccb->mParam.filterHandle, ccb->filt_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
					MONITOR_MODE_PRINT(LOG_ERR, "Couldn't parse filter %s: %s\n", ccb->filt_exp, pcap_geterr(ccb->mParam.monHandle));
					/* Report error to rpp-slave */
					ccb->mResp.msgID = ERR_INVALID_FILTER_EXPR;
					response_to_rppslave(&ccb->mResp);

					MONITOR_MODE_PRINT(LOG_ERR, "\n>>---ERR_INVALID_FILTER_EXPR---\n>");
					return EXIT_FAILURE;
			}

			/* Installing the filter expression */
			if (pcap_setfilter(ccb->mParam.monHandle, &ccb->mParam.filterHandle) == -1) {
					MONITOR_MODE_PRINT(LOG_ERR, "Couldn't install filter %s: %s\n", ccb->mParam.cParam.filter_expression,
									pcap_geterr(ccb->mParam.monHandle));

					/* Report error to rpp-slave */
					ccb->mResp.msgID = ERR_INVALID_FILTER_EXPR;
					response_to_rppslave(&ccb->mResp);

					MONITOR_MODE_PRINT(LOG_ERR, "\n>>---ERR_INVALID_FILTER_EXPR---\n>");
					return EXIT_FAILURE;
			}
	}
	ringbuf_reset(ccb->cb_ring);
	ccb->cb_full = false;

	MONITOR_MODE_PRINT(LOG_DEBUG, "\nCapturing the packet(Regular) in interface:%s.\n", ccb->mParam.cParam.mon_interface);

	/* call the packet handler using pcap_loop() */
	if (pcap_loop(ccb->mParam.monHandle, 0, monitor_mode_packet_handler, (u_char *)ccb) == -2) {
			MONITOR_MODE_PRINT(LOG_INFO, "\npcap_loop exited due to pcap_breakloop()\n");
	}

	pcap_close(ccb->mParam.monHandle);
	ccb->mParam.monHandle = NULL;

	return EXIT_FAILURE;
}

/*****************************************************************************
 *  Function Name          : regularCapture
 *  Description            : This function is used to call the common
 * do_pcapCapture
 *                           with pIdx.
 *  Input(s)               : pIdx (param index)
 *  Output(s)              : NIL
 *  Returns                : EXIT_SUCCESS/EXIT_FAILURE
 * ***************************************************************************/
void *regularCapture(void *arg)
{
    CCB *ccb=(CCB *)arg;

    MONITOR_MODE_PRINT(LOG_DEBUG, "\n<< Preparing capture for REGULAR >>\n");
    ccb->isCapRunning = 1;

    if (do_pcapCapture(ccb) == EXIT_FAILURE) {
        ccb->isCapRunning = 0;
    }

    return NULL;
}

/*****************************************************************************
 *  Function Name          : SDRCapture
 *  Description            : This function is used to call the common
 * do_pcapCapture
 *                           with pIdx.
 *  Input(s)               : pIdx (param index)
 *  Output(s)              : NIL
 *  Returns                : EXIT_SUCCESS/EXIT_FAILURE
 * ***************************************************************************/
void *SDRCapture(void *arg)
{
    CCB *ccb=(CCB *)arg;

    MONITOR_MODE_PRINT(LOG_DEBUG, "\n<< Preparing capture for SDR >>\n");
    ccb->isCapRunning = 1;

    if (do_pcapCapture(ccb) == EXIT_FAILURE) {
        ccb->isCapRunning = 0;
    }

    return NULL;
}

/*****************************************************************************
 *  Function Name          : rpphost_server_socket
 *  Description            : This function is used to create rpphost server
 *                           socket and connected to the host.
 *  Input(s)               : NIL
 *  Output(s)              : Server socket will be created and connected to it.
 *  Returns                : EXIT_SUCCESS/EXIT_FAILURE
 * ***************************************************************************/
int rpphost_server_socket(CCB *ccb)
{
    struct sockaddr_in serverAddress;
    unsigned int serverAddrLen = 0;
    int flag = 1;

    /* creating socket */
    if ((ccb->mParam.socketFd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        MONITOR_MODE_PRINT(LOG_ERR, "\n Socket creation failed \n");
        return EXIT_FAILURE;
    }
    memset(&serverAddress, '0', sizeof(serverAddress));

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(ccb->mParam.cParam.tcp_port_no);
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddrLen = sizeof(serverAddress);

    /*Bind failed if socket in TIME_WAIT stat and using SO_REUSEADDR |
     * SO_REUSEPORT to resolve it */
    if (setsockopt(ccb->mParam.socketFd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, (char *)&flag, sizeof(flag)) < 0) {
        MONITOR_MODE_PRINT(LOG_ERR, "\n RPP Host setsockopt failed..\n");
    }

    /* Bind RPPHOST Server socket */
    if (bind(ccb->mParam.socketFd, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        MONITOR_MODE_PRINT(LOG_ERR, "\n RPP Host Server Bind Failed \n");
        return EXIT_FAILURE;
    }

    /* Listen RPPHOST Server Socket */
    if (listen(ccb->mParam.socketFd, MAX_LISTEN_CLIENTS) < 0) {
        MONITOR_MODE_PRINT(LOG_ERR, "\n Listen to RPP Host Socket Failed \n");
        return EXIT_FAILURE;
    }

    if ((ccb->mParam.connSocketFd =
             accept(ccb->mParam.socketFd, (struct sockaddr *)&serverAddress, (socklen_t *)&serverAddrLen)) < 0) {
        MONITOR_MODE_PRINT(LOG_ERR, "\n Accept call Failed \n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/*****************************************************************************
 *  Function Name          : do_cleanup
 *  Description            : This function is used to free and close the malloc
 *                           and socket fds.
 *  Input(s)               : NIL
 *  Output(s)              : memory and socket will be cleared and closed.
 *  Returns                : EXIT_SUCCESS/EXIT_FAILURE
 * ***************************************************************************/
void do_cleanup(CCB *ccb)
{
    /* Clean the filter expresson malloc*/
    if (ccb->filt_exp != NULL)
        free(ccb->filt_exp);
    ccb->filt_exp = NULL;

    /* Close the rpphost TCP connection socket*/
    if (ccb->mParam.socketFd != 0)
        close(ccb->mParam.socketFd);
	ccb->mParam.socketFd = 0;

    if (ccb->mParam.connSocketFd != 0)
       close(ccb->mParam.connSocketFd);
	ccb->mParam.connSocketFd = 0;

    /* close syslog */
    closelog();
}

/*****************************************************************************
 *  Function Name          : disp_param
 *  Description            : This function is used to display the param
 *  Input(s)               : ccb
 *  Output(s)              : NIL
 *  Returns                : NIL
 * ***************************************************************************/
void disp_param(CCB *ccb) {
    MONITOR_MODE_PRINT(LOG_NOTICE, "=================================================\n");
    MONITOR_MODE_PRINT(LOG_NOTICE, "=============Capture configurations ============= \n");
    MONITOR_MODE_PRINT(LOG_NOTICE, "=================================================\n");
    MONITOR_MODE_PRINT(LOG_NOTICE, "Capture Type:    0x%x\n", ccb->mParam.cParam.rppsCmd);
    MONITOR_MODE_PRINT(LOG_NOTICE, "Capture interface:%s\n", ccb->mParam.cParam.mon_interface);
    MONITOR_MODE_PRINT(LOG_NOTICE, "Capture mode:    :0x%x\n", ccb->mParam.cParam.capture_mode);
    MONITOR_MODE_PRINT(LOG_NOTICE, "Capture Overwrite flag:0x%x\n", ccb->mParam.cParam.overwrite_flag);
    MONITOR_MODE_PRINT(LOG_NOTICE, "Capture TCP Port No:%d\n", ccb->mParam.cParam.tcp_port_no);
    if (ccb->mParam.cParam.filter_len > 0) {
        MONITOR_MODE_PRINT(LOG_NOTICE, "Capture Filter length:%d\n", ccb->mParam.cParam.filter_len);
        MONITOR_MODE_PRINT(LOG_NOTICE, "Capture Filter expression:%s\n", ccb->mParam.cParam.filter_expression);
    }
    MONITOR_MODE_PRINT(LOG_NOTICE, "=================================================\n");
}

/*****************************************************************************
 *  Function Name          : start_monitor_mode_daemon
 *  Description            : This function is used to start the daemon,
                             registering signal handler.
 *  Input(s)               : NIL
 *  Output(s)              : daemon will be started and registered signal
                             handler
 *  Returns                : void
 * ***************************************************************************/
void start_monitor_mode_daemon(void)
{
    /* pid - process ID sid - Session ID */
    pid_t pid, sid;
    /* Fork off the parent process */
    pid = fork();

    /* Exit the process with failure code if fork process is failed */
    if (pid < 0) {
        MONITOR_MODE_PRINT(LOG_ERR, "\n %s:%d - Failed to fork the process."
                                    " pid - %d",
                           __FUNCTION__, __LINE__, pid);
        exit(EXIT_FAILURE);
    }

    /* Exit the parent process once we got PID */
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);

    /* Open log file for capturing debug/error messages */
    openlog("monitor_mode_daemon", LOG_PID, LOG_DAEMON);

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        /* Log the failure */
        MONITOR_MODE_PRINT(LOG_ERR, "\n %s:%d - Failed to set session id for"
                                    " the forked process. sid - %d",
                           __FUNCTION__, __LINE__, sid);
        closelog();
        exit(EXIT_FAILURE);
    }

    /* Change the current working directory */
    if ((chdir("/")) < 0) {
        /* Log the failure */
        MONITOR_MODE_PRINT(LOG_ERR, "\n %s:%d - Failed to set session id for"
                                    " the forked process. sid - %d",
                           __FUNCTION__, __LINE__, sid);
        closelog();
        exit(EXIT_FAILURE);
    }
    MONITOR_MODE_PRINT(LOG_DEBUG, "Parent Process Exited Successfully.\n"
                                  "New child process created and started\n");
}

/*****************************************************************************
 *  Function Name          : validate_capture_params
 *  Description            : This function is used to validate capture
							 parameters.
 *  Input(s)               : pIdx (parameter index)
 *  Output(s)              : arguments will be validated
 *  Returns                : EXIT_SUCCESS/EXIT_FAILURE
 * ***************************************************************************/
int validate_capture_params(CCB *ccb)
{
    char buffer[1024] = {0};
    FILE *fp = NULL;

    /* Validating capture mode. capture mode should be 0 or 1 */
    if ((ccb->mParam.cParam.capture_mode != 0) && (ccb->mParam.cParam.capture_mode != 1)) {
        MONITOR_MODE_PRINT(LOG_ERR, "\n Invalid capture_mode:%d.\n", ccb->mParam.cParam.capture_mode);

        /*report error  to rpp-slave*/
        ccb->mResp.msgID = ERR_INVALID_CAP_MODE;
        response_to_rppslave(&ccb->mResp);

        MONITOR_MODE_PRINT(LOG_ERR, "\n>>---ERR_INVALID_CAP_MODE---\n>");
        return EXIT_FAILURE;
    }

    /* Validating overwrite flag. overwrite flag should be 0 or 1. */
    if ((ccb->mParam.cParam.overwrite_flag != 0) && (ccb->mParam.cParam.overwrite_flag != 1)) {
        MONITOR_MODE_PRINT(LOG_ERR, "\n Invalid overwrite_flag:%d.\n", ccb->mParam.cParam.capture_mode);

        /*report error  to rpp-slave*/
        ccb->mResp.msgID = ERR_INVALID_OVR_WR_FLAG;
        response_to_rppslave(&ccb->mResp);

        MONITOR_MODE_PRINT(LOG_ERR, "\n>>---ERR_INVALID_OVR_WR_FLAG---\n>");
        return EXIT_FAILURE;
    }

    if (ccb->mParam.cParam.filter_len > 0) {
        ccb->filt_exp = (char *)malloc(ccb->mParam.cParam.filter_len + 1);
        strcpy(ccb->filt_exp, ccb->mParam.cParam.filter_expression);
    }

    /* validating monitor interface name */
    memset(buffer, '\0', BUFFER_SIZE);
    snprintf(buffer, BUFFER_SIZE, "iwconfig %s | grep 'Mode:' > /dev/null", ccb->mParam.cParam.mon_interface);
    if (system(buffer) != 0) {
        MONITOR_MODE_PRINT(LOG_ERR, "\n Given interface is not wireless:%s.\n", ccb->mParam.cParam.mon_interface);

        /*report error  to rpp-slave*/
        ccb->mResp.msgID = ERR_INVALID_MON_INTF;
        response_to_rppslave(&ccb->mResp);

        MONITOR_MODE_PRINT(LOG_ERR, "\n>>---ERR_INVALID_MON_INTF---\n>");
        return EXIT_FAILURE;
    }

    /* Checking interface name is in monitor mode or not */
    memset(buffer, '\0', BUFFER_SIZE);
    snprintf(buffer, BUFFER_SIZE, "iwconfig %s | grep 'Mode:' | cut -c 16-23", ccb->mParam.cParam.mon_interface);

    /* Use popen to get output of command in file descriptor */
    fp = popen(buffer, "r");

    if (fp == NULL) {
        MONITOR_MODE_PRINT(LOG_ERR, "\n popen failed for interface %s\n", ccb->mParam.cParam.mon_interface);
        return EXIT_FAILURE;
    }

    /* Read string from fp */
    while (fgets(buffer, BUFFER_SIZE, fp) != NULL) {
        /* Check the interface is in Monitor or station(Managed) mode */
        if (strncmp(buffer, MONITOR_MODE, strlen(MONITOR_MODE)) != 0) {
            MONITOR_MODE_PRINT(LOG_ERR, "\n Interface(%s) is not in monitor mode, current mode:%s.\n",
                               ccb->mParam.cParam.mon_interface, buffer);
            pclose(fp);

            /*report error  to rpp-slave*/
            ccb->mResp.msgID = ERR_INVALID_MON_INTF;
            response_to_rppslave(&ccb->mResp);

            MONITOR_MODE_PRINT(LOG_ERR, "\n>>---ERR_INVALID_MON_INTF---\n>");
            return EXIT_FAILURE;
        }
    }

    pclose(fp);

    /* monitor interface down */
    memset(buffer, '\0', BUFFER_SIZE);
    snprintf(buffer, BUFFER_SIZE, "ifconfig %s down > /dev/null", ccb->mParam.cParam.mon_interface);
    if (system(buffer) != 0) {
        MONITOR_MODE_PRINT(LOG_ERR, "\n Could not down monitor interface: %s.\n", ccb->mParam.cParam.mon_interface);

        /*report error  to rpp-slave*/
        ccb->mResp.msgID = ERR_INVALID_MON_INTF;
        response_to_rppslave(&ccb->mResp);

        MONITOR_MODE_PRINT(LOG_ERR, "\n>>---ERR_INVALID_MON_INTF---\n>");
        return EXIT_FAILURE;
    }

    /* monitor interface up */
    memset(buffer, '\0', BUFFER_SIZE);
    snprintf(buffer, BUFFER_SIZE, "ifconfig %s up > /dev/null", ccb->mParam.cParam.mon_interface);
    if (system(buffer) != 0) {
        MONITOR_MODE_PRINT(LOG_ERR, "\n Could not up monitor interface: %s.\n", ccb->mParam.cParam.mon_interface);

        /*report error  to rpp-slave*/
        ccb->mResp.msgID = ERR_INVALID_MON_INTF;
        response_to_rppslave(&ccb->mResp);

        MONITOR_MODE_PRINT(LOG_ERR, "\n>>---ERR_INVALID_MON_INTF---\n>");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/*****************************************************************************
 *  Function Name          : rppslaveCmdProcess
 *  Description            : This function is used to process the rppslave
							 command request
 *  Input(s)               : NIL
 *  Output(s)              : NIL
 *  Returns                : EXIT_SUCCESS/EXIT_FAILURE
 * ***************************************************************************/
int rppslaveCmdProcess(void)
{
    char buffer[100];
    char cmd[BUFFER_SIZE];
    int cleanup_done = 0;

    unsigned int tempPacketCount = 0;
	monitordResponse_t mResp;
    CCB *ccb;

    mResp.msgHeader = CMD_RPPS_HEADER;
    mResp.msgID = CMD_MONITORD_IS_UP;

    memset(cmd, '\0', BUFFER_SIZE);
    // clear servaddr
    bzero(&servaddr, sizeof(servaddr));

    /* Assuming that IPQ eth0 always assigned to 192.168.1.2 */
    servaddr.sin_addr.s_addr = inet_addr("192.168.1.2");
    servaddr.sin_port = htons(rppSport);
    servaddr.sin_family = AF_INET;

    /* create datagram socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* connect to server */
    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        MONITOR_MODE_PRINT(LOG_ERR, "\n Error : Connect Failed \n");
        exit(0);
    }

    MONITOR_MODE_PRINT(LOG_NOTICE, "\n monitord started and using port %d for rpp-slave communication..\n", rppSport);

    // request to send datagram
    // no need to specify server address in sendto
    // connect stores the peers IP and port
    usleep(500);
    sendto(sockfd, (char *)&mResp, sizeof(monitordResponse_t), 0, (struct sockaddr *)NULL, sizeof(servaddr));
    MONITOR_MODE_PRINT(LOG_NOTICE, "Send CMD_MONITORD_IS_UP--->\n");

    while (1) {
        /*  waiting for response */
        recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)NULL, NULL);

        if (buffer[CMD_HEADER_OF] != CMD_RPPS_HEADER) {
            /*report error  to rpp-slave*/
            MONITOR_MODE_PRINT(LOG_ERR, "Invalid message header..\n");
        }

        switch (buffer[CMD_CAPT_TYPE_OF]) {
        /* Start the normal capture */
        case CMD_REGULAR_START:
            ccb = &regularCcb;
            MONITOR_MODE_PRINT(LOG_NOTICE, "\n<--- CMD_REGULAR_START---<<\n");
            /*Mostly this case won't happen because STC GUI wont allow this*/
            if (ccb->isCapRunning) {

                MONITOR_MODE_PRINT(LOG_ERR, "Regular capture is already running..\n");

                /* Report error to rpp-slave */
                mResp.msgID = ERR_CMD_SEQ;
                response_to_rppslave(&mResp);

                MONITOR_MODE_PRINT(LOG_NOTICE, "\n>>---ERR_CMD_SEQ (REGULAR-START)--->\n");
                break;
            } else {
                memcpy((char *)&ccb->mParam.cParam, buffer, sizeof(buffer));
                disp_param(ccb);

                if (validate_capture_params(ccb) != EXIT_SUCCESS) {
                    MONITOR_MODE_PRINT(LOG_ERR, "Capture param is invalid and "
                                                "reported to rpp-slave.\n");
                    /* monitord can wait for proper capture param from rpp-slave
                     */
                    break;
                }

                MONITOR_MODE_PRINT(LOG_NOTICE, "Regular capture running..\n");
                ccb->isCapRunning = 1;

                if (pthread_create(&ccb->tid, NULL, &regularCapture, (void *)ccb)) {
                    MONITOR_MODE_PRINT(LOG_ERR, "%s: %d - Monitor mode daemon "
                                                "thread creation failed \n",
                                       __FUNCTION__, __LINE__);
                    ccb->isCapRunning = 0;
                }
                /* start the Tx capture cmd*/
                /* 0 index is for Regular Capture */
                snprintf(cmd, BUFFER_SIZE, "iwpriv %s tx_capture 1 > /dev/null", ccb->mParam.cParam.mon_interface);
                if (system(cmd) != 0) {
                    /*report error  to rpp-slave*/
                    mResp.msgID = ERR_INVALID_MON_INTF;
                    mResp.packetCount = 0;
                    response_to_rppslave(&mResp);

                    MONITOR_MODE_PRINT(LOG_ERR, "\n Could not start the Tx packet capture.\n");
                    return EXIT_FAILURE;
                }

                /* Report error to rpp-slave */
                mResp.msgID = CMD_MONITORD_ACK;
                response_to_rppslave(&mResp);

                MONITOR_MODE_PRINT(LOG_NOTICE, "\n>>---CMD_MONITORD_ACK (REGULAR-START)--->\n");
            }

            break;
        /* Start the SDR capture */
        case CMD_SDR_START:
			ccb = &sdrCcb;
            MONITOR_MODE_PRINT(LOG_NOTICE, "\n<--- CMD_SDR_START---<<\n");
            if (ccb->isCapRunning) {

                MONITOR_MODE_PRINT(LOG_NOTICE, "SDR capture is already running..\n");

                /* Report error to rpp-slave */
                mResp.msgID = ERR_CMD_SEQ;
                response_to_rppslave(&mResp);

                MONITOR_MODE_PRINT(LOG_NOTICE, "\n>>---ERR_CMD_SEQ (SDR-START)--->\n");
                break;
            } else {
                memcpy((char *)&ccb->mParam.cParam, buffer, sizeof(buffer));
                disp_param(ccb);

                if (validate_capture_params(ccb) != EXIT_SUCCESS) {
                    MONITOR_MODE_PRINT(LOG_ERR, "Capture param is invalid and "
                                                "reported to rpp-slave.\n");
                    /* monitord can wait for proper capture param from rpp-slave
                     */
                    break;
                }

                MONITOR_MODE_PRINT(LOG_NOTICE, "SDR capture running..\n");
                ccb->isCapRunning = 1;

                if (pthread_create(&ccb->tid, NULL, &SDRCapture, (void *)ccb)) {
                    MONITOR_MODE_PRINT(LOG_ERR, "%s: %d - Monitor mode daemon "
                                                "thread creation failed \n",
                                       __FUNCTION__, __LINE__);
                    ccb->isCapRunning = 0;
                }

                mResp.msgID = CMD_MONITORD_ACK;
                response_to_rppslave(&mResp);
                MONITOR_MODE_PRINT(LOG_NOTICE, "\n>>---CMD_MONITORD_ACK (SDR-START)--->\n");
            }

            break;
        case CMD_REGULAR_STOP:
        case CMD_SDR_STOP:
			if ( buffer[CMD_CAPT_TYPE_OF] == CMD_REGULAR_STOP)
			{
                ccb = &regularCcb;
                MONITOR_MODE_PRINT(LOG_NOTICE, "\n<--- CMD_REGULAR_STOP---<<\n");
			}
			else
			{
                ccb = &sdrCcb;
                MONITOR_MODE_PRINT(LOG_NOTICE, "\n<--- CMD_SDR_STOP---<<\n");
            }
            if (!ccb->isCapRunning) {

                MONITOR_MODE_PRINT(LOG_ERR, "capture is not running at this moment..\n");

                /* Report error to rpp-slave */
                mResp.msgID = ERR_CMD_SEQ;
                response_to_rppslave(&mResp);

                MONITOR_MODE_PRINT(LOG_NOTICE, "\n>>---ERR_CMD_SEQ (REGULAR-STOP)--->\n");
                break;
            }

			if ( buffer[CMD_CAPT_TYPE_OF] == CMD_REGULAR_STOP)
			{
                snprintf(cmd, BUFFER_SIZE, "iwpriv %s tx_capture 0 > /dev/null", ccb->mParam.cParam.mon_interface);

                if (system(cmd) != 0) {
                   /*report error  to rpp-slave*/
                    mResp.msgID = ERR_INVALID_MON_INTF;
                    mResp.packetCount = 0;
                    response_to_rppslave(&mResp);

                    MONITOR_MODE_PRINT(LOG_ERR, "\n Could not stop the Tx capture command \n");
                    break;
               }
            }
            MONITOR_MODE_PRINT(LOG_NOTICE, "Stopping Capture..\n");

            /* Terminate pcap_loop by calling pcap_breakloop */
            pcap_breakloop(ccb->mParam.monHandle);

            /* Sending ACK to rpp slave*/
            mResp.msgID = CMD_MONITORD_ACK;
            response_to_rppslave(&mResp);
            ccb->isCapRunning = 0;

            MONITOR_MODE_PRINT(LOG_NOTICE, "\n>>---CMD_MONITORD_ACK (STOP)--->\n");

            break;
        case CMD_REGULAR_RETRIVE:
        case CMD_SDR_RETRIVE:
			if ( buffer[CMD_CAPT_TYPE_OF] == CMD_REGULAR_RETRIVE)
			{
                ccb = &regularCcb;
                MONITOR_MODE_PRINT(LOG_NOTICE, "\n<--- CMD_REGULAR_RETRIVE---<<\n");
			}
			else
			{
                ccb = &sdrCcb;
                MONITOR_MODE_PRINT(LOG_NOTICE, "\n<--- CMD_SDR_RETRIVE---<<\n");
            }
            if (ccb->isCapRunning) {

                MONITOR_MODE_PRINT(LOG_ERR, "capture is still running..\n");

                /* Report error to rpp-slave */
                mResp.msgID = ERR_CMD_SEQ;
                response_to_rppslave(&mResp);

                MONITOR_MODE_PRINT(LOG_NOTICE, "\n>>---ERR_CMD_SEQ (RETRIVE)--->\n");
            } else {
                /* Send packet count to rppslave */
                mResp.msgID = CMD_MONITORD_PKT_CNT;
                mResp.packetCount = ccb->packetCount;
                response_to_rppslave(&mResp);
                MONITOR_MODE_PRINT(LOG_NOTICE, "\n>>---CMD_MONITORD_PKT_CNT--->\n");

                MONITOR_MODE_PRINT(LOG_NOTICE, "Captured packet count:%d.\n", ccb->mResp.packetCount);

                /* Stream the pcakets to rpp host */
                MONITOR_MODE_PRINT(LOG_NOTICE, "Sending packet to rpp Host in port number:%d\n",
                                   ccb->mParam.cParam.tcp_port_no);
                if (ccb->packetCount != 0) {
                    if (rpphost_server_socket(ccb) != EXIT_SUCCESS) {
                        MONITOR_MODE_PRINT(LOG_ERR, "RppHost client socket creation failed\n");

                        /*report error to rpp-slave*/
                        mResp.msgID = ERR_RPPHOST_SOC_FAIL;
                        response_to_rppslave(&mResp);

                        MONITOR_MODE_PRINT(LOG_NOTICE, "\n>>---ERR_RPPHOST_SOC_FAIL--->\n");

                        return EXIT_FAILURE;
                    }
                }

                send_offlinedata_to_host(&tempPacketCount, ccb);
                MONITOR_MODE_PRINT(LOG_NOTICE, "\n %d packets sent to rpphost.\n", tempPacketCount);

                if ((tempPacketCount == ccb->packetCount) || (ccb->packetCount == 0)) {
                    /* Sending COMPLETE to rpp slave to intimate packet sending
                     * done */
                    mResp.msgID = CMD_MONITORD_COMPLETE;
                    response_to_rppslave(&mResp);
                    MONITOR_MODE_PRINT(LOG_NOTICE, "\n>>---CMD_MONITORD_COMPLETE---\n>");
                } else {
                    MONITOR_MODE_PRINT(LOG_ERR, "\nMismatch packet count so "
                                                "didn't send Actual Count : %d "
                                                "Sent Count : %d"
                                                " COMPLETE.",
                                       ccb->packetCount, tempPacketCount);
                    return EXIT_FAILURE;
                }

                if (!sdrCcb.isCapRunning && !regularCcb.isCapRunning) {
                    MONITOR_MODE_PRINT(LOG_NOTICE, "No ongoing activity, exiting..\n");
                    do_cleanup(&sdrCcb);
                    do_cleanup(&regularCcb);
                    /* Enable cleanup_done variable once the cleanup is done */
                    cleanup_done = 1;
                }
            }
            break;
        default:
            MONITOR_MODE_PRINT(LOG_NOTICE, "Unknown request");
            mResp.msgID = ERR_UNKNOWN_OP_CMD;
            response_to_rppslave(&mResp);
            MONITOR_MODE_PRINT(LOG_ERR, "\n>>---ERR_UNKNOWN_OP_CMD---\n>");
            break;
        }
        /* Come out from response while loop once cleanup is done. */
        if (cleanup_done == 1) {
            break;
        }
    }
    // close the descriptor
    close(sockfd);

    ringbuf_del(&sdrCcb.cb_ring);
    ringbuf_del(&regularCcb.cb_ring);

    return EXIT_SUCCESS;
}

/*****************************************************************************
 *  Function Name          : main
 *  Description            : main function
 *  Input(s)               : port number
 *  Output(s)              : NIL
 *  Returns                : EXIT_SUCCESS/EXIT_FAILURE
 * ***************************************************************************/
int main(int argc, char *argv[])
{
    int ret = 0;
    pid_t mpid;

    if (argc != 2) {
        MONITOR_MODE_PRINT(LOG_ERR, "Invalid number of arguments.");
        exit(0);
    }
    rppSport = atoi(argv[1]);

    regularCcb.mResp.msgHeader = CMD_RPPS_HEADER;
    regularCcb.mResp.msgID = CMD_MONITORD_IS_UP;
    regularCcb.cb_ring = ringbuf_new(OFFLINE_DATA_SIZE + 1);
    if (regularCcb.cb_ring == NULL) {
        MONITOR_MODE_PRINT(LOG_ERR, "\n Error : Capture buffer allocation Failed \n");
        exit(0);
    }

    sdrCcb.mResp.msgHeader = CMD_RPPS_HEADER;
    sdrCcb.mResp.msgID = CMD_MONITORD_IS_UP;
    sdrCcb.cb_ring = ringbuf_new(OFFLINE_SDR_DATA_SIZE + 1);
    if (sdrCcb.cb_ring == NULL) {
        MONITOR_MODE_PRINT(LOG_ERR, "\n Error : Capture buffer allocation Failed \n");
        exit(0);
    }

    /* get the process id */
    if ((mpid = getpid()) < 0) {
        perror("unable to get pid");
    } else {
        MONITOR_MODE_PRINT(LOG_NOTICE, "The main process id is %d\n", mpid);
    }
    /* Create child process and exit the parent process and
       start monitor mode daemon. */
    start_monitor_mode_daemon();

    MONITOR_MODE_PRINT(LOG_NOTICE, "daemonized done..\n");

    ret = rppslaveCmdProcess();

    exit(ret);
}
