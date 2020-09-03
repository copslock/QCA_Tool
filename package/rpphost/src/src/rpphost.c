#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include "rpp_message.h"
#include "rpp_ethcomm.h"
#include "rpphost_helper.h"

#define DEFAULT_STA_CONFIG_PATH "/tmp/sta.cfg"

#define DEFAULT_DELAY_PER_CMD_MSEC 100

static int socketFd;

/******************************************************************************
 * Function Name    : init_eth_comm
 * Description      : This Function used to initialize the UDP communication
 ******************************************************************************/
int32_t init_comm(void)
{
    int32_t errCode = RPP_APP_RET_SUCCESS;
    //create a UDP socket
    if ((socketFd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        errCode = RPP_APP_RET_FILEOPEN_FAILED;
		rpphost_debug_print(DEBUG_DATA, "ERROR: create socket failed");
        return errCode;
    }
    return errCode;
}

/******************************************************************************
 * Function Name    : send_msgto_rppslave
 * Description      : Send message to rppslave
 ******************************************************************************/
int32_t send_msgto_rppslave(char *buf, int32_t len)
{
    const int32_t errstr_len = 80;
    char errstr[errstr_len];
	
    struct sockaddr_in sockaddr;
    int32_t slen = sizeof(struct sockaddr);
    int32_t rc = 0;

    // zero out the structure
    memset((char *) &sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(RPP_HOST_SOCK_SEND_PORT_SYNC_MSG);
    sockaddr.sin_addr.s_addr = inet_addr(RPPSLAVE_SOCK_IP);

    rc = sendto(socketFd, buf, len, 0,
            (const struct sockaddr *) &sockaddr,
            slen);
    if (rc == -1) {
		 strerror_r(errno, errstr, errstr_len);
         rpphost_debug_print(DEBUG_DATA, "Error: 'send' [%d-%s]", errno, errstr);
    }

    RppMessageHead *msghdr = (RppMessageHead *)buf;
	print_rpp_msg(msghdr);
    return rc;
}

/******************************************************************************
 * Function Name    : thread_sync_msg_mon
 * Description      : Start monitor sync message
 ******************************************************************************/
void *thread_sync_msg_mon(void *p_threadData)
{
	int size;
	char buf[4096];
	RppMessageHead *msghdr;
	int sock = open_socket_conn(RPPSLAVE_SOCK_IP, RPP_HOST_SOCK_RECV_PORT_SYNC_MSG);
	if (sock < 0) {
		return NULL;
	}

	while((size = read(sock, buf, 4096)) > 0)
	{
		msghdr = (RppMessageHead *)buf;
		print_rpp_msg(msghdr);
	}
	return NULL;
}

/******************************************************************************
 * Function Name    : thread_async_msg_mon
 * Description      : Start monitor async message
 ******************************************************************************/
void *thread_async_msg_mon(void *p_threadData)
{
	int size;
	char buf[4096];
	RppMessageHead *msghdr;
	int sock = open_socket_conn(RPPSLAVE_SOCK_IP, RPP_HOST_SOCK_RECV_PORT_ASYNC_MSG);
	if (sock < 0) {
		return NULL;
	}

	while((size = read(sock, buf, 4096)) > 0)
	{
		msghdr = (RppMessageHead *)buf;
		print_rpp_msg(msghdr);
	}
	return NULL;
}

/******************************************************************************
 * Function Name    : thread_stats_msg_mon
 * Description      : Start monitor stats message
 ******************************************************************************/
void *thread_stats_msg_mon(void *p_threadData)
{
	int size;
	char buf[4096];
	RppMessageHead *msghdr;
	int sock = open_socket_conn(RPPSLAVE_SOCK_IP, RPP_HOST_UDP_STATS_RECV_PORT);
	if (sock < 0) {
		return NULL;
	}

	while((size = read(sock, buf, 4096)) > 0)
	{
		msghdr = (RppMessageHead *)buf;
		print_rpp_msg(msghdr);
	}
	return NULL;
}

/******************************************************************************
 * Function Name    : rpphost_monitor
 * Description      : Start monitor
 ******************************************************************************/
static int rpphost_monitor(int argc, char *argv[])
{
	int32_t ret;
	pthread_t syncMsgMonThreadId;
	pthread_t asyncMsgMonThreadId;
	pthread_t statsMsgMonThreadId;

	int options = 0;
	if (argc > 0) {
		options = atoi(argv[0]);
	}

	if (options <= 0 || options > MON_ALL_THREAD_MASK) { // Default is enable all monitory thread
		options = MON_ALL_THREAD_MASK;
	}

#define MON_THREAD_ENABLE(mask) (options & mask)

	if (MON_THREAD_ENABLE(MON_SYNC_THREAD_MASK)) {
		ret = pthread_create(&syncMsgMonThreadId, NULL, thread_sync_msg_mon, NULL);
		if (ret < 0) {
			rpphost_debug_print(DEBUG_DATA, "Create synchronous message monitor thread failed");
			return -1;
		}
	}
	
	if (MON_THREAD_ENABLE(MON_ASYNC_THREAD_MASK)) {
		ret = pthread_create(&asyncMsgMonThreadId, NULL, thread_async_msg_mon, NULL);
		if (ret < 0) {
			rpphost_debug_print(DEBUG_DATA, "Create asynchronous message monitor thread failed");
			return -1;
		}
	}

	if (MON_THREAD_ENABLE(MON_STATS_THREAD_MASK)) {
		ret = pthread_create(&statsMsgMonThreadId, NULL, thread_stats_msg_mon, NULL);
		if (ret < 0) {
			rpphost_debug_print(DEBUG_DATA, "Create stats message monitor thread failed");
			return -1;
		}
	}

	if (MON_THREAD_ENABLE(MON_SYNC_THREAD_MASK)) {
		pthread_join(syncMsgMonThreadId, NULL);
	}

	if (MON_THREAD_ENABLE(MON_ASYNC_THREAD_MASK)) {
		pthread_join(asyncMsgMonThreadId, NULL);
	}

	if (MON_THREAD_ENABLE(MON_STATS_THREAD_MASK)) {
		pthread_join(statsMsgMonThreadId, NULL);
	}
	return 0;
}

struct rpphost_cmd 
{
	const char *cmd;
	int (*handler)(int phyIndex, int argc, char *argv[]);
	char ** (*completion)(const char *str, int pos);
	const char *usage;
};

/******************************************************************************
 * Function Name    : rpphost_cmd_probe
 * Description      : Send probe request to rppslave
 ******************************************************************************/
static int rpphost_cmd_probe(int phyIndex, int argc, char *argv[])
{
	char buf[4096];
    RppMessageHead *msghdr = (RppMessageHead *)buf;

	msghdr->cat = RPP_MSG_REQ;
	msghdr->type = RPP_MSG_PROB_REQ;
	msghdr->len = RPPMSG_PROB_REQ_SZ;

	return send_msgto_rppslave(buf, msghdr->len);
}

/******************************************************************************
 * Function Name    : rpphost_cmd_get_phy
 * Description      : Send get phy request to rppslave
 ******************************************************************************/
static int rpphost_cmd_get_phy(int phyIndex, int argc, char *argv[])
{
	char buf[4096];
    RppMessageHead *msghdr = (RppMessageHead *)buf;

	msghdr->cat = RPP_MSG_REQ;
	msghdr->type = RPP_MSG_GETPHY_REQ;
	msghdr->len = RPPMSG_GETPHY_REQ_SZ;

	return send_msgto_rppslave(buf, msghdr->len);
}

/******************************************************************************
 * Function Name    : rpphost_cmd_set_phy
 * Description      : Send set phy request to rppslave
 ******************************************************************************/
static int rpphost_cmd_set_phy(int phyIndex, int argc, char *argv[])
{
	if (phyIndex < 0) {
		rpphost_debug_print(DEBUG_DATA, "Invalid radio name");
		return -1;
	}

	char cfgPath[64] = {0};
    if (argc > 0) {
        memcpy(cfgPath, argv[0], strlen(argv[0]));
    }

	char buf[4096];
    RppMessageHead *msghdr = (RppMessageHead *)buf;
	SetPhyReq* phyCfg = (SetPhyReq *)msghdr->body;
	load_phy_cfg(phyCfg, cfgPath);
	phyCfg->handle = phyIndex;

	msghdr->cat = RPP_MSG_REQ;
	msghdr->type = RPP_MSG_SETPHY_REQ;
	msghdr->len = RPPMSG_SETPHY_REQ_SZ;

	return send_msgto_rppslave(buf, msghdr->len);
}

/******************************************************************************
 * Function Name    : rpphost_cmd_scan
 * Description      : Send scan request to rppslave
 ******************************************************************************/
static int rpphost_cmd_scan(int phyIndex, int argc, char *argv[])
{
	if (phyIndex < 0) {
		rpphost_debug_print(DEBUG_DATA, "Invalid radio name");
		return -1;
	}

	char buf[4096];
    RppMessageHead *msghdr = (RppMessageHead *)buf;
	ScanReq* scanCfg = (ScanReq *)msghdr->body;
	scanCfg->phyhandle = phyIndex;
	scanCfg->duration = 10; // Scan duration

	msghdr->cat = RPP_MSG_REQ;
	msghdr->type = RPP_MSG_SCAN_REQ;
	msghdr->len = RPPMSG_SCAN_REQ_SZ;

	return send_msgto_rppslave(buf, msghdr->len);
}

/******************************************************************************
 * Function Name    : rpphost_cmd_add_station
 * Description      : Send add station request to rppslave
 ******************************************************************************/
static int rpphost_cmd_add_station(int phyIndex, int argc, char *argv[])
{
	if (phyIndex < 0) {
		rpphost_debug_print(DEBUG_DATA, "Invalid radio name");
		return -1;
	}

	char cfgPath[64] = {0};
    if (argc > 0) {
        memcpy(cfgPath, argv[0], strlen(argv[0]));
    } else {
        strcpy(cfgPath, DEFAULT_STA_CONFIG_PATH);
    }

	char buf[4096];
	int devCnt = 0;
	char macStr[MAC_ADDR_STR_LEN];
    RppMessageHead *msghdr = (RppMessageHead *)buf;
    AddStaReq* staCfg = (AddStaReq *)msghdr->body;
	load_sta_cfg(staCfg, &devCnt, cfgPath);
	staCfg->phyhandle = phyIndex;

	int delayUSec = DEFAULT_DELAY_PER_CMD_MSEC * 1000;
	if (argc > 1) {
		delayUSec = atoi(argv[1]) * 1000;
		rpphost_debug_print(DEBUG_DATA, "Add station with delay: %d msec", delayUSec/1000);
	}

	msghdr->cat = RPP_MSG_REQ;
	msghdr->type = RPP_MSG_ADDSTA_REQ;
	msghdr->len = RPPMSG_ADDSTA_REQ_SZ + staCfg->exdatalen; // Include exdatalen (encryption informations)

	rpphost_debug_print(DEBUG_DATA, "Add station device count: %d", devCnt);
	for (int i=0; i<devCnt; i++) {
		if (i>0) {
			usleep(delayUSec);
		}
        util_mac_addr_to_str(staCfg->mac, macStr);
		if (i>0 && increase_mac_number(staCfg->mac, 1)) { // Increase mac number failed
            rpphost_debug_print(DEBUG_DATA, "ERR_MSG------->Mac number slot is full at device number: %d mac: %s", i, macStr);
            break;
        }

		if (send_msgto_rppslave(buf, msghdr->len) < 0) {
			rpphost_debug_print(DEBUG_DATA, "Send command to add station#%d mac: %s failed", i, macStr);
		} else {
			rpphost_debug_print(DEBUG_DATA, "Send command to add station#%d mac: %s success", i, macStr);
		}
	}
	return 0;
}

/******************************************************************************
 * Function Name    : rpphost_cmd_associate
 * Description      : Send associate station request to rppslave
 ******************************************************************************/
static int rpphost_cmd_associate(int phyIndex, int argc, char *argv[])
{
	if (phyIndex < 0) {
		rpphost_debug_print(DEBUG_DATA, "Invalid radio name");
		return -1;
	}

	RppMessageHead *msghdr;
	AssocReq* assocReq;

	char buf[4096];
	if (argc < 1) {
		rpphost_debug_print(DEBUG_DATA, "Incomplete command or Invalid station name");
		return -1;
	}

	// Support multiple interfaces: sta0-sta10,sta12,sta15-sta20
	int intfCnt = 0;
	int *intfs = parse_intf_index(argv[0], DEVICE_INF_PREFIX, &intfCnt);
	if (intfCnt == 0 || intfs == NULL) {
		rpphost_debug_print(DEBUG_DATA, "Parse to associate station failed: %s", argv[0]);
		free(intfs);
		return -1;
	}

	int delayUSec = DEFAULT_DELAY_PER_CMD_MSEC * 1000;
	if (argc > 1) {
		delayUSec = atoi(argv[1]) * 1000;
		rpphost_debug_print(DEBUG_DATA, "Associate station with delay: %d msec", delayUSec/1000);
	}
	
	msghdr = (RppMessageHead *)buf;
	msghdr->cat = RPP_MSG_REQ;
	msghdr->type = RPP_MSG_ASSOC_REQ;
	msghdr->len = RPPMSG_ASSOC_REQ_SZ;
	assocReq = (AssocReq *)msghdr->body;
    assocReq->phyhandle = phyIndex;

	for (int i=0; i<intfCnt; i++) {
		if (i>0) {
			usleep(delayUSec);
		}
		assocReq->stahandle = intfs[i];
		if (send_msgto_rppslave(buf, msghdr->len) == -1) {
			rpphost_debug_print(DEBUG_DATA, "ERR_MSG------->Associate station failed at station: sta%d", intfs[i]);
		}
	}
	free(intfs);
	return 1;
}

/******************************************************************************
 * Function Name    : rpphost_cmd_disassociate
 * Description      : Send disassociate station request to rppslave
 ******************************************************************************/
static int rpphost_cmd_disassociate(int phyIndex, int argc, char *argv[])
{
	if (phyIndex < 0) {
		rpphost_debug_print(DEBUG_DATA, "Invalid radio name");
		return -1;
	}

	RppMessageHead *msghdr;
	DeAssocReq* deassocReq;

	char buf[4096];
	if (argc < 1 || strncmp(argv[0], DEVICE_INF_PREFIX, 3)) {
		rpphost_debug_print(DEBUG_DATA, "Incomplete command or Invalid station name");
		return -1;
	}

	// Support multiple interfaces: sta0-sta10,sta12,sta15-sta20
	int intfCnt = 0;
	int *intfs = parse_intf_index(argv[0], DEVICE_INF_PREFIX, &intfCnt);
	if (intfCnt == 0 || intfs == NULL) {
		rpphost_debug_print(DEBUG_DATA, "Parse to disassociate station failed: %s", argv[0]);
		free(intfs);
		return -1;
	}

	int delayUSec = DEFAULT_DELAY_PER_CMD_MSEC * 1000;
	if (argc > 1) {
		delayUSec = atoi(argv[1]) * 1000;
		rpphost_debug_print(DEBUG_DATA, "Disassociate station with delay: %d msec", delayUSec/1000);
	}
	
	msghdr = (RppMessageHead *)buf;
	msghdr->cat = RPP_MSG_REQ;
	msghdr->type = RPP_MSG_DEASSOC_REQ;
	msghdr->len = RPPMSG_DEASSOC_REQ_SZ;
	deassocReq = (DeAssocReq *)msghdr->body;
    deassocReq->phyhandle = phyIndex;

	for (int i=0; i<intfCnt; i++) {
		if (i>0) {
			usleep(delayUSec);
		}
		deassocReq->stahandle = intfs[i];
		if (send_msgto_rppslave(buf, msghdr->len) == -1) {
			rpphost_debug_print(DEBUG_DATA, "ERR_MSG------->Disassociate station failed at station: sta%d", intfs[i]);
		}
	}
	free(intfs);
	return 1;
}

/******************************************************************************
 * Function Name    : rpphost_cmd_remove_station
 * Description      : Send remove station request to rppslave
 ******************************************************************************/
static int rpphost_cmd_remove_station(int phyIndex, int argc, char *argv[])
{
	if (phyIndex < 0) {
		rpphost_debug_print(DEBUG_DATA, "Invalid radio name");
		return -1;
	}

	RppMessageHead *msghdr;
	DelStaReq* delReq;

	char buf[4096];
	if (argc < 1 || strncmp(argv[0], DEVICE_INF_PREFIX, 3)) {
		rpphost_debug_print(DEBUG_DATA, "Incomplete command or Invalid station name");
		return -1;
	}

	// Support multiple interfaces: sta0-sta10,sta12,sta15-sta20
	int intfCnt = 0;
	int *intfs = parse_intf_index(argv[0], DEVICE_INF_PREFIX, &intfCnt);
	if (intfCnt == 0 || intfs == NULL) {
		rpphost_debug_print(DEBUG_DATA, "Parse to remove station failed: %s", argv[0]);
		free(intfs);
		return -1;
	}

	int delayUSec = DEFAULT_DELAY_PER_CMD_MSEC * 1000;
	if (argc > 1) {
		delayUSec = atoi(argv[1]) * 1000;
		rpphost_debug_print(DEBUG_DATA, "Remove station with delay: %d msec", delayUSec/1000);
	}
	
	msghdr = (RppMessageHead *)buf;
	msghdr->cat = RPP_MSG_REQ;
	msghdr->type = RPP_MSG_DELSTA_REQ;
	msghdr->len = RPPMSG_DELSTA_REQ_SZ;
	delReq = (DelStaReq *)msghdr->body;
    delReq->phyhandle = phyIndex;

	for (int i=0; i<intfCnt; i++) {
		if (i>0) {
			usleep(delayUSec);
		}
		delReq->stahandle = intfs[i];
		if (send_msgto_rppslave(buf, msghdr->len) == -1) {
			rpphost_debug_print(DEBUG_DATA, "ERR_MSG------->Remove station failed at station: sta%d", intfs[i]);
		}
	}
	free(intfs);

	return 1;
}

static const struct rpphost_cmd rpphost_commands[] = {
	{ "probe", rpphost_cmd_probe, NULL, 
	  "probe request" },
	{ "getphy", rpphost_cmd_get_phy, NULL, 
	  "get phy configuration" },
	{ "setphy", rpphost_cmd_set_phy, NULL, 
	  "set phy configuration" },
	{ "scan", rpphost_cmd_scan, NULL, 
	  "execute scan request" },
	{ "create", rpphost_cmd_add_station, NULL,
	  "create a station" },
	{ "associate", rpphost_cmd_associate, NULL,
	  "associate given station" },
	{ "disassociate", rpphost_cmd_disassociate, NULL,
	  "disassociate given station" },
	{ "remove", rpphost_cmd_remove_station, NULL,
	  "remove a station" },
	{ NULL, NULL, NULL, NULL }
};

/******************************************************************************
 * Function Name    : rpphost_request
 * Description      : Handle rpphost request
 ******************************************************************************/
static int rpphost_request(char *phy, int argc, char *argv[])
{
	const struct rpphost_cmd *cmd, *match = NULL;
	int count;
	int ret = 0;

	if (argc == 0) {
		return -1;
	}

	int phyIndex = get_inf_index(phy, "", -1); // Get phy index (prefix is "")
	count = 0;
	cmd = rpphost_commands;
	while (cmd->cmd) 
	{
		if (strncasecmp(cmd->cmd, argv[0], strlen(argv[0])) == 0) {
			match = cmd;
			if (strcasecmp(cmd->cmd, argv[0]) == 0) {
				/* we have an exact match */
				count = 1;
				break;
			}
			count++;
		}
		cmd++;
	}

	if (count > 1) {
		rpphost_debug_print(DEBUG_DATA, "Ambiguous command '%s'; possible commands:", argv[0]);
		cmd = rpphost_commands;
		while (cmd->cmd) {
			if (strncasecmp(cmd->cmd, argv[0], strlen(argv[0])) == 0) {
				rpphost_debug_print(DEBUG_DATA, " %s", cmd->cmd);
			}
			cmd++;
		}
		rpphost_debug_print(DEBUG_DATA, "\n");
		ret = 1;
	} else if (count == 0) {
		rpphost_debug_print(DEBUG_DATA, "Unknown command '%s'", argv[0]);
		ret = 1;
	} else {
		ret = match->handler(phyIndex, argc - 1, &argv[1]);
	}

	return ret;
}

/******************************************************************************
 * Function Name    : main
 * Description      : Main function
 ******************************************************************************/
int main(int argc, char *argv[])
{
	char *radio_name = NULL;
	int c;
	int ret = 0;
	if (argc <= 1) {
		usage();
		return -1;
	}

	for (;;) {
		c = getopt(argc, argv, "r:h:m");
		if (c < 0)
			break;
		switch (c) 
		{
			case 'r':
			{
				radio_name = optarg;
				break;
			}
			case 'h':
			{
				usage();
				return 0;
			}
			case 'm':
			{
				rpphost_monitor(argc - optind, &argv[optind]);
				return 0;
			}
			default:
			{
				usage();
				return -1;
			}
		}
	}
	init_comm();
	ret = rpphost_request(radio_name, argc - optind, &argv[optind]);
	return ret;
}
