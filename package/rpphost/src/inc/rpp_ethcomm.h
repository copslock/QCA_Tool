#ifndef _RPP_IPC_COMM_H_
#define _RPP_IPC_COMM_H_

#include "rpp_header.h"
#include "rpp_capture.h"

#define RPP_LOCAL_HOST_IP_ADDRESS               "127.0.0.1"
#define RPP_HOST_SOCK_RECV_PORT_SYNC_MSG        (7098)
#define RPP_HOST_SOCK_RECV_PORT_ASYNC_MSG       (7099)
#define RPP_HOST_SOCK_SEND_PORT_SYNC_MSG        (8098)
#define RPP_HOST_TCP_SOCK_RECV_STATS_UPDT       (8099)
#define RPP_HOST_UDP_STATS_RECV_PORT            (7100)
#define RPP_SLAVE_SOCK_DOMAIN                   (AF_INET)
#define RPP_SLAVE_SOCK_TYPE                     (SOCK_STREAM)
#define RPP_SLAVE_SOCK_PROTOCOL                 (SOCK_DGRAM)

#define CAPDAEMON_PORT_NUM	5001

typedef struct {
	short int msgId;
	unsigned int msgLength;
	char data[100];
}__attribute__((packed)) rppCapDataInfo;

int32_t init_eth_comm(void);
int32_t deinit_eth_comm(void);
int32_t send_eth_msgto_fpga(const char *cmd, int32_t len);
int32_t send_eth_async_msgto_fpga(const char *buf, int32_t len);
int32_t recv_eth_msgfrom_fpga(char *buf, int32_t len);
int32_t rpp_receive_datafrom_monitord(monitordResponse_t *p_mResp, uint32_t phyhandle);
int32_t rpp_send_datato_monitord(captureParam_t *param_t, uint32_t phyhandle);
int32_t send_stats_buffer_to_fpga(const char *buf, int32_t len);
ssize_t send_eth_udp_stats_to_fpga(const char *buf, int32_t len);

#endif /* _RPP_IPC_COMM_H_ */
