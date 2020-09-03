#ifndef _RPPHOST_HELPER_H_
#define _RPPHOST_HELPER_H_

#include "rpp_message.h"
#include "rpp_ethcomm.h"

#define MAX_INTF_NUM 256
#define MAX_INTF_IDX (MAX_INTF_NUM - 1)
#define MAC_ADDR_STR_LEN 18

#define MON_SYNC_THREAD_MASK 1
#define MON_ASYNC_THREAD_MASK 2
#define MON_STATS_THREAD_MASK 4
#define MON_ALL_THREAD_MASK (MON_SYNC_THREAD_MASK | MON_ASYNC_THREAD_MASK | MON_STATS_THREAD_MASK)

#define RPPSLAVE_SOCK_IP "192.168.1.2"

#define DEVICE_INF_PREFIX "sta"

#define rpphost_debug_print(level, msg, ...) \
    do { \
        printf("(%d): "msg"\n", __LINE__, ##__VA_ARGS__); \
    } while(false)

// Map key to value
struct KeyValMap 
{
    char *key; 
    int val;
};

void usage(void);

int *parse_intf_index(const char *str, const char *prefix, int *intfCnt);

void util_mac_addr_to_str(uint8_t *addr, char *buff);

int open_socket_conn(const char *addr, int port);

int get_inf_index(const char *str, const char *prefix, int def);

int find_val_in_map(const struct KeyValMap *map, size_t mapLen, const char *key, const int def);

const char *find_key_in_map(const struct KeyValMap *map, size_t mapLen, const int val);

void print_rpp_msg(RppMessageHead *msghdr);

int increase_mac_number(uint8_t *mac, uint8_t incNum);

int load_sta_cfg(AddStaReq *staCfg, int *devCnt, const char *cfgPath);

int load_phy_cfg(SetPhyReq *phyCfg, const char *cfgPath);

#endif /* _RPPHOST_HELPER_H_ */