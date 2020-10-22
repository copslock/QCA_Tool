#ifndef RPP_WPACTRL_HELPER_H_
#define RPP_WPACTRL_HELPER_H_

#include "rpp_header.h"

typedef struct StaStateInfo {
    uint8_t reasonCode;
    uint8_t assocStatus;
    uint8_t bssid[ETHER_MAC_ADDR_LEN];
} StaStateInfo;

int open_wpa_ctrl_conn(int32_t radioIndex);

void close_wpa_ctrl_conn(int32_t radioIndex);

int get_sta_state(StaStateInfo *stateInfo, int radioIndex, char *intfName, uint8_t staIndex);

int config_network_intf(uint32_t radioIndex, const char *cmdFormat, ...);

#endif /* RPP_WPACTRL_HELPER_H_ */
