#ifndef _RPP_HEADER_H_
#define _RPP_HEADER_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <inttypes.h>

#include <unistd.h>

#include <sys/ipc.h>
#include <sys/sem.h>
#include <semaphore.h>
#include <pthread.h>

#include <signal.h>
#include <stdbool.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <errno.h>
#include<syslog.h>

#ifdef THREE_RADIO
	#define RPP_NUM_OF_RADIO 3
#else
	#define RPP_NUM_OF_RADIO 2
#endif

#define FIVE_G_RADIO_0 0
#define TWO_G_RADIO_1 1
#define FIVE_G_RADIO_2 2

#define RPP_APP_DEFNUM_ZERO 0
#define RPP_APP_DEFNUM_ONE  1
#define RPP_APP_DEFNUM_TWO  2
#define RPP_APP_DEFNUM_THREE    3
#define RPP_APP_DEFNUM_FOUR 4
#define RPP_APP_DEFNUM_FIVE     5
#define RPP_APP_DEFNUM_SIX  6
#define RPP_APP_DEFNUM_SEVEN    7
#define RPP_APP_DEFNUM_EIGHT    8
#define RPP_APP_DEFNUM_NINE     9
#define RPP_APP_DEFNUM_TEN      10
#define RPP_APP_DEFNUM_ELEVEN   11
#define RPP_APP_DEFNUM_TWELVE   12

#define ETHER_MAC_ADDR_LEN      6
#define MAC_STRING_FORMAT       "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"
/*#define DEBUG_ENA */

#define MUMIMO_OFDMA_PROXY_DISABLE

//#define PROXY_STA
extern uint8_t PROXY_STA[RPP_NUM_OF_RADIO];

#define DEBUG_INFO  RPP_APP_DEFNUM_ONE
#define DEBUG_DATA  RPP_APP_DEFNUM_TWO

#ifdef DEBUG_ENA
#define debug_print(value, msg, ...)  do { \
                        printf("\n"msg" - (%d)\n", ##__VA_ARGS__, __LINE__); \
                       } while(false)
#define dbg_printf(msg, ...)  do { \
                        printf("\n"msg" - (%d)\n", ##__VA_ARGS__, __LINE__); \
                       } while(false)


#else
#define debug_print(value, msg, ...)  do { }while(false)
#define dbg_printf(msg, ...)  do { }while(false)
#endif

#define SYSLOG_PRINT(x,fmt, ...) {\
syslog(x, fmt,  ##__VA_ARGS__);  }

enum rppAppFuncErrCode {
    RPP_APP_RET_FILEOPEN_FAILED = -7,
    RPP_APP_RET_NULL_POINTER,
    RPP_APP_RET_MALLOC_FAILED,
    RPP_APP_RET_COMMAND_FAILED,
    RPP_APP_RET_READ_FAILED,
    RPP_APP_RET_EXISTS,
    RPP_APP_RET_REPLACED,
    RPP_APP_RET_SUCCESS
};

typedef enum {
     REVANCHE_IRET_FAILURE = 0,
     REVANCHE_IRET_SUCCESS
} revanche_inf_return_et;

enum nssconfig {
    DEFAULT_NSS,
    NSS1,
    NSS2,
    NSS3,
    NSS4
};

enum chainmaskconfig {
    SMA_1_5_CHAINMASK      = 17,
    SMA_2_6_CHAINMASK      = 34,
    SMA_3_7_CHAINMASK      = 68,
    SMA_4_8_CHAINMASK      = 136,
    SMA_12_56_CHAINMASK    = 51,
    SMA_34_78_CHAINMASK    = 204,
    SMA_ALL_CHAINMASK      = 255
};

typedef enum {
     REVANCHE_IECODE_NO_ERR = 1,
     REVANCHE_IECODE_READ_TIMEOUT = 2,
     REVANCHE_IECODE_PERMS_ERR = 3,
     REVANCHE_IECODE_INVALID_PARAM = 4,
     REVANCHE_IECODE_NO_MEMORY = 5,
     REVANCHE_IECODE_WRITE_ERR = 6,
     REVANCHE_IECODE_ERR_OPEN_DEVFILE = 7,
     REVANCHE_IECODE_ERR_CLOSE_DEVFILE = 8,
     REVANCHE_IECODE_READ_ERR = 9,
     REVANCHE_IECODE_MAGIC_ERR = 10
} revanche_inf_ecode_et;

typedef enum {
     APINFO_SUCCESS = 0,
     APINFO_NOTFOUND,
     APINFO_FAILURE = -1,
} revanche_apinfo_returnCode;

typedef struct {
    uint8_t mac_address[ETHER_MAC_ADDR_LEN];
} apMacAddData;

typedef struct {
    uint8_t proxy_mac_address[ETHER_MAC_ADDR_LEN];
} proxyStaMacAddData;

typedef struct {
    uint32_t freqband;
    uint8_t chwidth;
    uint8_t bw160nssworkaround;
    bool is11kEnable;
    bool is11vEnable;
    bool is11vtriggered;
    bool is11ktriggered; 
    int8_t rssi;
    int8_t ftRoamThreshold;
    int8_t scanThreshold;
    time_t roam11kv_trigger_time;
}gSphyBandInfo;
#endif /* _RPP_HEADER_H_ */
