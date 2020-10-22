
/*****************************************************************************
 *                                                                           *
 *  FILE NAME            : rev_utils_monitor.h                               *
 *  AUTHOR               : Aricent                                           *
 *  DESCRIPTION          : This file contains include files, macros and      *
 *                         function declarations for moniotr utility         *
 *                         implementation                                    *
 *****************************************************************************/

#ifndef __REV_UTILS_MONITOR_H
#define __REV_UTILS_MONITOR_H

/*****************************************************************************
 * INCLUDE FILES
 *****************************************************************************/
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <pthread.h>
/*****************************************************************************
 * MACRO DEFINITONS
 *****************************************************************************/
#define REV_UTILS_MON_PRINT(x,fmt, ...) { printf(fmt, ##__VA_ARGS__); \
                                        syslog(x, fmt,  ##__VA_ARGS__);}
#define TFTP_SERVER_IP_SLOT0      "192.168.1.1"
#define TFTP_SERVER_IP_SLOT1      "192.168.3.1"
#define GPIO_26_SYS_INTF          "/sys/class/gpio/gpio26/value"
#define GPIO_54_SYS_INTF          "/sys/class/gpio/gpio54/value"
#define GPIO_31_SYS_INTF          "/sys/class/gpio/gpio31/value"
#define RPPSLAVE_PROCESS          "/usr/bin/rppslave"
#define BUFFER_SIZE               100
#define IP_ADDRESS_SIZE           15
#define UPGRADE_FILE_PATH         "/tmp/norplusnand-ipq807x_64-single.img"
#define UPGRADE_FILE              "norplusnand-ipq807x_64-single.img"
#define UPGRADE_LOG_FILE          "/var/log/upgrade.log"
#define GPIO_26                   26
#define GPIO_31                   31
#define GPIO_54                   54
#define NUM_GPIO_PINS             3
/*****************************************************************************
 * GLOBAL STRUCTURES
 *****************************************************************************/
/*****************************************************************************
 * FUNCTION PROTOTYPES
 *****************************************************************************/
void start_rev_utils_monitor_daemon(void);
int get_ip_address();
int initialize_rev_utils_monitor(void);
#endif /* __REV_UTILS_MONITOR_H */
