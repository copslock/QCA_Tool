
/*****************************************************************************
 *                                                                           *
 *  FILE NAME            : revanche_upgrade.h                                *
 *  AUTHOR               : Aricent                                           *
 *  DESCRIPTION          : This file contains include files, macros and      *
 *                         function declarations for upgrade utility         *
 *                         implementation                                    *
 *****************************************************************************/

#ifndef __REVANCHE_UPGRADE_H
#define __REVANCHE_UPGRADE_H

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
/*****************************************************************************
 * MACRO DEFINITONS
 *****************************************************************************/
#define REVANCHE_UPGRADE_PRINT(x,fmt, ...) { printf(fmt, ##__VA_ARGS__); \
                                        syslog(x, fmt,  ##__VA_ARGS__);}
#define TFTP_SERVER_IP            "192.168.1.1"
#define BUFFER_SIZE               250
#define IP_ADDRESS_SIZE           15
#define UPGRADE_FILE_PATH         "/tmp/IPQ.bin"
#define UPGRADE_FILE_PATH1        "/tmp/IPQ-tmp.bin"
#define UPGRADE_FILE              "IPQ.bin"
#define IMAGE_FILE_SIZE           22
#define UPGRADE_LOG_FILE          "/tmp/log/upgrade.log"
#define UPGRADE_SUCCESS           0
#define UPGRADE_TFTP_FAILED       0x00000001
#define UPGRADE_IMG_INVALID       0x00000002
#define REVANCHE_SW_VER_FILE      "/etc/ipq_image_version"
#define DEFAULT_VERSION           0xFFFFFFFF
/*****************************************************************************
 * GLOBAL STRUCTURES
 *****************************************************************************/
/*****************************************************************************
 * FUNCTION PROTOTYPES
 *****************************************************************************/
void start_revanche_upgrade_daemon(void);
#endif /* __REVANCHE_UPGRADE_H */
