#ifndef __BSP_REVANCHE_UPGRADE_H__
#define __BSP_REVANCHE_UPGRADE_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <mtd/mtd-user.h>
#include <sys/ioctl.h>
#include "revanche_enums_common.h"

#define BSP_REVANCHE_INVE_DEBUG	1
#define BSP_REVANCHE_READ        1
#define BSP_REVANCHE_WRITE       2


#ifdef BSP_REVANCHE_INVE_DEBUG
#define UPGRADE_API_ERROR(msg, args...)     do {printf("[%s] %d\t", __func__, __LINE__); printf(msg, ##args);printf("\n"); }while(0)
#else
#define UPGRADE_API_ERROR(msg, args...)     do { }while(0)
#endif

typedef char            INT1;
typedef short           INT2;
typedef unsigned char   UINT1;
typedef unsigned short  UINT2;
typedef int             INT4;
typedef unsigned int    UINT4;
typedef unsigned long   UINT8;
typedef void            VOID;

typedef unsigned char   revanche_u8_t;
typedef unsigned int    revanche_u32_t;


/* MTD number */
#define	PRIMARY_BOOTCONFIG		2
#define	SECONDARY_BOOTCONFIG		3

#define	ROOTFS	7

#define _SMEM_DUAL_BOOTINFO_MAGIC_START         0xA3A2A1A0
#define _SMEM_DUAL_BOOTINFO_MAGIC_END           0xB3B2B1B0

#define MTD_DEV_NAME_SIZE	15

#define BSP_REVANCHE_BOOTFLAG_WRITE	2
#define BSP_REVANCHE_BOOTFLAG_READ	1
#define NUM_ALT_PARTITION 16
#define ALT_PART_NAME_LENGTH 16

#define BUF_SIZE           1024
#define CRASH_DUMP_ADDRESS 0x10000
#define ERASE_SIZE         65536

struct per_part_info
{
        char name[ALT_PART_NAME_LENGTH];
        uint32_t primaryboot;
};

typedef struct bootFlagConfigInfo{

        /* Magic number for identification when reading from flash */
        uint32_t magic_start;
        /* upgradeinprogress indicates to attempting the upgrade */
        uint32_t    age;
        /* numaltpart indicate number of alt partitions */
        uint32_t    numaltpart;

        struct per_part_info per_part_entry[NUM_ALT_PARTITION];

        uint32_t magic_end;
        uint32_t primary_count;
        uint32_t secondary_count;

}bootFlagInfo;

revanche_inf_return_et revanche_update_boot_count(revanche_inf_ecode_et *p_ecode);
revanche_inf_return_et revanche_ctrl_read_boot_count(uint32_t *primary_boot_cnt, uint32_t *secondary_boot_cnt, revanche_inf_ecode_et *p_ecode);
revanche_inf_return_et revanche_ctrl_write_boot_count(uint32_t boot_cnt, uint32_t primary, revanche_inf_ecode_et *p_ecode);
revanche_inf_return_et revanche_ctrl_read_active_partition(uint32_t *active_partition, revanche_inf_ecode_et *p_ecode);
bsp_revanche_status bsp_mtd_dev_bflag_rw(UINT1 option,UINT1 dev_to, bootFlagInfo *bsp_idu_bflag_data);
revanche_inf_return_et revanche_read_crashlog(char *buf);
revanche_inf_return_et revanche_clear_crashlog();
#endif







