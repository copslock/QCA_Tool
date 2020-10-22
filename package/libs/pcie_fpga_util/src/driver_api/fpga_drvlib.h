#ifndef __FPGA_DRVLIB_H__
#define  __FPGA_DRVLIB_H__

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close
#include <string.h>

#define IPQ_FW_VER_REG            0x30
#define IPQ_HW_VER_REG            0x30
#define IPQ_UPGRADE_STATUS_REG    0x34
#define IPQ_BOOTUP_STATUS_REG     0x38

int set_ipq_appln_bootup_status(uint32_t value);
int set_ipq_upgrade_status(uint32_t value);
int get_ipq_sw_version(uint32_t *version);
#endif /* __FPGA_DRV_LIB_H__ */


