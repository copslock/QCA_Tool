/*****************************************************************************
*  FILE NAME             : sw_upgrade.c
*  PRINCIPAL AUTHOR      : Revanche team
*  SUBSYSTEM NAME        : MTD bootflag Access Driver APIs
*  MODULE NAME           : Driver API
*  LANGUAGE              : C
*  DATE OF FIRST RELEASE :
*  AUTHOR                :
*  FUNCTIONS DEFINED(Applicable for Source files) :
*  DESCRIPTION           : This file contains the MTD bootflag Acesss Driver
*                          API implementations.
******************************************************************************/
#include "sw_upgrade.h"
#include <sys/stat.h>

/******************************************************************************
 * Function Name         : bsp_mtd_dev_open
 * Description           : This function is used to open the MTD device file.
 * Input(s)              : UINT1 dev_num, UINT1* mtd_fd
 * Output(s)             :
 * <OPTIONAL Fields>     :
 * Global Variables Referred :
 * Global variables Modified :
 * Exceptions or Operating System Error Handling :
 * Use of Recursion      :
 * Returns               : UPGRADE_OK/UPGRADE_ERROR
********************************************************************************/
revanche_inf_return_et bsp_mtd_dev_open(UINT1 dev_num, UINT1* mtd_fd)
{
    UINT1 dev_name[MTD_DEV_NAME_SIZE];
    int mtd_fd2 =0;

    sprintf(dev_name, "/dev/mtd%d", dev_num);
    printf("\nOpening device:%s",dev_name);

    /* opening the MTD device file */
    mtd_fd2 = open(dev_name, O_RDWR);

    printf("\nvalue in mtd_fd = %d\n",mtd_fd2);

    /* error check for open system call */
    if (mtd_fd2 < 0 ) {
        UPGRADE_API_ERROR("\n%s, MTD dev open failed, dev=%s ret=%d",
                                __func__,dev_name, mtd_fd2);
        return REVANCHE_IRET_FAILURE;
    }

   *mtd_fd = (UINT1) mtd_fd2;

   return REVANCHE_IRET_SUCCESS;
}

/******************************************************************************
 * Function Name         : bsp_mtd_dev_close
 * Description           : This function is used to close the MTD device file.
 * Input(s)              : UINT1 mtd_fd
 * Output(s)             :
 * <OPTIONAL Fields>     :
 * Global Variables Referred :
 * Global variables Modified :
 * Exceptions or Operating System Error Handling :
 * Use of Recursion      :
 * Returns               : REVANCHE_IRET_SUCCESS/REVANCHE_IRET_FAILURE
********************************************************************************/

revanche_inf_return_et bsp_mtd_dev_close(UINT1 mtd_fd)
{
    int ret = 0;

    /* closing MTD device file */
    ret = close(mtd_fd);
    if (ret) {
        UPGRADE_API_ERROR("\n%s, MTD dev close failed, ret=%d", __func__, ret);
        return REVANCHE_IRET_FAILURE;
    }

    return REVANCHE_IRET_SUCCESS;
}

/******************************************************************************
 * Function Name         : bsp_bf_mtd_dev_erase
 * Description           : This API does memory erase.
 * Input(s)              : UINT1 dev_to, struct erase_info_user *erase
 * Output(s)             :
 * <OPTIONAL Fields>     :
 * Global Variables Referred :
 * Global variables Modified :
 * Exceptions or Operating System Error Handling :
 * Use of Recursion      :
 * Returns               : REVANCHE_IRET_SUCCESS/REVANCHE_IRET_FAILURE
********************************************************************************/

bsp_revanche_status bsp_bf_mtd_dev_erase(UINT1 dev_to, struct erase_info_user *erase)
{
        int ret = 0;

        ret = ioctl(dev_to, MEMERASE, erase);
        if (ret < 0) {
                UPGRADE_API_ERROR("\nERR: MTD IOCTL");
                bsp_mtd_dev_close(dev_to);
                return REVANCHE_IRET_FAILURE;
        }

	return REVANCHE_IRET_SUCCESS;
}

/******************************************************************************
 * Function Name         : bsp_mtd_dev_bflag_rw
 * Description           : This API is used to read/write from bootconfig partition
 * Input(s)              : UINT1 option,UINT1 dev_to, bootFlagInfo *bsp_idu_bflag_data
 * Output(s)             :
 * <OPTIONAL Fields>     :
 * Global Variables Referred :
 * Global variables Modified :
 * Exceptions or Operating System Error Handling :
 * Use of Recursion      :
 * Returns               : REVANCHE_IRET_SUCCESS/REVANCHE_IRET_FAILURE
********************************************************************************/

bsp_revanche_status bsp_mtd_dev_bflag_rw(UINT1 option,UINT1 dev_to, bootFlagInfo *bsp_idu_bflag_data)
{
        if (BSP_REVANCHE_WRITE == option) {
                lseek(dev_to, 0x0, SEEK_SET);
		INT4 write_size = 0;
                write_size = write(dev_to, bsp_idu_bflag_data, sizeof(bootFlagInfo));
                if (write_size == 0) {
                        UPGRADE_API_ERROR("\nERR: MTD Write");
                        bsp_mtd_dev_close(dev_to);
                        return REVANCHE_IRET_FAILURE;
                }
        } else if (BSP_REVANCHE_READ == option) {
                lseek(dev_to, 0x0, SEEK_SET);
		INT4 read_size = 0;
                read_size = read(dev_to, bsp_idu_bflag_data, sizeof(bootFlagInfo));
                if (read_size == 0) {
                        UPGRADE_API_ERROR("\nERR: MTD Read");
                        bsp_mtd_dev_close(dev_to);
                        return REVANCHE_IRET_FAILURE;
                }
        }
        return REVANCHE_IRET_SUCCESS;
}

/******************************************************************************
 * Function Name         : bsp_mtd_dev_crashread
 * Description           : This API is used to read crash log from boot config
 *                         partition
 * Input(s)              : UINT1 dev_to(mtd ptr), char *buf(buffer to read),
 *                         size_t buflen(length to read)
 * Output(s)             :
 * <OPTIONAL Fields>     :
 * Global Variables Referred :
 * Global variables Modified :
 * Exceptions or Operating System Error Handling :
 * Use of Recursion      :
 * Returns               : REVANCHE_IRET_SUCCESS/REVANCHE_IRET_FAILURE
********************************************************************************/
bsp_revanche_status bsp_mtd_dev_crashread(UINT1 dev_to, char *buf, size_t buflen)
{
		INT4 read_size = 0;

        /* Set the pointer in boot config partition to point crash dump address */
        lseek(dev_to, CRASH_DUMP_ADDRESS, SEEK_SET);
        /* Read crash dump log */
        read_size = read(dev_to, buf, buflen);

        if (read_size == 0) {
                UPGRADE_API_ERROR("\nERR: MTD Read");
                bsp_mtd_dev_close(dev_to);
                return REVANCHE_IRET_FAILURE;
        }

        return REVANCHE_IRET_SUCCESS;
}

/******************************************************************************
 * Function Name         : revanche_get_dev_num
 * Description           : This API is used to get MTD device number to read
			   valid bootconfig partition.
 * Input(s)              : UINT1 dev_num
 * Output(s)             :
 * <OPTIONAL Fields>     :
 * Global Variables Referred :
 * Global variables Modified :
 * Exceptions or Operating System Error Handling :
 * Use of Recursion      :
 * Returns               : REVANCHE_IRET_SUCCESS/REVANCHE_IRET_FAILURE
********************************************************************************/

revanche_inf_return_et revanche_get_dev_num (UINT1 *dev_num)
{
        UINT1 dev_to, rc;
        bootFlagInfo mtd_bfsp;
	uint32_t primary;

        rc=bsp_mtd_dev_open(PRIMARY_BOOTCONFIG, &dev_to);
        if(!rc)
        return 0;

        if( 0>bsp_mtd_dev_bflag_rw(1,dev_to,&mtd_bfsp) ){
                printf("\nERR: MTD Read");
                return REVANCHE_IRET_FAILURE;
        }

        if((mtd_bfsp.magic_start != _SMEM_DUAL_BOOTINFO_MAGIC_START) ||
                (mtd_bfsp.magic_end != _SMEM_DUAL_BOOTINFO_MAGIC_END)) {
		printf("\nERR:Primary bootconfig - Invalid Magic Number");
		*dev_num = SECONDARY_BOOTCONFIG;
	} else {
		*dev_num = PRIMARY_BOOTCONFIG;
	}

        bsp_mtd_dev_close(dev_to);

        return REVANCHE_IRET_SUCCESS;
}

/******************************************************************************
 * Function Name         : revanche_ctrl_read_boot_count
 * Description           : This API is used to read primary & secondary bootcount.
 * Input(s)              : uint32_t *primary_boot_cnt,
			   uint32_t *secondary_boot_cnt, revanche_inf_ecode_et *p_ecode
 * Output(s)             :
 * <OPTIONAL Fields>     :
 * Global Variables Referred :
 * Global variables Modified :
 * Exceptions or Operating System Error Handling :
 * Use of Recursion      :
 * Returns               : REVANCHE_IRET_SUCCESS/REVANCHE_IRET_FAILURE
********************************************************************************/

revanche_inf_return_et revanche_ctrl_read_boot_count(uint32_t *primary_boot_cnt, uint32_t *secondary_boot_cnt, revanche_inf_ecode_et *p_ecode)
{
        UINT1 dev_to, dev_num, rc;
        bootFlagInfo mtd_bfrd;

	rc = revanche_get_dev_num(&dev_num);
        if(!rc)
        return 0;

        rc=bsp_mtd_dev_open(dev_num, &dev_to);
        if(!rc)
        return 0;

        if( 0>bsp_mtd_dev_bflag_rw(1,dev_to,&mtd_bfrd) ){
                printf("\nERR: MTD Read");
                *p_ecode = REVANCHE_IECODE_READ_ERR;
                return REVANCHE_IRET_FAILURE;

        }

        if((mtd_bfrd.magic_start != _SMEM_DUAL_BOOTINFO_MAGIC_START) ||
                (mtd_bfrd.magic_end != _SMEM_DUAL_BOOTINFO_MAGIC_END)) {
                printf("\nERR: Invalid Magic Number");
		*p_ecode = REVANCHE_IECODE_MAGIC_ERR;
                return REVANCHE_IRET_FAILURE;
        }


        *primary_boot_cnt = mtd_bfrd.primary_count;
        *secondary_boot_cnt = mtd_bfrd.secondary_count;

        bsp_mtd_dev_close(dev_to);

        return REVANCHE_IRET_SUCCESS;
}

/******************************************************************************
 * Function Name         : revanche_ctrl_read_active_partition
 * Description           : This API is used to read active partition.
 * Input(s)              : uint32_t *active_partition, revanche_inf_ecode_et *p_ecode
 * Output(s)             :
 * <OPTIONAL Fields>     :
 * Global Variables Referred :
 * Global variables Modified :
 * Exceptions or Operating System Error Handling :
 * Use of Recursion      :
 * Returns               : REVANCHE_IRET_SUCCESS/REVANCHE_IRET_FAILURE
********************************************************************************/

revanche_inf_return_et revanche_ctrl_read_active_partition(uint32_t *active_partition, revanche_inf_ecode_et *p_ecode)
{
        UINT1 dev_to, dev_num, rc;
        bootFlagInfo mtd_bfrd;

	rc = revanche_get_dev_num(&dev_num);
        if(!rc)
        return 0;

	rc=bsp_mtd_dev_open(dev_num, &dev_to);
        if(!rc)
        return 0;

        if( 0>bsp_mtd_dev_bflag_rw(1,dev_to,&mtd_bfrd) ){
                printf("\nERR: MTD Read");
                *p_ecode = REVANCHE_IECODE_READ_ERR;
                return REVANCHE_IRET_FAILURE;

        }

        if((mtd_bfrd.magic_start != _SMEM_DUAL_BOOTINFO_MAGIC_START) ||
                (mtd_bfrd.magic_end != _SMEM_DUAL_BOOTINFO_MAGIC_END)) {
                printf("\nERR: Invalid Magic Number");
		*p_ecode = REVANCHE_IECODE_MAGIC_ERR;
                return REVANCHE_IRET_FAILURE;
        }


        *active_partition = mtd_bfrd.per_part_entry[ROOTFS].primaryboot;

        bsp_mtd_dev_close(dev_to);

        return REVANCHE_IRET_SUCCESS;
}



/******************************************************************************
 * Function Name         : revanche_ctrl_write_boot_count
 * Description           : This API is used to write primary & secondary bootcount.
 * Input(s)              : uint32_t boot_cnt, uint32_t primary,  revanche_inf_ecode_et *p_ecode
 * Output(s)             :
 * <OPTIONAL Fields>     :
 * Global Variables Referred :
 * Global variables Modified :
 * Exceptions or Operating System Error Handling :
 * Use of Recursion      :
 * Returns               : REVANCHE_IRET_SUCCESS/REVANCHE_IRET_FAILURE
********************************************************************************/

revanche_inf_return_et revanche_ctrl_write_boot_count(uint32_t boot_cnt, uint32_t primary,  revanche_inf_ecode_et *p_ecode)
{
        UINT1 dev_to, dev_num,rc;
        bootFlagInfo mtd_bfsp;

	rc = revanche_get_dev_num(&dev_num);
        if(!rc)
        return 0;

        struct erase_info_user erase;
        erase.start = 0x0;
        erase.length = 65536;

        rc=bsp_mtd_dev_open(dev_num, &dev_to);
        if(!rc)
        return 0;

        if( 0>bsp_mtd_dev_bflag_rw(1,dev_to,&mtd_bfsp) ){
                printf("\nERR: MTD Read");
                *p_ecode = REVANCHE_IECODE_READ_ERR;
                return REVANCHE_IRET_FAILURE;
        }

        if((mtd_bfsp.magic_start != _SMEM_DUAL_BOOTINFO_MAGIC_START) ||
                (mtd_bfsp.magic_end != _SMEM_DUAL_BOOTINFO_MAGIC_END)) {
		printf("\nERR: Invalid Magic Number");
		*p_ecode = REVANCHE_IECODE_MAGIC_ERR;
		return REVANCHE_IRET_FAILURE;
	}

        if(!primary) {
		mtd_bfsp.primary_count = boot_cnt;
        } else {
		mtd_bfsp.secondary_count = boot_cnt;
        }

	if(bsp_bf_mtd_dev_erase(dev_to,&erase) < 0) {
                printf("\nERR: MTD Erase");
                *p_ecode = REVANCHE_IECODE_READ_ERR;
                return REVANCHE_IRET_FAILURE;
        }

        if( 0>bsp_mtd_dev_bflag_rw(2,dev_to,&mtd_bfsp) ){
                printf("\nERR: MTD Write");
                *p_ecode = REVANCHE_IECODE_WRITE_ERR;
                return REVANCHE_IRET_FAILURE;
        }
        bsp_mtd_dev_close(dev_to);

        return REVANCHE_IRET_SUCCESS;
}

/******************************************************************************
 * Function Name         : revanche_update_boot_count
 * Description           : This API is used to write update bootcount.
 * Input(s)              : revanche_inf_ecode_et *p_ecode
 * Output(s)             :
 * <OPTIONAL Fields>     :
 * Global Variables Referred :
 * Global variables Modified :
 * Exceptions or Operating System Error Handling :
 * Use of Recursion      :
 * Returns               : REVANCHE_IRET_SUCCESS/REVANCHE_IRET_FAILURE
********************************************************************************/

revanche_inf_return_et revanche_update_boot_count(revanche_inf_ecode_et *p_ecode)
{
        UINT1 dev_to, dev_primary, dev_secondary, dev_num,rc;
        bootFlagInfo mtd_common;
	uint32_t primary;

	rc = revanche_get_dev_num(&dev_num);
        if(!rc)
        return 0;

	struct erase_info_user erase;
        erase.start = 0x0;
        erase.length = 65536;

        rc |= bsp_mtd_dev_open(PRIMARY_BOOTCONFIG, &dev_primary);
        rc |= bsp_mtd_dev_open(SECONDARY_BOOTCONFIG, &dev_secondary);

	if(!rc)
        return 0;

        if (dev_num == PRIMARY_BOOTCONFIG){
		dev_to = dev_primary;
	} else {
		dev_to = dev_secondary;
        }

        if( 0>bsp_mtd_dev_bflag_rw(1,dev_to,&mtd_common) ){
                printf("\nERR: MTD Read");
                *p_ecode = REVANCHE_IECODE_READ_ERR;
                return REVANCHE_IRET_FAILURE;
        }

        if((mtd_common.magic_start != _SMEM_DUAL_BOOTINFO_MAGIC_START) ||
                (mtd_common.magic_end != _SMEM_DUAL_BOOTINFO_MAGIC_END)) {
		printf("\nERR: Invalid Magic Number");
		*p_ecode = REVANCHE_IECODE_MAGIC_ERR;
		return REVANCHE_IRET_FAILURE;
	}

	primary = mtd_common.per_part_entry[ROOTFS].primaryboot;

        if(!primary) {
		mtd_common.primary_count = 4;
        } else {
		mtd_common.secondary_count = 4;
        }

        if(bsp_bf_mtd_dev_erase(dev_primary,&erase) < 0) {
                printf("\nERR: MTD Erase");
                *p_ecode = REVANCHE_IECODE_READ_ERR;
                return REVANCHE_IRET_FAILURE;
        }
        if( 0>bsp_mtd_dev_bflag_rw(2,dev_primary,&mtd_common) ){
                printf("\nERR: MTD Write");
                *p_ecode = REVANCHE_IECODE_WRITE_ERR;
                return REVANCHE_IRET_FAILURE;
        }
	if(bsp_bf_mtd_dev_erase(dev_secondary,&erase) < 0) {
                printf("\nERR: MTD Erase");
                *p_ecode = REVANCHE_IECODE_READ_ERR;
                return REVANCHE_IRET_FAILURE;
        }
        if( 0>bsp_mtd_dev_bflag_rw(2,dev_secondary,&mtd_common) ){
                printf("\nERR: MTD Write");
                *p_ecode = REVANCHE_IECODE_WRITE_ERR;
                return REVANCHE_IRET_FAILURE;
        }

        bsp_mtd_dev_close(dev_primary);
        bsp_mtd_dev_close(dev_secondary);

        return REVANCHE_IRET_SUCCESS;
}

/******************************************************************************
 * Function Name         : revanche_read_crashlog
 * Description           : This API is used to read crash dump log.
 * Input(s)              : char *crashbuf(buffer to read crash log
 * Output(s)             :
 * <OPTIONAL Fields>     :
 * Global Variables Referred :
 * Global variables Modified :
 * Exceptions or Operating System Error Handling :
 * Use of Recursion      :
 * Returns               : REVANCHE_IRET_SUCCESS/REVANCHE_IRET_FAILURE
********************************************************************************/
revanche_inf_return_et revanche_read_crashlog(char *crashbuf)
{
    UINT1 dev_to,dev_num,rc;
    char buf[BUF_SIZE];
    int i = 0;

    /* Get the current mtd partition number */
    rc = revanche_get_dev_num(&dev_num);
    if(!rc)
        return 0;
    /* open current mtd partition */
    rc = bsp_mtd_dev_open(dev_num, &dev_to);
    if(!rc)
        return 0;
        
    memset(buf, 0xff, BUF_SIZE);
    /* read crash log using current mtd ptr */
    if( 0 > bsp_mtd_dev_crashread(dev_to,buf,sizeof(buf)) ){
         printf("\nERR: MTD crash Read");
         return REVANCHE_IRET_FAILURE;
    }
    /* Printing read crash log */
    for ( i = 0; i < 1024; i++ ) {
         printf("%c",buf[i]);
    }
    /* Copying read buf to crashbuf */
    memcpy(crashbuf, &buf[0], BUF_SIZE);

    bsp_mtd_dev_close(dev_to);

    return REVANCHE_IRET_SUCCESS;
}

/******************************************************************************
 * Function Name         : revanche_clear_crashlog
 * Description           : This API is used to clear crash log from boot config
 *                         partition
 * Input(s)              : void
 * Output(s)             : crash log will be cleared from boot config parition
 * <OPTIONAL Fields>     :
 * Global Variables Referred :
 * Global variables Modified :
 * Exceptions or Operating System Error Handling :
 * Use of Recursion      :
 * Returns               : REVANCHE_IRET_SUCCESS/REVANCHE_IRET_FAILURE
********************************************************************************/

revanche_inf_return_et revanche_clear_crashlog(void)
{
    UINT1 dev_to,dev_num,rc;
    char buf[BUF_SIZE];
    int i = 0;

    /* Get current mtd partition number */
    rc = revanche_get_dev_num(&dev_num);
    if(!rc)
        return 0;

    /* Open current mtd device */
    rc = bsp_mtd_dev_open(dev_num, &dev_to);
    if(!rc)
        return 0;
        
    struct erase_info_user erase;
    erase.start = CRASH_DUMP_ADDRESS;
    erase.length = ERASE_SIZE;

    /* erase crash log from boot config parition */
	if(bsp_bf_mtd_dev_erase(dev_to, &erase) < 0) {
                printf("\nERR: MTD Erase");
                return REVANCHE_IRET_FAILURE;
    }

    /* close current mtd device */
    bsp_mtd_dev_close(dev_to);

    return REVANCHE_IRET_SUCCESS;
}

