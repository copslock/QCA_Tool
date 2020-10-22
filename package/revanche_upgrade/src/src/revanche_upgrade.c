/*****************************************************************************
 *                                                                           *
 *  FILE NAME            : revanche_upgrade.c                                *
 *  AUTHOR               : Aricent                                           *
 *  DESCRIPTION          : This file contains implementaion of revanche      *
 *                         upgrade                                           *
 *****************************************************************************/
/*****************************************************************************
 * INCLUDE FILES
 *****************************************************************************/
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "fpga_drvlib.h"
#include "revanche_upgrade.h"

/*****************************************************************************
 * MACRO DEFINITONS
 *****************************************************************************/
/*****************************************************************************
 * GLOBAL DECLARATIONS
 *****************************************************************************/
/*****************************************************************************
 * FUNCTION DEFINITIONS
 *****************************************************************************/
/* 
 * get IPQ_SW_VERSION prefix string len 
 * thus 003.06 and 003.6 can both be supported
 * 
*/
#define MAGIC_STRING "IPQ_SW_VERSION"
#define MAGIC_SEC_LEN 255

static int get_magic_len()
{
    char magic[MAGIC_SEC_LEN + 1];
    size_t nbytes = 0;
    char *p = NULL;
    int major, minor;
    int cnt = 0;

    FILE *fp = fopen(UPGRADE_FILE_PATH, "r");
    if(!fp)
        return -1;

    nbytes = fread(magic, sizeof(char), MAGIC_SEC_LEN, fp);
    if(ferror(fp))
        return -1;
    fclose(fp);
    magic[nbytes] = '\0';

    p = strstr(magic, MAGIC_STRING);
    if (!p)
        return -1;
    cnt =sscanf(p, MAGIC_STRING "%d.%d", &major, &minor);
    if(cnt !=2)
        return -1;
    p = strstr(p, ".");
    p++;

    while(*p) {
        if (!isdigit(*p) && *p != 0x0a)
            break;
        ++p;
    }
    if(!*p)
        return -1;
    return (p - magic);
}


static int get_current_sw_version_info(uint32_t *major, uint32_t *minor)
{
    char *p = NULL;
    char version_str[128] = {'\0'};

    FILE *fp = fopen(REVANCHE_SW_VER_FILE, "r");
    if(!fp) {
        REVANCHE_UPGRADE_PRINT(LOG_ERR, "%s:%d failed to open version file (%s).\n"
                , __FUNCTION__, __LINE__, REVANCHE_SW_VER_FILE);
        return -1;
    }

    if(!fgets(version_str, sizeof(version_str), fp)) {
        REVANCHE_UPGRADE_PRINT(LOG_ERR, "%s:%d failed to read version file (%s).\n"
                , __FUNCTION__, __LINE__, REVANCHE_SW_VER_FILE);
        return -1;
    }
    fclose(fp);

    p = strstr(version_str, MAGIC_STRING);
    if (!p) {
        REVANCHE_UPGRADE_PRINT(LOG_ERR, "%s:%d version file has no magic string.\n"
                , __FUNCTION__, __LINE__);
        return -1;
    }
    if(sscanf(p, MAGIC_STRING "%d.%d", major, minor) != 2) {
        REVANCHE_UPGRADE_PRINT(LOG_ERR, "%s:%d magic string has invalid version info.\n"
                , __FUNCTION__, __LINE__);
        return -1;
    }
    return 0;
}
static void get_upgrade_sw_info(uint32_t version, uint32_t *major, uint32_t *minor)
{
    /* get version composition method
     *
     *    REG_FW_VER
     * 
     *    |[31,28]    |[27,20]  |[19,0]   |
     *    |composition|reserved |revision |
     *   
     *   
     *    composition:
     *     0 - revison_composition 0 (major 12bits, minor 8bits)
     *     1 - revison_composition 1 (major 4bits, minor 16bits)
     *    revision: 
     *     consists major bits and minor bits and compostion deponds on 
     *     composition method
     *
     * */

    int composition_method = 0;
    composition_method = (version & 0xF0000000) >> 28;
    switch(composition_method) {
        case 0:
        default:
            *minor =  (version & 0xFF);
            *major =  ((version & 0xFFF00) >> 8);
            break;
        case 1:
            *minor =  (version & 0xFFFF);
            *major =  ((version & 0xF0000) >> 16);
            break;
    }
}
/*****************************************************************************
 *  Function Name          : is_upgrade_needed
 *  Description            : This function is used to check upgrade is needed
 *                           or not.
 *  Input(s)               : NIL
 *  Output(s)              : -
 *  Returns                : EXIT_SUCCESS/EXIT_FAILURE
 * ***************************************************************************/
bool is_upgrade_needed(void)
{
    uint32_t upgrade_sw_version = 0;
    uint32_t upgrade_sw_major, upgrade_sw_minor = 0;
    uint32_t current_sw_major, current_sw_minor = 0;

    /* read revanche ipq sw version from fpga version register */
    if (get_ipq_sw_version(&upgrade_sw_version) != EXIT_SUCCESS) {
        REVANCHE_UPGRADE_PRINT(LOG_ERR, "version read is failed."
                              "upgrade will not proceed\n");
        return false;
    }

    if (upgrade_sw_version == DEFAULT_VERSION) {
        REVANCHE_UPGRADE_PRINT(LOG_ERR, "default version %x is read."
                          "upgrade will not proceed\n", DEFAULT_VERSION);
        return false;
    }

    /* get new sw version info from FPGA register written by X86 */
    get_upgrade_sw_info(upgrade_sw_version, &upgrade_sw_major, &upgrade_sw_minor);
    /* get current sw version info from /etc/ipq_image_version */
    get_current_sw_version_info(&current_sw_major, &current_sw_minor);

    if(upgrade_sw_major == current_sw_major && 
       upgrade_sw_minor == current_sw_minor) {
        REVANCHE_UPGRADE_PRINT(LOG_ERR, "same version %d.%d skip upgrade.\n",
                upgrade_sw_major, upgrade_sw_minor);
        return false;
    }

    REVANCHE_UPGRADE_PRINT(LOG_ERR, "sw version %d.%d ===> %d.%d\n",
            current_sw_major, current_sw_minor,
            upgrade_sw_major, upgrade_sw_minor);

    return true;
}

/*****************************************************************************
 *  Function Name          : revanche_upgrade
 *  Description            : This function is used to upgrade revanche.
 *  Input(s)               : NIL
 *  Output(s)              : Revanche upgrade will be performed.
 *  Returns                : EXIT_SUCCESS/EXIT_FAILURE
 * ***************************************************************************/
int revanche_upgrade(void)
{
    char temp_buffer[BUFFER_SIZE];
    int magic_len = -1;

    if(!is_upgrade_needed())
        return EXIT_SUCCESS;

    memset(temp_buffer, '\0', BUFFER_SIZE);
    snprintf(temp_buffer, BUFFER_SIZE, "tftp -l %s -g -r %s %s",
            UPGRADE_FILE_PATH, UPGRADE_FILE, TFTP_SERVER_IP);

    REVANCHE_UPGRADE_PRINT(LOG_INFO, "Getting Image %s from tftp server"
            " %s...\n", UPGRADE_FILE_PATH, TFTP_SERVER_IP);

    if(system(temp_buffer) != EXIT_SUCCESS) {
        REVANCHE_UPGRADE_PRINT(LOG_ERR, "TFTP Failed.\n");
        return -1;
    }
    REVANCHE_UPGRADE_PRINT(LOG_INFO, "Image downloaded successfully...\n");

    if(set_ipq_appln_bootup_status(0) != EXIT_SUCCESS) {
        REVANCHE_UPGRADE_PRINT(LOG_ERR, "\n Writing ipq appln boot status failed ");
        return -2;
    }

    magic_len = get_magic_len();
    if(magic_len < 0) {
        REVANCHE_UPGRADE_PRINT(LOG_ERR, "\n invalid magic string length.");
        return -3;
    }

    /* skip version header from IPQ image */
    memset(temp_buffer, '\0', BUFFER_SIZE);
    snprintf(temp_buffer, BUFFER_SIZE, "dd if=%s of=%s skip=1 bs=%d > "
            "%s 2>&1", UPGRADE_FILE_PATH,UPGRADE_FILE_PATH1,
            magic_len, UPGRADE_LOG_FILE);
    if(system(temp_buffer) != EXIT_SUCCESS) {
        REVANCHE_UPGRADE_PRINT(LOG_ERR, "%s:%d Upgrade failed. Check %s "
                "file for detailed logs. ", __FUNCTION__,
                __LINE__, UPGRADE_LOG_FILE);
        return -2;
    }
    /* upgrade the image using sysupgrade tool */
    memset(temp_buffer, '\0', BUFFER_SIZE);
    snprintf(temp_buffer, BUFFER_SIZE, "sysupgrade -v %s >> %s 2>&1",
            UPGRADE_FILE_PATH1, UPGRADE_LOG_FILE);
    if(system(temp_buffer) != EXIT_SUCCESS) {
        REVANCHE_UPGRADE_PRINT(LOG_ERR, "%s:%d Upgrade failed. Check %s "
                "file for detailed logs. ", __FUNCTION__,
                __LINE__, UPGRADE_LOG_FILE);
        return -2;
    }
    return EXIT_SUCCESS;
}
/*****************************************************************************
 *  Function Name          : main
 *  Description            : main function for revanche upgrade functionality.
 *  Input(s)               : -
 *  Output(s)              : image will be upgraded.
 *  Returns                : EXIT_SUCCESS/EXI_FAILURE
 * ***************************************************************************/
int main(void)
{
    int ret_val = EXIT_SUCCESS;
    uint32_t upgrade_status = 0;

    ret_val = revanche_upgrade();
    if (ret_val == EXIT_SUCCESS) {
        upgrade_status = UPGRADE_SUCCESS;
    } else {
        if ( ret_val == -1) {
            upgrade_status = UPGRADE_TFTP_FAILED;
        } else {
            upgrade_status = UPGRADE_IMG_INVALID;
        }
    }
    /* write  upgrade successful as 0 in IPQ_UPGRADE_STATUS_REG */
    ret_val = set_ipq_upgrade_status(upgrade_status);
    if (ret_val != EXIT_SUCCESS) {
        REVANCHE_UPGRADE_PRINT(LOG_ERR, "%s:%d Writing upgrade status"
                           "failed", __FUNCTION__, __LINE__);
    }
    exit(ret_val);
}
