/*****************************************************************************
 *                                                                           *
 *  FILE NAME            : rev_utils_monitor.c                               *
 *  AUTHOR               : Aricent                                           *
 *  DESCRIPTION          : This file contains gpio monitor implementation    *
 *                         This utility will monitor GPIO 26 to trigger      *
 *                         upgrade and GPIO 54 to reset IPQ                  *
 *****************************************************************************/
/*****************************************************************************
 * INCLUDE FILES
 *****************************************************************************/
#include "rev_utils_monitor.h"

/*****************************************************************************
 * MACRO DEFINITONS
 *****************************************************************************/
/*****************************************************************************
 * GLOBAL DECLARATIONS
 *****************************************************************************/
pthread_t pthread_utils_mon;
unsigned int rppslave_pid;
FILE *gpio_fp[NUM_GPIO_PINS] = {NULL, NULL, NULL};
/* GPIO_26 - index 0 - upgrade GPIO
   GPIO_31 - index 1 - Mac Address identification GPIO
   GPIO_54 - index 2 - IPQ Reset GPIO*/
enum {
    GPIO_IDX_26,
    GPIO_IDX_31,
    GPIO_IDX_54
};
int gpio_pins[NUM_GPIO_PINS] = {GPIO_26, GPIO_31, GPIO_54};
char gpio_sys_file[NUM_GPIO_PINS][BUFFER_SIZE] = {GPIO_26_SYS_INTF,
                                                  GPIO_31_SYS_INTF,
                                                  GPIO_54_SYS_INTF};
char ipaddress[IP_ADDRESS_SIZE];
/*****************************************************************************
 * FUNCTION DEFINITIONS
 *****************************************************************************/
/*****************************************************************************
 *  Function Name          : get_ip_address
 *  Description            : This function is used to get the ipaddress based
 *                           on gpio 31
 *  Input(s)               : NIL
 *  Output(s)              : ipadress of the tftp server
 *  Returns                : EXIT_SUCCESS/EXIT_FAILURE
 * ***************************************************************************/
int get_ip_address()
{
    int gpio_read_value = 0;

    /* Read sys interface file for GPIO pin 31 */
    if(fscanf(gpio_fp[GPIO_IDX_31], "%d", &gpio_read_value) < 1) {
        REV_UTILS_MON_PRINT(LOG_ERR, "%s: %d GPIO 31 sysfs file read failed\n",
                           __FUNCTION__, __LINE__);
        return EXIT_FAILURE;
    }

    REV_UTILS_MON_PRINT(LOG_INFO, "\n IPQ is in slot %d\n", gpio_read_value);

    /* Get the TFTP server ipaddress based on slot */
    if(gpio_read_value) {
        snprintf(ipaddress, IP_ADDRESS_SIZE, "%s", TFTP_SERVER_IP_SLOT1);
    } else {
        snprintf(ipaddress, IP_ADDRESS_SIZE, "%s", TFTP_SERVER_IP_SLOT0);
    }
    REV_UTILS_MON_PRINT(LOG_DEBUG, "TFTP server ip: %s\n", ipaddress);

    return EXIT_SUCCESS;
}
/*****************************************************************************
 *  Function Name          : rev_utils_mon_handler
 *  Description            : This handler is used to access gpio pin 26 and 
 *                           gpio 54 and perform reset or upgrade based on 
 *                           gpio pin values.
 *  Input(s)               : NIL
 *  Output(s)              : IPQ reset or upgrade will be performed.
 *  Returns                : void
 * ***************************************************************************/
void *rev_utils_mon_handler()
{
    int gpio_read_value = 0;
    char temp_buffer[BUFFER_SIZE];

    while(1) {
        fseek(gpio_fp[GPIO_IDX_54], 0, SEEK_SET);
        /* Read GPIO 54 value to check reset value is set or not */
        if(fscanf(gpio_fp[GPIO_IDX_54], "%d", &gpio_read_value) < 1) {
            REV_UTILS_MON_PRINT(LOG_ERR, "%s: %d GPIO 54 sysfs file read"
                              " failed\n", __FUNCTION__, __LINE__);
        } else {
            /* if reset value is set, issue reboot() */
            if(gpio_read_value) {
                REV_UTILS_MON_PRINT(LOG_DEBUG, "Reset value is set as %d\n",
                                  gpio_read_value);
                /* send the signal to RPP slave */
                if(kill(rppslave_pid, SIGUSR1) != EXIT_SUCCESS) {
                    REV_UTILS_MON_PRINT(LOG_ERR, "%s:%d Sending signal to"
                            " rppslave failed\n", __FUNCTION__, __LINE__);
                }
                REV_UTILS_MON_PRINT(LOG_INFO, "\n Sent signal to rppslave.");
                /* This command will call reboot() in kernel,which will toggle"
                   " LNX_IPQ_RST GPIO 64 pin */
                if(system("reboot") != EXIT_SUCCESS) {
                    REV_UTILS_MON_PRINT(LOG_ERR, "%s:%d IPQ Failed to "
                                     "reboot\n", __FUNCTION__, __LINE__);
                }
            }
        }
        gpio_read_value = 0;
        fseek(gpio_fp[GPIO_IDX_26], 0, SEEK_SET);
        /* Read GPIO 26 value to check upgrade mode is set or not */
        if(fscanf(gpio_fp[GPIO_IDX_26], "%d", &gpio_read_value) < 1) {
            REV_UTILS_MON_PRINT(LOG_ERR, "%s: %d GPIO 26 sysfs file read"
                               " failed\n", __FUNCTION__, __LINE__);
            continue;
        }
        /* if upgrade mode is set, upgrade the image using sysupgrade */
        if(gpio_read_value) {
            REV_UTILS_MON_PRINT(LOG_INFO, "Upgrade mode is set as %d\n",
                               gpio_read_value);


            memset(temp_buffer, '\0', BUFFER_SIZE);
            snprintf(temp_buffer, BUFFER_SIZE, "tftp -l %s -g -r %s %s",
                     UPGRADE_FILE_PATH, UPGRADE_FILE, ipaddress);

            REV_UTILS_MON_PRINT(LOG_INFO, "Getting Image %s from tftp server"
                         " %s...\n", UPGRADE_FILE_PATH, ipaddress);

            if(system(temp_buffer) != EXIT_SUCCESS) {
                REV_UTILS_MON_PRINT(LOG_ERR, "TFTP Failed.\n");
                continue;
            }
            REV_UTILS_MON_PRINT(LOG_INFO, "Image downloaded successfully...\n");
            /* send the signal to RPP slave */
            if(kill(rppslave_pid, SIGUSR1) != EXIT_SUCCESS) {
                REV_UTILS_MON_PRINT(LOG_ERR, "%s:%d Sending signal to"
                         " rppslave failed\n", __FUNCTION__, __LINE__);
                continue;
            }
            REV_UTILS_MON_PRINT(LOG_INFO, "\n Sent signal to rppslave.");

            /* upgrade the image using sysupgrade tool */
            memset(temp_buffer, '\0', BUFFER_SIZE);
            snprintf(temp_buffer, BUFFER_SIZE, "sysupgrade -v %s > %s 2>&1",
                     UPGRADE_FILE_PATH, UPGRADE_LOG_FILE);
            if(system(temp_buffer) != EXIT_SUCCESS) {
                REV_UTILS_MON_PRINT(LOG_ERR, "%s:%d Upgrade failed. Check %s "
                                   "file for detailed logs. ", __FUNCTION__,
                                   __LINE__, UPGRADE_LOG_FILE);
            }
        }
        sleep(1);
    }
    return NULL; 
}
/*****************************************************************************
 *  Function Name          : initialize_rev_utils_monitor
 *  Description            : This function is used to get tftp server ip and
 *                           rppslave pid and create pthread to monitor.
 *  Input(s)               : void
 *  Output(s)              : Thread will be created.
 *  Returns                : EXIT_SUCCESS/EXIT_FAILURE
 * ***************************************************************************/
int initialize_rev_utils_monitor(void)
{
    FILE *fp = NULL;
    struct stat s = {0};
    char temp_buffer[BUFFER_SIZE];
    int ret_val = 0;
    int i = 0;

    /* Open log file for capturing debug/error messages */
    openlog ("rev_utils_monitor", LOG_PID, LOG_DAEMON);

    for ( i = 0; i < NUM_GPIO_PINS; i++) {
        /* Open sys interface file for GPIO PIN 31 to read the value */
        gpio_fp[i] = fopen(gpio_sys_file[i], "r");
        if(gpio_fp[i] == NULL) {
            REV_UTILS_MON_PRINT(LOG_ERR, "%s: %d GPIO 31 sysfs file open failed\n",
                                  __FUNCTION__, __LINE__);
                ret_val++;
        }
    }
    if(ret_val) {
        return EXIT_FAILURE;
    }
    
    if(get_ip_address() == EXIT_FAILURE) {
         REV_UTILS_MON_PRINT(LOG_ERR, "%s: %d Getting IP address"
                            " failed \n", __FUNCTION__, __LINE__);
         return EXIT_FAILURE;
    }
    /* Get rppslave process id to send signal if reset/upgrade mode is set */
    snprintf(temp_buffer, BUFFER_SIZE, "pgrep -f %s", RPPSLAVE_PROCESS);
    fp = popen(temp_buffer, "r");
    if(fp == NULL) {
        REV_UTILS_MON_PRINT(LOG_ERR, "%s: %d Getting rppslave pid failed\n",
                           __FUNCTION__, __LINE__);
    } else {
        if(fscanf(fp, "%u", &rppslave_pid) < 1) {
            REV_UTILS_MON_PRINT(LOG_ERR, "%s: %d reading rppslave pid failed\n",
                                __FUNCTION__, __LINE__);
        }
        REV_UTILS_MON_PRINT(LOG_DEBUG," RPP SLAVE pid %u\n", rppslave_pid);
        pclose(fp);
    }
    /* create a thread which monitor GPIO pins */
    if(pthread_create(&pthread_utils_mon, NULL, rev_utils_mon_handler, NULL)) {
        REV_UTILS_MON_PRINT(LOG_ERR, "%s: %d Error creating thread\n",
                           __FUNCTION__, __LINE__);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/*****************************************************************************
 *  Function Name          : main
 *  Description            : main function for revanche monitor utility.
 *  Input(s)               : -
 *  Output(s)              : ipq will be reset or ipq imagewill be upgraded.
 *  Returns                : EXIT_SUCCESS/EXI_FAILURE
 * ***************************************************************************/
int main(void)
{
    int ret_val = EXIT_SUCCESS;
    struct stat s = {0};
    char temp_buffer[BUFFER_SIZE];
    int i = 0;

    /* initialize gpio monitor utility */
    ret_val = initialize_rev_utils_monitor();

    if (ret_val != EXIT_SUCCESS) {
       REV_UTILS_MON_PRINT(LOG_ERR, "%s: %d - Monitor Utility"
                         " initialization Failed ret_val = %d\n", __FUNCTION__,
                          __LINE__, ret_val);
    } else {
        /* wait for the second thread to finish */
        if(pthread_join(pthread_utils_mon, NULL)) {
            REV_UTILS_MON_PRINT(LOG_ERR, "%s: %d Error joining thread\n",
                               __FUNCTION__, __LINE__);
            ret_val = EXIT_FAILURE;
        }
    }

    for ( i = 0; i < NUM_GPIO_PINS; i++ ) {
        fclose(gpio_fp[i]);
    }
    closelog();
    exit(ret_val);
}
