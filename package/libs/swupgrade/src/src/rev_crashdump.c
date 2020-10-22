/*****************************************************************************
 *                                                                           *
 *  FILE NAME            : rev_crashdump.c                                   *
 *  AUTHOR               : Aricent                                           *
 *  DESCRIPTION          : This file contains userspace crashdump            *
                           functionality. This utility is used to read crash *
 *                         log and send it to host and clear crash log.      *
 *****************************************************************************/
/*****************************************************************************
 * INCLUDE FILES
 *****************************************************************************/
#include "../driver_api/sw_upgrade.h"

/*****************************************************************************
 * MACRO DEFINITIONS
 *****************************************************************************/
#define CRASHDUMP_LOG     "/log/ipq_log/RevancheLinuxCrashDump.log"
#define CRASHDUMP_LOG_FILE "RevancheLinuxCrashDump.log"
#define CRASHDUMP_LOG_DIR "/log/ipq_log/"
#define STR_SIZE          200
#define TFTP_SERVER_IP    "192.168.1.1"

/*****************************************************************************
 * FUNCTION DEFINITIONS
 *****************************************************************************/
/*****************************************************************************
 *  Function Name          : main
 *  Description            : This function is used to read crash log from boot
 *                           config parition and send it to host and clear
 *                           crash log after successful completion of tftp
 *                           transfer.
 *                           NIL
 *  Input(s)               : NIL
 *  Output(s)              : crash log will be sent to host.
 *  Returns                : void
 * ***************************************************************************/

int main (void)
{
    char crashbuf[BUF_SIZE];
    FILE *fp = NULL;
    char buf[STR_SIZE];

    memset(crashbuf, 0xff, BUF_SIZE);

    if(revanche_read_crashlog(&crashbuf[0]) != REVANCHE_IRET_SUCCESS) {
        printf("\n crash dump read failed...\n");
        exit(EXIT_FAILURE);
    }

    printf("\n crash dump read... OK. \n");

    if(!(strncmp(&crashbuf[0], "PC", 2))) {
        printf("\n crashdump log found\n");

        /* writing build info in crash log file */
        memset(buf, 0xff, STR_SIZE);
        snprintf(buf, STR_SIZE, "uname -a > %s", CRASHDUMP_LOG);
        system(buf);

        /* wring date and time info when crash log read in crash log file */
        memset(buf, 0xff, STR_SIZE);
        snprintf(buf, STR_SIZE, "date >> %s", CRASHDUMP_LOG);
        system(buf);

        fp = fopen(CRASHDUMP_LOG, "a");
        if (fp == NULL) {
            printf("\n crashdump log open is failed\n");
            exit(EXIT_FAILURE);
        }

        for ( int i = 0; i < BUF_SIZE; i++ ) {
            /* put crash dump in crash log file */
            fputc(crashbuf[i], fp);
        }

        fclose(fp);

        printf("\n Sending crash log to host...\n");
        memset(buf, 0xff, STR_SIZE);
        /* Sending crash log to host machine via tftp server */
        snprintf(buf, STR_SIZE, "cd %s && tftp -l %s -p %s", CRASHDUMP_LOG_DIR, CRASHDUMP_LOG_FILE, TFTP_SERVER_IP);
        if(system(buf) != 0) {
            printf("\n Sending crash log to host failed...\n");
            system("cd -");
            exit(EXIT_FAILURE);
        }

        system("cd -");
        printf("\n Sending crash log to host success...\n");
        /* clear crash log after sending crash log successful */
        revanche_clear_crashlog();
    }
    return 0;
}

