#include "rpp_header.h"
#include "rpp_core.h"

int32_t rpp_validate_phyhandle(int32_t phyhandle)
{
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_validate_phyhandle_fun()_start");
#ifdef THREE_RADIO
    if ((phyhandle != 0xff) && (phyhandle == PHY_HANDLE_2G || phyhandle == PHY_HANDLE_5G || phyhandle == PHY_HANDLE_5G2))
#else 
    if ((phyhandle != 0xff) && (phyhandle == PHY_HANDLE_2G || phyhandle == PHY_HANDLE_5G ))
#endif
    {
        return 0;
    } else {
        return RPP_APP_DEFNUM_ONE;
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_validate_phyhandle_fun()_exit");
}

int32_t rpp_getPhy_errorCheck(int32_t errCode, int32_t value, char *cmdOutput, int32_t option)
{
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_getPhy_errorCheck_fun()_start");
    if (option == RPP_APP_DEFNUM_ONE) {
        return RPP_APP_DEFNUM_ONE;
    } else if (option == RPP_APP_DEFNUM_TWO) {
        return 0;
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_getPhy_errorCheck_fun()_exit");

    return 0;
}

int32_t rpp_setPhy_errorCheck(int32_t errCode, int32_t value, char *cmdOutput, int32_t option)
{
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_setPhy_errorCheck_fun()_start");
    if (option == RPP_APP_DEFNUM_ONE) {
        return RPP_APP_DEFNUM_ONE;
    } else if (option == RPP_APP_DEFNUM_TWO) {
        return 0;
    }
    SYSLOG_PRINT(LOG_DEBUG,"DEBUG_MSG------->rpp_setPhy_errorCheck_fun()_exit");

    return 0;
}
