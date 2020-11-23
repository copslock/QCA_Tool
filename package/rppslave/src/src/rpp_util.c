#include "rpp_core.h"
#include "rpp_wpactrl_helper.h"

#define CERT_DIR_NAME "cert_wifi"

extern char* sourceIp;
extern staAssocInfo staAssocHdl[RPP_NUM_OF_RADIO];

int util_install_certificate(const uint32_t phyhandle, const char* sta, const char* key_filename,
        const char* cert_filename)
{
    char    dirName[20] = "\0";
    char    certFile[50] = "\0";
    struct stat c_st;

    //  key_filename = "ca_cert"
    //  cert_filename = "ca.pem"
    /* skip empty filename
     * basename return "." for empty filepath */
    if(!strlen(cert_filename) || !strcmp(cert_filename, "."))
        return 0;

    //  dirName = "/tmp/cert_wifi0"
    sprintf(dirName, "/tmp/%s%d", CERT_DIR_NAME, phyhandle);
    if (stat(dirName, &c_st))
    {
        SYSLOG_PRINT(LOG_DEBUG, "CERT ------ create directory %s",dirName);
        system_cmd_set_f("mkdir %s" , dirName);
    }
    else if (!S_ISDIR(c_st.st_mode)) {
        SYSLOG_PRINT(LOG_ERR, "CERT ------ %s is not directory",dirName);
        return -1;
    }

    // certFile = "/tmp/cert_wifi0/ca.pem"
    sprintf(certFile, "%s/%s", dirName, cert_filename);
    if (stat(certFile, &c_st))
    {
        SYSLOG_PRINT(LOG_DEBUG, "CERT ------ file does not exist %s",certFile);
        system_cmd_set_f("tftp -g -r %s %s", cert_filename, sourceIp);
        system_cmd_set_f("mv %s %s/", cert_filename,dirName);
    }

    // wpa_cli -i staX0 set_network 0 ca_cert "/tmp/cert_wifi0/ca.pem"
    config_network_intf(phyhandle, "IFNAME=%s SET_NETWORK 0 %s \"%s\"", sta, key_filename, certFile);

    return 0;
}

int util_uninstall_certificate(const uint32_t phyhandle)
{
    struct stat c_st;
    char    dirName[20] = "\0";

    if (PROXY_STA[phyhandle]) {
        if ( staAssocHdl[phyhandle].associated_stations_per_radio != 0 ){
            SYSLOG_PRINT(LOG_DEBUG, "CERT ------ Clients in radio%d left associated = %d",phyhandle,
                staAssocHdl[phyhandle].associated_stations_per_radio);
            return 0;
        }
    }

    sprintf(dirName, "/tmp/%s%d", CERT_DIR_NAME, phyhandle);
    if (stat(dirName, &c_st))
    {
        SYSLOG_PRINT(LOG_DEBUG, "CERT ------ %s does not exist",dirName);
        return 0;
    }

    if (!S_ISDIR(c_st.st_mode)) {
        SYSLOG_PRINT(LOG_ERR, "CERT ------ %s is not directory",dirName);
        return -1;
    }

    system_cmd_set_f("rm -rf /tmp/%s%d", CERT_DIR_NAME, phyhandle);
    return 0;
}

int util_install_certificate2(const uint32_t phyhandle, uint32_t stanum, const char* keyname,
        const char* filepath)
{ 
    char intfName[32] = {'\0'};
    // skip configuring empty certificate
    if(!strlen(filepath))
        return 0;
    snprintf(intfName, sizeof(intfName)-1, "sta%u", stanum);
    return util_install_certificate(phyhandle,intfName, keyname, filepath);
}

int util_is_empty_array(uint8_t* array, size_t size)
{
    size_t idx = 0;
    for(; idx < size; ++idx) {
        if(array[idx])
            return 0;
    }
    return 1;
}

char* util_mac_addr_to_str(uint8_t* addr)
{
    static char str[18];

    if(addr == NULL)
        return "";

    snprintf(str, sizeof(str), MAC_STRING_FORMAT,
                      addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

    return str;
}

uint8_t util_str_to_mac_addr(const char* addr, uint8_t* values)
{
    if (sscanf(addr, MAC_STRING_FORMAT, &values[0], &values[1], &values[2],&values[3], &values[4], &values[5]))
        return 1;
    else
        return 0;
}

/******************************************************************************
 * Function Name    : util_is_intf_online
 * Description      : Return 1 when interface is online
 ******************************************************************************/
uint8_t util_is_intf_online(const char* intfName)
{
#define INF_UP_STR "unknown"
    char buf[32];
    system_cmd_get_f(buf, sizeof(buf), "cat /sys/class/net/%s/operstate", intfName);
    /* When interface is up, in /sys/class/net/<intfName>/operstate will show 'unknown' */
    if (strlen(buf) && (strncmp(buf, INF_UP_STR, strlen(INF_UP_STR)) == 0)) {
        return 1;
    }
    return 0;
}
