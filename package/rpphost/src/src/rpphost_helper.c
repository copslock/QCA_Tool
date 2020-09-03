#include "rpphost_helper.h"

#define MAX_READ_LINE 64
#define MAX_LINE_LEN 128

// Get array length
#define GET_ARRAY_LEN(arr)               (sizeof(arr)/sizeof(arr[0]))
// Ignore newline
#define IGNORE_NEWLINE(line)            if (line[strlen(line)-1] == '\n') line[strlen(line)-1] = 0;

#define MAP_KEY_TO_VAL(map, str, def)   find_val_in_map(map, GET_ARRAY_LEN(map), str, def)
#define MAP_VAL_TO_KEY(map, val)        find_key_in_map(map, GET_ARRAY_LEN(map), val)

// Read key string value to buffer
#define READ_KEY_STR_VALUE(line, key, buff, found) \
{ \
    found = 0; \
    const char *sPtr = p_keyword(line, key); \
    if (sPtr) { \
        memset(buff, 0, sizeof(buff)); \
        memcpy((char *)buff, sPtr, strlen(sPtr)); \
        found = 1; \
    } \
}

// Read string from line started with key to buffer
#define READ_LINE_STR_VALUE(lines, lineCnt, key, buff, found) \
{ \
    int line_num = get_linenum_start_with(lines, lineCnt, key); \
    if (line_num < 0) { \
        found = 0; \
    } else { \
        READ_KEY_STR_VALUE(lines[line_num], key, buff, found); \
    } \
}

// Read key number value to buffer
#define READ_KEY_NUM_VALUE(line, key, buff, found) \
{ \
    found = 0; \
    const char *sPtr = p_keyword(line, key); \
    if (sPtr) { \
        buff = str_to_int(sPtr); \
        found = 1; \
    } \
}

// Read number from line started with key to buffer
#define READ_LINE_NUM_VALUE(lines, lineCnt, key, buff, found) \
{ \
    int line_num = get_linenum_start_with(lines, lineCnt, key); \
    if (line_num < 0) { \
        found = 0; \
    } else { \
        READ_KEY_NUM_VALUE(lines[line_num], key, buff, found) \
    } \
}

struct KeyValMap encrypTypeMap[] = {
    {"OPEN", OPEN}, 
    {"PERSONAL", PERSONAL}, 
    {"ENTERPRISE", ENTERPRISE}, 
    {"WEP", WEP}, 
    {"ENHANCED_OPEN", ENHANCED_OPEN}, 
    {"WPA3_PERSONAL", WPA3_PERSONAL}, 
    {"WPA2_WPA3_PERSONAL", WPA2_WPA3_PERSONAL}, 
    {"WPA3_ENTERPRISE", WPA3_ENTERPRISE} 
};

struct KeyValMap encEAPTypeMap[] = {
    {"EAP_TLS", EAP_TLS}, 
    {"EAP_TTLS", EAP_TTLS}, 
    {"EAP_PEAP", EAP_PEAP}, 
    {"EAP_AKA", EAP_AKA}
};

/******************************************************************************
 * Function Name    : usage
 * Description      : Rpp host usage
 ******************************************************************************/
void usage(void)
{
	printf("rpphost "
	       "  -h = help (show this usage text)\n"
		   "  probe = probe request \n"
		   "  getphy = get phy request \n"
		   "  -r <PhyIndex (0:5G|1:6G|2:2G)> <options> \n"
		   "    Example: \n"
		   "      -r 0 setphy /tmp/phy.cfg = set phy handle with configurations from file \n"
		   "      -r 0 create /tmp/sta.cfg = create a station with configurations from file \n"
	       "      -r 0 associate sta0 = associate the station: sta0 \n"
           "      -r 0 associate sta0-sta2,sta7,sta10-sta11 = associate multiple stations: sta0,sta1,sta2,sta7,sta10,sta11 \n"
	       "      -r 0 disassociate sta0 = disassociate the station: sta0 \n"
           "      -r 0 disassociate sta0-sta2,sta7,sta10-sta11 = associate multiple stations: sta0,sta1,sta2,sta7,sta10,sta11 \n"
		   "      -r 0 remove sta0 = remove a station \n"
           "      -r 0 remove sta0-sta2,sta7,sta10-sta11 = remove multiple station: sta0,sta1,sta2,sta7,sta10,sta11 \n"
		   "  -m <SocketMsgOption> = Run rpphost in monitor mode (Keep listening socket from rppslave and print out message) \n"
		   "    SocketMsgOption: to enable monitor on each port (No specify enable all)\n"
		   "      bit#0: Sync msg port \n"
		   "      bit#1: Aync msg port \n"
		   "      bit#2: Stats msg port \n"
		   );
}

/******************************************************************************
 * Function Name    : parse_intf_index
 * Description      : Parse interface index to array
                      Example: prefix: sta string: sta0-sta3,sta7,sta15-sta17 got index: 0,1,2,3,7,15,16,17
 ******************************************************************************/
int *parse_intf_index(const char *str, const char *prefix, int *intfCnt)
{
    int *intfs = NULL;
    int sIdx, eIdx, staIndex;
    char *token1, *token2;
    char *savePtr1 = NULL, *savePtr2 = NULL;
    if (str == NULL || prefix == NULL || intfCnt == NULL) {
        return NULL;
    }

#define MIN_VAL(x, y) ((x) < (y) ? (x) : (y))
#define DELIM_1 ","
#define DELIM_2 "-"

    *intfCnt = 0;
    if ((strstr(str, ",") == NULL) && (strstr(str, "-") == NULL)) {
        staIndex = get_inf_index(str, prefix, -1); // Get station index
        if (staIndex >= 0) {
            intfs = (int*)malloc(sizeof(int)*1);
            intfs[(*intfCnt)++] = staIndex;
        }
        return intfs;
    }

    // Copy string for parsing
    char tmpStr[strlen(str)];
    strcpy(tmpStr, str);
    
    int8_t tmpIntf[MAX_INTF_NUM] = {0}; // Parsed interface index
    token1 = strtok_r(tmpStr, DELIM_1, &savePtr1);
    while (token1 != NULL)
    {
        sIdx = eIdx = -1; // Reset index
        token2 = strtok_r(token1, DELIM_2, &savePtr2);
        while (token2 != NULL)
        {
            staIndex = get_inf_index(token2, prefix, -1); // Get station index
            if (staIndex < 0) {
                rpphost_debug_print(DEBUG_DATA, "Parse interface index sub token: %s failed", token2);
                goto nextloop;
            }
            if (sIdx < 0) { // Keep start index
                sIdx = staIndex;
            } else { // Keep end index
                eIdx = staIndex;
            }
            token2 = strtok_r(NULL, DELIM_2, &savePtr2);
        }
        if (sIdx > MAX_INTF_IDX) {
            rpphost_debug_print(DEBUG_DATA, "Interface index: %d greater than limit: %d", sIdx, MAX_INTF_IDX);
            goto nextloop;
        }
        if (eIdx < 0) eIdx = sIdx;
        if (sIdx < 0 && eIdx < 0) {
            rpphost_debug_print(DEBUG_DATA, "Parse interface index token: %s failed", token1);
            goto nextloop;
        }
        // Validate interface index
        eIdx = MIN_VAL(eIdx, MAX_INTF_IDX);
        for (int i=sIdx; i<=eIdx; i++) {
            tmpIntf[i] = 1;
        }
nextloop:
        token1 = strtok_r(NULL, DELIM_1, &savePtr1);
    }

    intfs = (int*)malloc(sizeof(int)*MAX_INTF_NUM);
    for (int i=0; i<MAX_INTF_NUM; i++) {
        if (tmpIntf[i]) {
            intfs[(*intfCnt)++] = i;
        }
    }
    return intfs;
}

/******************************************************************************
 * Function Name    : util_mac_addr_to_str
 * Description      : Convert mac address to string
 ******************************************************************************/
void util_mac_addr_to_str(uint8_t *addr, char *buff)
{
    memset(buff, 0, MAC_ADDR_STR_LEN);
    if (addr == NULL) {
        return;
    }
    snprintf(buff, MAC_ADDR_STR_LEN, MAC_STRING_FORMAT, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

/******************************************************************************
 * Function Name    : open_socket_conn
 * Description      : Open socket connection (return -1 when failed)
 ******************************************************************************/
int open_socket_conn(const char *addr, int port)
{
    int sock;
    struct sockaddr_in sockaddr;
    //create a UDP socket
    if ((sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		rpphost_debug_print(DEBUG_DATA, "ERROR: create socket failed");
        return -1;
    }

    // zero out the structure
    memset((char *) &sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(port);
    sockaddr.sin_addr.s_addr = inet_addr(addr);

    if (bind(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0) {
        rpphost_debug_print(DEBUG_DATA, "ERROR: bind socket to address: %s port: %d failed", addr, port);
        // return -1;
    }
    rpphost_debug_print(DEBUG_DATA, "Open socket for address: %s port: %d socket id: %d", addr, port, sock);
    return sock;
}

/******************************************************************************
 * Function Name    : get_inf_index
 * Description      : Get interface index (Example: input 'sta0' with prefix 'sta' got index '0')
 ******************************************************************************/
int get_inf_index(const char *str, const char *prefix, int def)
{
    int index = def;
    const char *tmpStr = str;
    if (tmpStr != NULL) {
        while (*tmpStr == ' ') tmpStr++; // Get rid of whitespace
        if (strncmp(tmpStr, prefix, strlen(prefix)) == 0) {
            char format[32];
            snprintf(format, sizeof format, "%s%s", prefix, "%d");
            sscanf(tmpStr, format, &index);
        }
    }
    return index;
}

/******************************************************************************
 * Function Name    : find_val_in_map
 * Description      : Find value in map, return default when not found
 ******************************************************************************/
int find_val_in_map(const struct KeyValMap *map, size_t mapLen, const char *key, const int def)
{
    for (int i=0; i<mapLen; i++) {
        if (strcasecmp(map[i].key, key) == 0) {
            return map[i].val;
        }
    }
    return def;
}

/******************************************************************************
 * Function Name    : find_key_in_map
 * Description      : Find value in map, return "" when not found
 ******************************************************************************/
const char *find_key_in_map(const struct KeyValMap *map, size_t mapLen, const int val)
{
    for (int i=0; i<mapLen; i++) {
        if (map[i].val == val) {
            return map[i].key;
        }
    }
    return "";
}

/******************************************************************************
 * Function Name    : get_linenum_start_with
 * Description      : Return line number that start with str, -1 when failed
 ******************************************************************************/
int get_linenum_start_with(const char (*lines)[MAX_LINE_LEN], uint8_t lineCnt, const char *key)
{
    const char *line;
    for (int i=0; i<lineCnt; i++) {
        line = lines[i];
        if (line != NULL && memcmp(line, key, strlen(key)) == 0) {
            return i;
        }
    }
    return -1;
}

/******************************************************************************
 * Function Name    : * p_keyword
 * Description      : This Function is used to return pointer of keyword in buf 
 ******************************************************************************/
const char *p_keyword(const char *buf, const char *key)
{
    uint8_t keyLen = strlen(key);
    if (memcmp(buf, key, keyLen)) {
        return NULL;
    }
    return (buf + keyLen);
}

/******************************************************************************
 * Function Name    : str_to_int
 * Description      : Convert string to integer
 ******************************************************************************/
int str_to_int(const char *buf)
{
#define HEX_NUM_PREFIX "0x"
    if (strlen(buf)>2 && (memcmp(buf, HEX_NUM_PREFIX, strlen(HEX_NUM_PREFIX)) == 0)) { // Hex number
        return (int)strtol(buf, NULL, 0);
    }
    return atoi(buf);
}

/******************************************************************************
 * Function Name    : print_sta_cfg
 * Description      : Print sta configuration object
 ******************************************************************************/
void print_sta_cfg(AddStaReq *staCfg)
{
    rpphost_debug_print(DEBUG_DATA, "mac: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", 
    staCfg->mac[0], staCfg->mac[1], staCfg->mac[2], staCfg->mac[3], staCfg->mac[4], staCfg->mac[5]);
    rpphost_debug_print(DEBUG_DATA, "apssid: %s apbssid: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", 
    staCfg->apssid, staCfg->apbssid[0], staCfg->apbssid[1], staCfg->apbssid[2], staCfg->apbssid[3], staCfg->apbssid[4], staCfg->apbssid[5]);
    rpphost_debug_print(DEBUG_DATA, "protocolrate: %d gi: %d disableht40M: %d disablemaxamsdu: %d disableldpc: %d", 
    staCfg->protocolrate, staCfg->gi, staCfg->disableht40M, staCfg->disablemaxamsdu, staCfg->disableldpc);
    rpphost_debug_print(DEBUG_DATA, "maxampdusize: %d minampdudensity: %d vhtmaxampdusize: %d pmftype: %d",
    staCfg->maxampdusize, staCfg->minampdudensity, staCfg->vhtmaxampdusize, staCfg->pmftype);
    rpphost_debug_print(DEBUG_DATA, "Encryption: %s", MAP_VAL_TO_KEY(encrypTypeMap, staCfg->encryption.type));
    switch (staCfg->encryption.type)
    {
        case OPEN:
        case ENHANCED_OPEN:
        {
            // Do nothing
            break;
        }
        case PERSONAL:
        case WPA3_PERSONAL:
        case WPA2_WPA3_PERSONAL:
        {
            EncryptionPersonal *personal = (EncryptionPersonal *)&(staCfg->exdata[staCfg->encryption.cfgoffset]);
            if (!personal) {
                rpphost_debug_print(DEBUG_DATA, "Invalid encryption information type: %s", MAP_VAL_TO_KEY(encrypTypeMap, staCfg->encryption.type));
                break;
            }
            rpphost_debug_print(DEBUG_DATA, "Passphrase: %s", personal->passphrase);
            break;
        }
        case ENTERPRISE:
        case WPA3_ENTERPRISE:
        {
            EncryptionEAP *eap = (EncryptionEAP *)&(staCfg->exdata[staCfg->encryption.cfgoffset]);
            if (!eap) {
                rpphost_debug_print(DEBUG_DATA, "Invalid encryption information type: %s", MAP_VAL_TO_KEY(encrypTypeMap, staCfg->encryption.type));
                break;
            }
            rpphost_debug_print(DEBUG_DATA, "EAP type: %s", MAP_VAL_TO_KEY(encEAPTypeMap, eap->type));
            switch (eap->type)
            {
                case EAP_TLS:
                {
                    rpphost_debug_print(DEBUG_DATA, "Peeridentity: %s Password: %s Cacertfilename: %s Privkeyfilename: %s Certfilename: %s", 
                    eap->u.tls.peeridentity, eap->u.tls.password, eap->u.tls.cacertfilename, eap->u.tls.privkeyfilename, eap->u.tls.certfilename);
                    break;
                }
                case EAP_TTLS:
                {
                    rpphost_debug_print(DEBUG_DATA, 
                    "Phase2Type: %d Peeridentity: %s Anonymousidentity: %s Password: %s Cacertfilename: %s "
                    "Phase2_cacertfilename: %s Phase2_certfilename: %s Phase2_privkeyfilename: %s Phase2_privkeypassphrase: %s", 
                    eap->u.ttls.phase2Type, eap->u.ttls.peeridentity, eap->u.ttls.anonymousidentity, eap->u.ttls.password, eap->u.ttls.cacertfilename, 
                    eap->u.ttls.phase2_cacertfilename, eap->u.ttls.phase2_certfilename, eap->u.ttls.phase2_privkeyfilename, eap->u.ttls.phase2_privkeypassphrase);
                    break;
                }
                case EAP_PEAP:
                {
                    rpphost_debug_print(DEBUG_DATA, 
                    "Phase2Type: %d Peeridentity: %s Anonymousidentity: %s Password: %s Cacertfilename: %s "
                    "Phase2_cacertfilename: %s Phase2_certfilename: %s Phase2_privkeyfilename: %s Phase2_privkeypassphrase: %s", 
                    eap->u.ttls.phase2Type, eap->u.ttls.peeridentity, eap->u.ttls.anonymousidentity, eap->u.ttls.password, eap->u.ttls.cacertfilename, 
                    eap->u.ttls.phase2_cacertfilename, eap->u.ttls.phase2_certfilename, eap->u.ttls.phase2_privkeyfilename, eap->u.ttls.phase2_privkeypassphrase);
                    break;
                }
                case EAP_AKA:
                {
                    rpphost_debug_print(DEBUG_DATA, "Subtype: %d Identity: %s Password: %s", eap->u.aka.subtype, eap->u.aka.identity, eap->u.aka.password);
                    break;
                }
                default:
                {
                    rpphost_debug_print(DEBUG_DATA, "Invalid encryption sub type: %d", eap->type);
                    break;
                }
            }
            break;
        }
        case WEP:
        {
            EncryptionWEP *wep = (EncryptionWEP *)&(staCfg->exdata[staCfg->encryption.cfgoffset]);
            if (!wep) {
                rpphost_debug_print(DEBUG_DATA, "Invalid encryption information type: %s", MAP_VAL_TO_KEY(encrypTypeMap, staCfg->encryption.type));
                break;
            }
            rpphost_debug_print(DEBUG_DATA, "Format: %d Key: %s", wep->format, wep->key);
            break;
        }
        default:
        {
            rpphost_debug_print(DEBUG_DATA, "Invalid encryption type: %d", staCfg->encryption.type);
            break;
        }
    }
    rpphost_debug_print(DEBUG_DATA, "fbtcfg.enable: %d fbtcfg.overds: %d fbtcfg.nbroftargets: %d fbtcfg.targetsoffset: %d", 
    staCfg->fbtcfg.enable, staCfg->fbtcfg.overds, staCfg->fbtcfg.nbroftargets, staCfg->fbtcfg.targetsoffset);
}

/******************************************************************************
 * Function Name    : print_rpp_msg
 * Description      : Print rpp message
 ******************************************************************************/
void print_rpp_msg(RppMessageHead *msghdr)
{
    if (!msghdr) {
        return;
    }
    static uint8_t ignoreType [] = {RPP_MSG_KEEPALIVE};
    for (int i=0; i<GET_ARRAY_LEN(ignoreType); i++) {
        if (ignoreType[i] == msghdr->type) {
            return;
        }
    }

    rpphost_debug_print(DEBUG_DATA, "Rpp message info category: %d (len: %d)", msghdr->cat, msghdr->len);
    switch (msghdr->type)
    {
        case RPP_MSG_PROB_REQ:
        {
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_PROB_REQ");
            break;
        }
        case RPP_MSG_PROB_RESP:
        {
            ProbeResp *resp = (ProbeResp *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_PROB_RESP");
            rpphost_debug_print(DEBUG_DATA, "handle: %d hwver: %d swver: %d", resp->handle, resp->hwver, resp->swver);
            break;
        }
        case RPP_MSG_GETPHY_REQ:
        {
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_GETPHY_REQ");
            break;
        }
        case RPP_MSG_GETPHY_RESP:
        {
            GetPhyResp *resp = (GetPhyResp*)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_GETPHY_RESP");
            rpphost_debug_print(DEBUG_DATA, "errcode: %d", resp->errcode);
            PhyIntfDesc *phys = (PhyIntfDesc *)resp->phys;
            for (int i=0; i<resp->nbrofphys; i++) {
                int index = (phys[i].supportedbands==FREQBAND_5_0_GHz)?RPP_APP_DEFNUM_ONE:0;
                rpphost_debug_print(DEBUG_DATA, "handle: %d supportedbands: %d maxnss: %d maxsta: %d", 
                phys[i].handle, phys[i].supportedbands, phys[i].maxnss, phys[i].maxsta);
                rpphost_debug_print(DEBUG_DATA, "htcap: %d vhtcap: %d hemaccap: %"PRIu64" hephycaplow: %"PRIu64" hephycaphigh: %"PRIu64, 
                phys[i].htcap[index], phys[i].vhtcap[index], phys[i].hemaccap[index], phys[i].hephycaplow[index], phys[i].hephycaphigh[index]);
            }
            break;
        }
        case RPP_MSG_SETPHY_REQ:
        {
            SetPhyReq* phyCfg = (SetPhyReq *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_SETPHY_REQ");
            rpphost_debug_print(DEBUG_DATA, "handle: %d regulatory: %c%c freqband: %d cfgnss: 0x%x", 
            phyCfg->handle, phyCfg->regulatory[0], phyCfg->regulatory[1], phyCfg->freqband, phyCfg->cfgnss);
            rpphost_debug_print(DEBUG_DATA, "supportedrates: 0x%x supportedhtmcsset: 0x%x supportedvhtmcsset: 0x%x supportedhemcsset: 0x%x", 
            phyCfg->supportedrates, phyCfg->supportedhtmcsset, phyCfg->supportedvhtmcsset, phyCfg->supportedhemcsset);
            rpphost_debug_print(DEBUG_DATA, "amsdudepth: %d ampdudepth: %d txpowerattnueation: %d txmcsmap: %d rxmcsmap: %d", 
            phyCfg->amsdudepth, phyCfg->ampdudepth, phyCfg->txpowerattnueation, phyCfg->txmcsmap, phyCfg->rxmcsmap);
            rpphost_debug_print(DEBUG_DATA, "heflags: 0x%x hebsscolor: %d hefrag: %d flags: 0x%x", 
            phyCfg->heflags, phyCfg->hebsscolor, phyCfg->hefrag, phyCfg->flags);
            break;
        }
        case RPP_MSG_SETPHY_RESP:
        {
            SetPhyResp *resp = (SetPhyResp*)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_SETPHY_RESP");
            rpphost_debug_print(DEBUG_DATA, "errcode: %d", resp->errcode);
            break;
        }
        case RPP_MSG_ADDSTA_REQ:
        {
            AddStaReq* staCfg = (AddStaReq *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_ADDSTA_REQ");
            print_sta_cfg(staCfg);
            break;
        }
        case RPP_MSG_ADDSTA_RESP:
        {
            AddStaResp *resp = (AddStaResp *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_ADDSTA_RESP");
            rpphost_debug_print(DEBUG_DATA, "stahandle: %d errcode: %d", resp->stahandle, resp->errcode);
            break;
        }
        case RPP_MSG_DELSTA_REQ:
        {
            DelStaReq *req = (DelStaReq *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_DELSTA_REQ");
            rpphost_debug_print(DEBUG_DATA, "phyhandle: %d stahandle: %d", req->phyhandle, req->stahandle);
            break;
        }
        case RPP_MSG_DELSTA_RESP:
        {
            DelStaResp *resp = (DelStaResp*)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_DELSTA_RESP");
            rpphost_debug_print(DEBUG_DATA, "errcode: %d", resp->errcode);
            break;
        }
        case RPP_MSG_SCAN_REQ:
        {
            ScanReq *req = (ScanReq *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_SCAN_REQ");
            rpphost_debug_print(DEBUG_DATA, "phyhandle: %d duration: %d", req->phyhandle, req->duration);
            break;
        }
        case RPP_MSG_SCAN_RESP:
        {
            ScanResp *resp = (ScanResp*)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_SCAN_RESP");
            rpphost_debug_print(DEBUG_DATA, "errcode: %d nbrofresults: %d more: %d", resp->errcode, resp->nbrofresults, resp->more);
            ScanInfo *info = (ScanInfo *)resp->results;
            char buff[MAC_ADDR_STR_LEN];
            util_mac_addr_to_str(info->bssid, buff);
            rpphost_debug_print(DEBUG_DATA, "ssid: %s ss ssidlen: %d bssid: %s rssi: %d", info->ssid, info->ssidlen, buff, info->rssi);
            rpphost_debug_print(DEBUG_DATA, "htcap: %d vhtcap: %d hecap: %d freq: %d", info->htcap, info->vhtcap, info->hecap, info->freq);
            rpphost_debug_print(DEBUG_DATA, "maxphyrate: %d chnbw: %d sgi: %d enctype: %d", info->maxphyrate, info->chnbw, info->sgi, info->enctype);
            rpphost_debug_print(DEBUG_DATA, "encinfo: %s manufacturer: %s modelname: %s", info->encinfo, info->manufacturer, info->modelname);
            break;
        }
        case RPP_MSG_ASSOC_REQ:
        {
            AssocReq *req = (AssocReq *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_ASSOC_REQ");
            rpphost_debug_print(DEBUG_DATA, "phyhandle: %d stahandle: %d", req->phyhandle, req->stahandle);
            break;
        }
        case RPP_MSG_ASSOC_RESP:
        {
            AssocResp *resp = (AssocResp*)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_ASSOC_RESP");
            rpphost_debug_print(DEBUG_DATA, "errcode: %d", resp->errcode);
            break;
        }
        case RPP_MSG_DEASSOC_REQ:
        {
            DeAssocReq* req = (DeAssocReq *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_DEASSOC_REQ");
            rpphost_debug_print(DEBUG_DATA, "phyhandle: %d stahandle: %d", req->phyhandle, req->stahandle);
            break;
        }
        case RPP_MSG_DEASSOC_RESP:
        {
            DeAssocResp *resp = (DeAssocResp*)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_DEASSOC_RESP");
            rpphost_debug_print(DEBUG_DATA, "errcode: %d", resp->errcode);
            break;
        }
        case RPP_MSG_FBT_REQ:
        {
            FBTReq* req = (FBTReq *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_FBT_REQ");
            rpphost_debug_print(DEBUG_DATA, "phyhandle: %d stahandle: %d targetap: %s", req->phyhandle, req->stahandle, req->targetap);
            break;
        }
        case RPP_MSG_FBT_RESP:
        {
            FBTResp *resp = (FBTResp*)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_FBT_RESP");
            rpphost_debug_print(DEBUG_DATA, "errcode: %d", resp->errcode);
            break;
        }
        case RPP_MSG_SETMODE_REQ:
        {
            SetModeReq *req = (SetModeReq *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_SETMODE_REQ");
            rpphost_debug_print(DEBUG_DATA, "phyhandle: %d mode: %d bw: %d ctl_freq: %d", req->phyhandle, req->mode, req->bw, req->ctl_freq);
            rpphost_debug_print(DEBUG_DATA, "center_freq1: %d center_freq2: %d buffaction: %d capfilterlen: %d capfilter: %s", 
            req->center_freq1, req->center_freq2, req->buffaction, req->capfilterlen, req->capfilter);
            break;
        }
        case RPP_MSG_SETMODE_RESP:
        {
            SetModeResp *resp = (SetModeResp*)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_SETMODE_RESP");
            rpphost_debug_print(DEBUG_DATA, "errcode: %d", resp->errcode);
            break;
        }
        case RPP_MSG_ASSOCSTATE_NOTF:
        {
            AssocStateNtfy *assocState = (AssocStateNtfy *)msghdr->body;
            char buff[MAC_ADDR_STR_LEN];
            util_mac_addr_to_str(assocState->bssid, buff);
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_ASSOCSTATE_NOTF");
            rpphost_debug_print(DEBUG_DATA, "phyhandle: %d stahandle: %d state: %d bssid: %s errcode: %d", 
            assocState->phyhandle, assocState->stahandle, assocState->state, buff, assocState->errcode);
            break;
        }
        case RPP_MSG_GETSTATS_REQ:
        {
            GetStatsReq *req = (GetStatsReq *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_GETSTATS_REQ");
            rpphost_debug_print(DEBUG_DATA, "phyhandle: %d stahandle: %d", req->phyhandle, req->stahandle);
            break;
        }
        case RPP_MSG_GETSTATS_RESP:
        {
            GetStatsResp *resp = (GetStatsResp*)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_GETSTATS_RESP");
            rpphost_debug_print(DEBUG_DATA, "errcode: %d nbrofstats: %d", resp->errcode, resp->nbrofstats);
            StaStats *stats = (StaStats *)resp->stats;
            char buff[MAC_ADDR_STR_LEN];
            util_mac_addr_to_str(stats->bssid, buff);
            rpphost_debug_print(DEBUG_DATA, "wlanmode: %d mimomode: %d rxnss: %d txnss: %d", stats->wlanmode, stats->mimomode, stats->rxnss, stats->txnss);
            rpphost_debug_print(DEBUG_DATA, "freqband: %d chnbw: %d txmcsindex: %d rxmcsindex: %d", stats->freqband, stats->chnbw, stats->txmcsindex, stats->rxmcsindex);
            rpphost_debug_print(DEBUG_DATA, "ctlfreq: %d stastate: %d bssid: %s", stats->ctlfreq, stats->stastate, buff);
            rpphost_debug_print(DEBUG_DATA, "rssi: %d noisefloor: %d rxgi: %d txgi: %d", stats->rssi, stats->noisefloor, stats->rxgi, stats->txgi);
            rpphost_debug_print(DEBUG_DATA, "etc");
            break;
        }
        case RPP_MSG_CLRSTATS_REQ:
        {
            ClearStatsReq *req = (ClearStatsReq *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_CLRSTATS_REQ");
            rpphost_debug_print(DEBUG_DATA, "phyhandle: %d stahandle: %d", req->phyhandle, req->stahandle);
            break;
        }
        case RPP_MSG_CLRSTATS_RESP:
        {
            ClearStatsResp *resp = (ClearStatsResp *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_CLRSTATS_RESP");
            rpphost_debug_print(DEBUG_DATA, "errcode: %d", resp->errcode);
            break;
        }
        case RPP_MSG_SETLOG_REQ:
        {
            SetLogLevelReq *req = (SetLogLevelReq *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_SETLOG_REQ");
            rpphost_debug_print(DEBUG_DATA, "severity: %d", req->severity);
            break;
        }
        case RPP_MSG_SETLOG_RESP:
        {
            SetLogLevelResp *resp = (SetLogLevelResp *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_SETLOG_RESP");
            rpphost_debug_print(DEBUG_DATA, "errcode: %d", resp->errcode);
            break;
        }
        case RPP_MSG_LOGGER_REQ:
        {
            SetLogLevelReq *req = (SetLogLevelReq *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_LOGGER_REQ");
            rpphost_debug_print(DEBUG_DATA, "severity: %d", req->severity);
            break;
        }
        case RPP_MSG_KEEPALIVE:
        {
            KeepAlive *k = (KeepAlive *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_KEEPALIVE");
            rpphost_debug_print(DEBUG_DATA, "dummy: %d", k->dummy);
            break;
        }
        case RPP_MSG_CAPCTRL_REQ:
        {
            CaptureControlReq *req = (CaptureControlReq *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_CAPCTRL_REQ");
            rpphost_debug_print(DEBUG_DATA, "phyhandle: %d cmd: %d caphnd: %d CapFilterLen: %d CapFilter: %s", 
            req->phyhandle, req->cmd, req->caphnd, req->CapFilterLen, req->CapFilter);
            break;
        }
        case RPP_MSG_CAPCTRL_RESP:
        {
            CaptureControlResp *resp = (CaptureControlResp *)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_CAPCTRL_RESP");
            rpphost_debug_print(DEBUG_DATA, "errcode: %d pktcount: %d streamcrvport: %d", resp->errcode, resp->pktcount, resp->streamcrvport);
            break;
        }
        case RPP_MSG_REBOOT:
        {
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_REBOOT");
            break;
        }
        case RPP_MSG_STATS_UPDATE:
        {
            // StatsBulkUpdate *resp = (StatsBulkUpdate*)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_STATS_UPDATE");
            rpphost_debug_print(DEBUG_DATA, "To be add");
            break;
        }
        case RPP_MSG_CCA_STATS_UPDATE:
        {
            // PhyCcaStatsUpdate *resp = (PhyCcaStatsUpdate*)msghdr->body;
            rpphost_debug_print(DEBUG_DATA, "Type: RPP_MSG_CCA_STATS_UPDATE");
            rpphost_debug_print(DEBUG_DATA, "To be add");
            break;
        }
        default:
        {
            rpphost_debug_print(DEBUG_DATA, "Type: %d not yet supported", msghdr->type);
            break;
        }
    }
    rpphost_debug_print(DEBUG_DATA, "------------");
}

/******************************************************************************
 * Function Name    : init_sta_cfg
 * Description      : Initial add station request
 ******************************************************************************/
void init_sta_cfg(AddStaReq *staCfg)
{
	memset(staCfg, 0, sizeof(*staCfg));
    staCfg->phyhandle = 0;
    memset(staCfg->mac, 0, sizeof(staCfg->mac));
    memset(staCfg->apbssid, 0, sizeof(staCfg->apbssid));
    memset(staCfg->apssid, 0, sizeof(staCfg->apssid));
    staCfg->protocolrate = 6;
    staCfg->gi = 2;
    staCfg->disableht40M = 0;
    staCfg->disablemaxamsdu = 0;
    staCfg->disableldpc = 0;
    staCfg->maxampdusize = 3;
    staCfg->minampdudensity = 6;
    staCfg->vhtmaxampdusize = 7;
    staCfg->fbtcfg.enable = 0;
    staCfg->fbtcfg.nbroftargets = 0;
    staCfg->pmftype = 0;
	// Initial encryption type is OPEN
    staCfg->encryption.type = OPEN;
    staCfg->encryption.cfgoffset = 0;
    staCfg->exdatalen = 0;
}

/******************************************************************************
 * Function Name    : parse_sta_encryption
 * Description      : Handle station encryption parsing, return 0 when success
 ******************************************************************************/
int parse_sta_encryption(const char (*lines)[MAX_LINE_LEN], uint8_t lineCnt, AddStaReq *staCfg)
{
    int found;
    uint8_t encryptType;
    { // Encryption type
        char encrypt_str[32];
        READ_LINE_STR_VALUE(lines, lineCnt, "encryption=", encrypt_str, found);
        if (!found) {
            rpphost_debug_print(DEBUG_DATA, "Invalid encryption type in configuration");
            return 0;
        }

        encryptType = MAP_KEY_TO_VAL(encrypTypeMap, encrypt_str, -1);
        if (encryptType < 0) {
            rpphost_debug_print(DEBUG_DATA, "Invalid encryption type: %s", encrypt_str);
            return 0;
        }
    }

	staCfg->encryption.type = encryptType;
    staCfg->encryption.cfgoffset = 0;
    staCfg->exdatalen = 0;
    switch (staCfg->encryption.type)
    {
        case OPEN:
        case ENHANCED_OPEN:
        {
            // Do nothing
            break;
        }
        case PERSONAL:
        case WPA3_PERSONAL:
        case WPA2_WPA3_PERSONAL:
        {
            staCfg->exdatalen = sizeof(EncryptionPersonal);
            EncryptionPersonal *personal = (EncryptionPersonal *)&(staCfg->exdata[staCfg->encryption.cfgoffset]);
            memset(personal->passphrase, 0, sizeof(personal->passphrase));
            READ_LINE_STR_VALUE(lines, lineCnt, "passphrase=", personal->passphrase, found);
            break;
        }
        case ENTERPRISE:
        case WPA3_ENTERPRISE:
        {
            char eapauthStr[32];
            READ_LINE_STR_VALUE(lines, lineCnt, "eapauth=", eapauthStr, found);
            staCfg->exdatalen = sizeof(EncryptionEAP);
            EncryptionEAP *eap = (EncryptionEAP *)&(staCfg->exdata[staCfg->encryption.cfgoffset]);
            int eapType = MAP_KEY_TO_VAL(encEAPTypeMap, eapauthStr, -1);
            if (eapType < 0) {
                rpphost_debug_print(DEBUG_DATA, "Invalid configuration 'eapauth' value: %s", eapauthStr);
                return 0;
            }
            eap->type = eapType;
            rpphost_debug_print(DEBUG_DATA, "eap->type %d", eap->type);
            switch (eap->type)
            {
                case EAP_TLS:
                {
                    READ_LINE_STR_VALUE(lines, lineCnt, "peeridentity=", eap->u.tls.peeridentity, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "password=", eap->u.tls.password, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "cacertfilename=", eap->u.tls.cacertfilename, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "privkeyfilename=", eap->u.tls.privkeyfilename, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "certfilename=", eap->u.tls.certfilename, found);
                    break;
                }
                case EAP_TTLS:
                {
                    READ_LINE_NUM_VALUE(lines, lineCnt, "phase2Type=", eap->u.ttls.phase2Type, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "peeridentity=", eap->u.ttls.peeridentity, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "anonymousidentity=", eap->u.ttls.anonymousidentity, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "password=", eap->u.ttls.password, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "cacertfilename=", eap->u.ttls.cacertfilename, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "phase2_cacertfilename=", eap->u.ttls.phase2_cacertfilename, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "phase2_certfilename=", eap->u.ttls.phase2_certfilename, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "phase2_privkeyfilename=", eap->u.ttls.phase2_privkeyfilename, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "phase2_privkeypassphrase=", eap->u.ttls.phase2_privkeypassphrase, found);
                    break;
                }
                case EAP_PEAP:
                {
                    READ_LINE_NUM_VALUE(lines, lineCnt, "phase2Type=", eap->u.peap.phase2Type, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "peeridentity=", eap->u.peap.peeridentity, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "anonymousidentity=", eap->u.peap.anonymousidentity, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "password=", eap->u.peap.password, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "cacertfilename=", eap->u.peap.cacertfilename, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "phase2_cacertfilename=", eap->u.peap.phase2_cacertfilename, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "phase2_certfilename=", eap->u.peap.phase2_certfilename, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "phase2_privkeyfilename=", eap->u.peap.phase2_privkeyfilename, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "phase2_privkeypassphrase=", eap->u.peap.phase2_privkeypassphrase, found);
                    break;
                }
                case EAP_AKA:
                {
                    READ_LINE_NUM_VALUE(lines, lineCnt, "subtype=", eap->u.aka.subtype, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "identity=", eap->u.aka.identity, found);
                    READ_LINE_STR_VALUE(lines, lineCnt, "password=", eap->u.aka.password, found);
                    break;
                }
                default:
                {
                    rpphost_debug_print(DEBUG_DATA, "Invalid encryption EAP type: %d", eap->type);
                    break;
                }
            }
            break;
        }
        case WEP:
        {
            staCfg->exdatalen = sizeof(EncryptionWEP);
            EncryptionWEP *wep = (EncryptionWEP *)&(staCfg->exdata[staCfg->encryption.cfgoffset]);
            READ_LINE_NUM_VALUE(lines, lineCnt, "format=", wep->format, found);
            READ_LINE_STR_VALUE(lines, lineCnt, "key=", wep->key, found);
            break;
        }
        default:
        {
            rpphost_debug_print(DEBUG_DATA, "Invalid encryption subtype: %d", staCfg->encryption.type);
            return 1;
        }
    }
    return 0;
}

/******************************************************************************
 * Function Name    : sta_cfg_parser
 * Description      : This Function is used to parse 
 ******************************************************************************/
uint8_t sta_cfg_parser(const char (*lines)[MAX_LINE_LEN], uint8_t lineCnt, AddStaReq *staCfg) 
{
    int found = 0;
    char tmp[32] = {0};
    READ_LINE_STR_VALUE(lines, lineCnt, "mac=", tmp, found);
    if (found) {
        sscanf(tmp, MAC_STRING_FORMAT, 
        (char *)&staCfg->mac[0], (char *)&staCfg->mac[1], (char *)&staCfg->mac[2], (char *)&staCfg->mac[3], (char *)&staCfg->mac[4], (char *)&staCfg->mac[5]);
    }

    memset(tmp, 0, sizeof(tmp));
    READ_LINE_STR_VALUE(lines, lineCnt, "apbssid=", tmp, found);
    if (found) {
        sscanf(tmp, MAC_STRING_FORMAT,
        (char *)&staCfg->apbssid[0], (char *)&staCfg->apbssid[1], (char *)&staCfg->apbssid[2], (char *)&staCfg->apbssid[3], (char *)&staCfg->apbssid[4], (char *)&staCfg->apbssid[5]);
    }
    READ_LINE_STR_VALUE(lines, lineCnt, "apssid=", staCfg->apssid, found);
    READ_LINE_NUM_VALUE(lines, lineCnt, "protocolrate=", staCfg->protocolrate, found);
    READ_LINE_NUM_VALUE(lines, lineCnt, "gi=", staCfg->gi, found);
    READ_LINE_NUM_VALUE(lines, lineCnt, "disableht40M=", staCfg->disableht40M, found);
    READ_LINE_NUM_VALUE(lines, lineCnt, "disablemaxamsdu=", staCfg->disablemaxamsdu, found);
    READ_LINE_NUM_VALUE(lines, lineCnt, "disableldpc=", staCfg->disableldpc, found);
    READ_LINE_NUM_VALUE(lines, lineCnt, "maxampdusize=", staCfg->maxampdusize, found);
    READ_LINE_NUM_VALUE(lines, lineCnt, "minampdudensity=", staCfg->minampdudensity, found);
    READ_LINE_NUM_VALUE(lines, lineCnt, "vhtmaxampdusize=", staCfg->vhtmaxampdusize, found);
    READ_LINE_NUM_VALUE(lines, lineCnt, "pmftype=", staCfg->pmftype, found);
    parse_sta_encryption(lines, lineCnt, staCfg); // Parse station encryption informations


    for (int i=0; i<lineCnt; i++) {
        READ_KEY_STR_VALUE(lines[i], "cacertfilename=", tmp, found);
        if (found) {
            printf("i: %d cacer: %s\n", i, tmp);
        }
        READ_KEY_STR_VALUE(lines[i], "certfilename=", tmp, found);
        if (found) {
            printf("i: %d cer: %s\n", i, tmp);
        }
    }
    return APINFO_SUCCESS;
}

/******************************************************************************
 * Function Name    : increase_mac_number
 * Description      : Increase mac number by incNum (start with last ADDR position), return 0 when success
 ******************************************************************************/
int increase_mac_number(uint8_t *mac, uint8_t incNum)
{
    uint8_t tmp[ETHER_MAC_ADDR_LEN];
    memcpy(tmp, mac, sizeof(uint8_t)*ETHER_MAC_ADDR_LEN);
    for (int i=ETHER_MAC_ADDR_LEN-1; i>=0; i--) {
        if (tmp[i] + incNum <= 0xFF) {
            tmp[i] += incNum;
            memcpy(mac, tmp, sizeof(uint8_t)*ETHER_MAC_ADDR_LEN);
            return 0;
        }
        tmp[i] += incNum;
        incNum = 1;
    }
    return 1;
}

/******************************************************************************
 * Function Name    : load_sta_cfg
 * Description      : Load staion configuration from file, return 0 when success
 ******************************************************************************/
int load_sta_cfg(AddStaReq *staCfg, int *devCnt, const char *cfgPath) 
{
    init_sta_cfg(staCfg); // Initial AddStaReq
    if (strlen(cfgPath) == 0) {
        rpphost_debug_print(DEBUG_DATA, "No sta configuration file, use default configurations");
        return 0;
    }

    FILE *fptr;
    rpphost_debug_print(DEBUG_DATA, "Parse station configurations from file: %s", cfgPath);
    if ((fptr = fopen(cfgPath, "r")) == NULL){
        rpphost_debug_print(DEBUG_DATA, "ERR_MSG------->Read station configurations file failed");
        return -1;
    }

    // Store configuration line in array for parse encryption informations once
	uint8_t lineCnt = 0;
	char lines[MAX_READ_LINE][MAX_LINE_LEN];
	while(fgets(lines[lineCnt], sizeof(lines[lineCnt]), fptr) != NULL) 
    {
        IGNORE_NEWLINE(lines[lineCnt]);
		lineCnt++;
	}
    fclose(fptr);
    sta_cfg_parser(lines, lineCnt, staCfg); // Parse station configuration
	if (devCnt) { // Get device count, default is 1
        int found = 1;
        READ_LINE_NUM_VALUE(lines, lineCnt, "devcnt=", *devCnt, found);
        if (!found) { // Set device count to 1 when read 'devcnt' value failed
            *devCnt = 1;
        }
    }
	print_sta_cfg(staCfg);
    return 0;
}

/******************************************************************************
 * Function Name    : init_phy_cfg
 * Description      : Initial add station request
 ******************************************************************************/
void init_phy_cfg(SetPhyReq *phyCfg)
{
	memset(phyCfg, 0, sizeof(*phyCfg));
    phyCfg->handle = 0;
    strncpy((char*)phyCfg->regulatory, "US", 2);
    phyCfg->freqband = 0;
    phyCfg->cfgnss = 15; // Nss 4
    phyCfg->supportedrates = 0xff0;
    phyCfg->supportedhtmcsset = 0xff;
    phyCfg->supportedvhtmcsset = 0x209;
    phyCfg->supportedhemcsset = 0x80b;
    phyCfg->amsdudepth = 7;
    phyCfg->ampdudepth = 255;
    phyCfg->txpowerattnueation = 0;
    phyCfg->txmcsmap = 0;
    phyCfg->rxmcsmap = 0;
    phyCfg->heflags = 0x101; // 0x101 -> DL_oFDMA, 0x100 -> Proxy mode
    // phyCfg->hebsscolor = 0;
    phyCfg->hefrag = 2;
    phyCfg->flags = 14; // 14 -> 1110 (Enable 80/40/20 MHz chbw), 2 -> 0010 (Enable 20MHz chbw)
}

/******************************************************************************
 * Function Name    : phy_cfg_parser
 * Description      : This Function is used to parse 
 ******************************************************************************/
uint8_t phy_cfg_parser(char *line, SetPhyReq *phyCfg) 
{

#define PHY_CFG_READ_KEY_STR_VALUE(key, buff) \
    READ_KEY_STR_VALUE(line, key, buff, found); \
    if (found) return APINFO_SUCCESS;

#define PHY_CFG_READ_KEY_NUM_VALUE(key, buff) \
    READ_KEY_NUM_VALUE(line, key, buff, found); \
    if (found) return APINFO_SUCCESS;

    // Read phy configures, return when found
    int found = 0;
    PHY_CFG_READ_KEY_STR_VALUE("regulatory=", phyCfg->regulatory);
    PHY_CFG_READ_KEY_NUM_VALUE("freqband=", phyCfg->freqband);
    PHY_CFG_READ_KEY_NUM_VALUE("cfgnss=", phyCfg->cfgnss);
    PHY_CFG_READ_KEY_NUM_VALUE("supportedrates=", phyCfg->supportedrates);
    PHY_CFG_READ_KEY_NUM_VALUE("supportedhtmcsset=", phyCfg->supportedhtmcsset);
    PHY_CFG_READ_KEY_NUM_VALUE("supportedvhtmcsset=", phyCfg->supportedvhtmcsset);
    PHY_CFG_READ_KEY_NUM_VALUE("supportedhemcsset=", phyCfg->supportedhemcsset);
    PHY_CFG_READ_KEY_NUM_VALUE("amsdudepth=", phyCfg->amsdudepth);
    PHY_CFG_READ_KEY_NUM_VALUE("ampdudepth=", phyCfg->ampdudepth);
    PHY_CFG_READ_KEY_NUM_VALUE("txpowerattnueation=", phyCfg->txpowerattnueation);
    PHY_CFG_READ_KEY_NUM_VALUE("txmcsmap=", phyCfg->txmcsmap);
    PHY_CFG_READ_KEY_NUM_VALUE("rxmcsmap=", phyCfg->rxmcsmap);
    PHY_CFG_READ_KEY_NUM_VALUE("heflags=", phyCfg->heflags);
    PHY_CFG_READ_KEY_NUM_VALUE("hefrag=", phyCfg->hefrag);
    PHY_CFG_READ_KEY_NUM_VALUE("flags=", phyCfg->flags);
    return APINFO_SUCCESS;
}

/******************************************************************************
 * Function Name    : load_phy_cfg
 * Description      : Load phy configuration from file, return 0 when success
 ******************************************************************************/
int load_phy_cfg(SetPhyReq *phyCfg, const char *cfgPath)
{
    init_phy_cfg(phyCfg); // Initial SetPhyReq
    if (strlen(cfgPath) == 0) {
        rpphost_debug_print(DEBUG_DATA, "No sta configuration file, use default configurations");
        return 0;
    }

    FILE *fptr;
    rpphost_debug_print(DEBUG_DATA, "Parse phy configurations from file: %s", cfgPath);
    if ((fptr = fopen(cfgPath, "r")) == NULL){
        rpphost_debug_print(DEBUG_DATA, "ERR_MSG------->Read phy configurations file failed");
        return -1;
    }

    char line[MAX_LINE_LEN];
	while(fgets(line, sizeof(line), fptr) != NULL) 
    {
        IGNORE_NEWLINE(line);
        phy_cfg_parser(line, phyCfg);
	}
    fclose(fptr);
    return 0;
}
