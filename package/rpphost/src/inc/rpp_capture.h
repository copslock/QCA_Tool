#ifndef RPP_CAPTURE_H_
#define RPP_CAPTURE_H_


/* Unique socket port for each radio */
#define CAPDAEMON_RADIO_0_PORT  5000
#define CAPDAEMON_RADIO_1_PORT  5002
#define CAPDAEMON_RADIO_2_PORT  5003

/* Unique ID for RPP-Slave commands */
#define CMD_RPPS_HEADER         0x55

/* Test operation commands */
#define CMD_REGULAR_START       0x11
#define CMD_REGULAR_STOP        0x12
#define CMD_REGULAR_RETRIVE     0x13

#define CMD_SDR_START           0x22
#define CMD_SDR_STOP            0x23
#define CMD_SDR_RETRIVE         0x24

/* Message from monitorD */
#define CMD_MONITORD_IS_UP      0x33
#define CMD_MONITORD_ACK        0x34
#define CMD_MONITORD_PKT_CNT    0x35
#define CMD_MONITORD_COMPLETE   0x36

/* Capture configuration parameters errors*/
#define ERR_UNKNOWN_OP_CMD      0x44       //Refer "Test operation commands" for valid commands
#define ERR_INVALID_MON_INTF    0x45       //monitor interface is not valid or couldn't be open
#define ERR_INVALID_CAP_MODE    0x46       //Invalid Capture mode (live/offline)
#define ERR_INVALID_OVR_WR_FLAG 0x47       //Invalid over write flag
#define ERR_INVALID_FILTER_EXPR 0x48       //Invalid filter expression

/* Memory allocation errors */
#define ERR_MEM_ALLOC           0x49       //No memory to allocate for capture

/* RPP-HOST communication errors */
#define ERR_RPPHOST_SOC_FAIL    0x50       //RPP-HOST TCP socket/bind failed
#define ERR_RPPHOST_SND_FAIL    0x51       //Packet stream to RPP-HOST failed


/* Offset for each data to prepare byte array(message) for socket communication
 * it can be used to manually convert structure to byte array.
 */
enum {
        CMD_HEADER_OF,
        CMD_CAPT_TYPE_OF,
        CMD_MON_INTF_OF,        //10B of data
        CMD_CAPT_MODE_OF = 13,
        CMD_OVER_WR_FLAG_OF,
        CMD_TCP_PORTNO_OF,
        CMD_FILTER_LEN_OF = CMD_TCP_PORTNO_OF + 4,
        CMD_FILTER_EXPR_OF,
}cmdOffset;

/*Creating the sockaddr and socketFd for each radio */
struct sockaddr_in capPortAddr_perRadio[RPP_NUM_OF_RADIO];
int32_t capPortFd_perRadio[RPP_NUM_OF_RADIO];

/* Message Frame:
 =================
 * Test Configuration message frame:
 * Test Configuration message frame:
 * |0:CMD_RPPS_HEADER | 1:rppsCmd | 2-12:mon_interface | 13:capture_mode | 14:overwrite_flag | 15-18:tcp_port_no | 19:filter_len | 20-filter_len:filter_expression |
 *
 * Normal Commands from/to RPP-Slave:
 * |0:CMD_RPPS_HEADER | 1:rppsCmd |
 */

typedef struct captureParams_tag {
    char msgHeader;

    /* Refer Test operation commands */
    char rppsCmd;

    /* Monitor interface name (it should be '\0' terminated string) */
    char mon_interface[10];

    /* 0:live mode 1:Offline mode*/
    char capture_mode;

    /* 1:Enable, 0:Disable*/
    char overwrite_flag;

    /* TCP port number to send captured packet*/
    int  tcp_port_no;

    /* Packet capture filter string len*/
    char filter_len;

    /* As of now we are declaring as zero-size array,
     * based on filter_len we can allocate memory
     * it should be '\0' terminated string
     */
    char filter_expression[0];
} __attribute__((packed)) captureParam_t; 

typedef struct monitordResponse_tag {
    char msgHeader;
    char msgID;
    unsigned int packetCount;
}__attribute__((packed)) monitordResponse_t;

int32_t rpp_receive_datafrom_monitord(monitordResponse_t *p_mResp, uint32_t phyhandle);
int32_t rpp_send_datato_monitord(captureParam_t *param_t, uint32_t phyhandle);

#endif /*RPP_CAPTURE_H_*/
