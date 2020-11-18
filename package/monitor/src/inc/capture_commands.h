#ifndef CAPTURE_CMD_H__
#define CAPTURE_CMD_H__

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

#define CMD_HEADER_OF		0
#define CMD_CAPT_TYPE_OF	1

/* Capture configuration parameters errors*/
#define ERR_UNKNOWN_OP_CMD	0x44	//Refer "Test operation commands" for valid commands
#define	ERR_INVALID_MON_INTF	0x45	//monitor interface is not valid or couldn't be open
#define	ERR_INVALID_CAP_MODE	0x46	//Invalid Capture mode (live/offline)
#define	ERR_INVALID_OVR_WR_FLAG	0x47	//Invalid over write flag
#define	ERR_INVALID_FILTER_EXPR	0x48	//Invalid filter expression

/* Memory allocation errors */
#define ERR_MEM_ALLOC		0x49	//No memory to allocate for capture

/* RPP-HOST communication errors */
#define	ERR_RPPHOST_SOC_FAIL	0x50	//RPP-HOST TCP socket/bind failed
#define	ERR_RPPHOST_SND_FAIL	0x51	//Packet stream to RPP-HOST failed

/* Command sequence error */
#define ERR_CMD_SEQ		0x52

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

struct pcap_pkt_usrhdr {
    uint64_t ts;      /* time stamp */
    uint32_t caplen;     /* length of portion present */
    uint32_t len;        /* length this packet (off wire) */
}__attribute__((packed));

#endif
