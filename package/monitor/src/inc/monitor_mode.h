#ifndef INCLUDED_MONITOR_H
#define INCLUDED_MONITOR_H

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h> 
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdint.h>
#include <sys/param.h>
#include <assert.h>
#include <stddef.h>
#include "capture_commands.h"

#define TIMEOUT_LIMIT             1000
#define OFFLINE_REG_DATA_SIZE     (256 * 1024 * 1024)
#define OFFLINE_DATA_SIZE	  OFFLINE_REG_DATA_SIZE
#define OFFLINE_SDR_DATA_SIZE     (10 * 1024 * 1024)
#define OFFLINE_MODE              1
#define LIVE_MODE                 0
#define PKT_SIZE_KB               1024
#define MONITOR_MODE_COUNT_PKT    1
#define MONITOR_MODE_SEND_PKT     2
#define MAX_LISTEN_CLIENTS        5
#define BUFFER_SIZE               100
#define MONITOR_MODE              "Monitor"

#define MONITOR_MODE_WRAP_ENABLE 1

#define MONITOR_MODE_PRINT(x,fmt, ...) { printf(fmt, ##__VA_ARGS__); \
                                        syslog(x, fmt,  ##__VA_ARGS__);}

typedef struct monitorParam_tag {
	captureParam_t cParam;
	unsigned char *offlineCapData;
	pcap_t *monHandle;
	struct bpf_program filterHandle;
	int socketFd;
	int connSocketFd;
	unsigned int packetCount;
}monitorParam_t;

monitorParam_t mParam[2];

struct ringbuf_t
{
    uint8_t *buf;
    uint8_t *wptr, *rptr;
    size_t size;
};

typedef struct ringbuf_t *ringbuf_t;

ringbuf_t ringbuf_new(size_t capacity);

void ringbuf_del(ringbuf_t *rb);

size_t ringbuf_buffer_size(const struct ringbuf_t *rb);

size_t ringbuf_capacity(const struct ringbuf_t *rb);

size_t ringbuf_bytes_free(const struct ringbuf_t *rb);

size_t ringbuf_bytes_used(const struct ringbuf_t *rb);

int ringbuf_is_full(const struct ringbuf_t *rb);

void *ringbuf_write_buffer(ringbuf_t rb, const uint8_t *src, size_t count);

void *ringbuf_read_buffer(ringbuf_t rb, uint8_t *dst, size_t count);

const uint8_t *ringbuf_end(const struct ringbuf_t *rb);

void ringbuf_reset(ringbuf_t rb);

void ringbuf_discard(ringbuf_t rb, size_t count);
#endif /* INCLUDED_MONITOR_H */
