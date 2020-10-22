#ifndef __FPGA_LIB_COMMON_H__
#define __FPGA_LIB_COMMON_H__

#include <stdint.h>

int fpga_dev_open();
void fpga_dev_close(int id);
int fpga_read_value(int fd, uint32_t offset, uint32_t *value);
int fpga_write_value(int fd, uint32_t offset, uint32_t value);

#endif /* __FPGA_LIB_COMMON_H__ */
