#ifndef     __FPGA_DRVLIB_COMMON_H__
#define     __FPGA_DRVLIB_COMMON_H__

#include <linux/ioctl.h>

#define FPGA_DEVICE_NAME	"fpgadev"
#define FPGA_CLASS_NAME	    "fpgaclass"
#define FPGA_DEVNODE_NAME	"fpgadev"

typedef struct userdata {
	uint32_t regOffset;
	uint32_t regValue;
} FpgaStruct;

/* /dev/fpgadev ioctls */
#define FPGA_IOCTL_MAGIC	       'f'
#define FPGA_IOCTL_READ_DATA      _IOR(FPGA_IOCTL_MAGIC, 0x01, FpgaStruct)
#define FPGA_IOCTL_WRITE_DATA     _IOW(FPGA_IOCTL_MAGIC, 0x02, FpgaStruct)

#endif /* __FPGA_PCI_DRV_H__ */
