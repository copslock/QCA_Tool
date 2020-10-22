#ifndef     __FPGA_PCI_DRV_H__
#define     __FPGA_PCI_DRV_H__

#include <linux/module.h>    /* included for all kernel modules */
#include <linux/kernel.h>    /* included for KERN_INFO */
#include <linux/init.h>      /* included for __init and __exit macros */
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include "fpga_drv_lib_common.h"

#define     FPGA_VENDOR_ID      0x174a
#define     FPGA_DEVICE_ID      0x8034
#define     FPGA_DRV_REG_SIZE   0x1000

#define     DEBUG_PRINT

#ifdef      DEBUG_PRINT
#define     dbg_log(fmt, ...)   { do { printk(fmt, ##__VA_ARGS__); }while(0); }
#else
#define     dbg_log(fmt, ...)   { do { }while(0); }
#endif


/* Local device data structure to handle the BAR register, size and IO/MEM option */
typedef struct devicedetail {
    uint32_t ulBaraddr;
    uint32_t ulBarsize;
    uint32_t mem_io_flag;
    void __iomem *regBase;
}FpgaDrvStruct;

#endif /* __FPGA_PCI_DRV_H__ */
