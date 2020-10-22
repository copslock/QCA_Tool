/* PCIE FPGA END Point Device driver */
#include "pcie-fpga-drv.h"
#include <linux/time.h>
#include <linux/interrupt.h>
#include <linux/gpio.h>

#define FPGA_DRIVER_NAME    "fpgadrv"
#define WIFI_5G             0
#define WIFI_2G             1
#define LED_GREEN           0
#define LED_RED             1
#define WIFI_5G_LED_OFFSET  0x40
#define WIFI_2G_LED_OFFSET  0x44

//#define IRQ_LAT_MEAS
#define CURRENT_TS_LSB      (0x58)
#define CURRENT_TS_MSB      (0x5c)
#define TS_YEAR_OFFSET_LSB  (0x78)
#define TS_YEAR_OFFSET_MSB  (0x7c)

#define timespec64_to_u64(tsp) \
    (((tsp)->tv_sec * NSEC_PER_SEC) + (tsp)->tv_nsec)

#define u64_to_timespec64(nsec, tsp)    \
    (tsp)->tv_sec = nsec / NSEC_PER_SEC;  \
    (tsp)->tv_nsec = nsec % NSEC_PER_SEC;

/* Every PCI device in the system is represented by  a pcie_dev data structure */
struct pci_dev  *devStruct;
FpgaDrvStruct   fpgaBar0Data;
FpgaDrvStruct   fpgaBar1Data;

/* Major Number for the driver */
static dev_t fpgaMajorNum;
static struct class *fpgaDevclass;
static struct cdev fpgaClassDev;

/* DeLorean PPS */
static const char* pps_gpio_label = "delorean-pps";
static unsigned int pps_gpio_pin = 28;
static unsigned int delorean_ts_ena_gpio_pin = 29;
static unsigned int delorean_ts_enabled = 0;
static int delorean_pps_irq;
struct pps_time {
    struct timespec64 kt0, kt1, kt2; /* kernel timestamp */
    struct timespec64 dt;       /* DeLorean timestamp */
    u64 curr_ts;                /* DeLorean Current TS */
    u64 curr_ts_ns;             /* DeLorean Current TS in ns */
    u64 diff;
};
static struct pps_time *ppst;
#ifdef IRQ_LAT_MEAS
/* Ensure GPIO_69 pin mux is configured as GPIO in the DTS */
static unsigned int lat_meas_gpio_pin = 69;
#endif

static const struct pci_device_id fpga_dev_ids[] = {
        { PCI_DEVICE(FPGA_VENDOR_ID, FPGA_DEVICE_ID) }, /* PCI-E FPGA */
        {0}
};

MODULE_DEVICE_TABLE(pci, fpga_dev_ids);

static irqreturn_t delorean_pps_irq_hndlr(int irq, void *data)
{
    u32 cts_5c, cts_58, yr_7c, yr_78, tmp;
    struct timespec64 kt0, kt1, kt2; /* kernel time */
    struct timespec64 dt;  /* delorean time */
    u64 curr_ts, curr_ts_ns, kt1_ns, kt2_ns, dt_ns, yr;
    s64 diff = 0;

#ifdef IRQ_LAT_MEAS
    gpio_set_value(lat_meas_gpio_pin, 1);
#endif
    getnstimeofday64(&kt0);

    cts_5c = ioread32(fpgaBar0Data.regBase + CURRENT_TS_MSB);
    cts_58 = ioread32(fpgaBar0Data.regBase + CURRENT_TS_LSB);

    getnstimeofday64(&kt1);
    kt1_ns = timespec64_to_u64(&kt1);

    tmp = ioread32(fpgaBar0Data.regBase + 0x5c);
    if(cts_5c != tmp) { /* cts_58 register has overflown and incremented cts_5c */
        getnstimeofday64(&kt0);
        cts_5c = ioread32(fpgaBar0Data.regBase + CURRENT_TS_MSB);
        cts_58 = ioread32(fpgaBar0Data.regBase + CURRENT_TS_LSB);
        getnstimeofday64(&kt1);
    }
    curr_ts = ((u64) cts_5c << 32) | (u64) cts_58;
    curr_ts_ns = (curr_ts * 10) / 4;    /* (TS*2.5) ns */

    /* add year offset */
    yr_7c = ioread32(fpgaBar0Data.regBase + TS_YEAR_OFFSET_MSB);
    yr_78 = ioread32(fpgaBar0Data.regBase + TS_YEAR_OFFSET_LSB);
    yr = ((u64) yr_7c << 32) | (u64) yr_78;
    curr_ts_ns += (yr*NSEC_PER_SEC); /* year offset */
    u64_to_timespec64(curr_ts_ns, &dt);

    getnstimeofday64(&kt2);
    kt2_ns = timespec64_to_u64(&kt2);

    if(kt1.tv_sec != dt.tv_sec) {
        /* time correction */
        dt_ns = timespec64_to_u64(&dt);
        dt_ns += (kt2_ns - kt1_ns);
        ppst->curr_ts_ns = dt_ns;

        return IRQ_WAKE_THREAD;
    } else {
        diff = dt.tv_nsec - kt1.tv_nsec;
        if(diff > 10000 || diff < -10000) { /* +/- 10us */
            /* time correction */
            dt_ns = timespec64_to_u64(&dt);
            dt_ns += (kt2_ns - kt1_ns);

            ppst->curr_ts_ns = dt_ns;
            return IRQ_WAKE_THREAD;
        }
    }

#ifdef IRQ_LAT_MEAS
    gpio_set_value(lat_meas_gpio_pin, 0);
#endif

    return IRQ_HANDLED;
}

static irqreturn_t delorean_pps_thread(int irq, void *dev_id)
{
    struct timespec64 dt;  /* delorean time */
    u64_to_timespec64(ppst->curr_ts_ns, &dt);

    /* set the delorean-time to kernel */
    if(0 != do_settimeofday64(&dt)) {
        pr_err("Error: Failed to do_settimeofday64\n");
    }

    return IRQ_HANDLED;
}

static long fpga_dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    uint32_t regValue = 0;
    FpgaStruct FpgaData;

    if (copy_from_user(&FpgaData, (FpgaStruct *)arg, sizeof(FpgaStruct)) != 0) {
        return -EFAULT;
    }

    switch (cmd) {
        case FPGA_IOCTL_READ_DATA:
            FpgaData.regValue = ioread32(fpgaBar0Data.regBase + FpgaData.regOffset);

            printk("INFO: Offset : 0x%lx Value : 0x%lx\n",
                  (unsigned long)(fpgaBar0Data.regBase + FpgaData.regOffset),
                  (unsigned long)FpgaData.regValue);

            if (copy_to_user((FpgaStruct *)arg, &FpgaData, sizeof(FpgaStruct)) != 0) {
                return -EFAULT;
            }
            break;
        case FPGA_IOCTL_WRITE_DATA:
            regValue = FpgaData.regValue;

            printk("INFO: Offset : 0x%lx Value : 0x%x\n",
                  (unsigned long)(fpgaBar0Data.regBase + FpgaData.regOffset), regValue);

            iowrite32(regValue, fpgaBar0Data.regBase + FpgaData.regOffset);
            break;
        default:
            break;
    }
    return 0;
}

static int32_t fpga_drv_probe(struct pci_dev *pdev, const struct pci_device_id *fpgaDevID)
{
    int32_t err = 0;

    /* It is used to Initialize device by the driver */
    err = pci_enable_device(pdev);
    if (err) {
        dbg_log("ERROR: pci_enable_device \n");
        goto err_probe_out;
    }

    err = pci_request_regions(pdev, FPGA_DRIVER_NAME);
    if (err) {
        dbg_log("ERROR: pci_request_regions \n");
        goto err_probe_region;
    }

    fpgaBar0Data.ulBaraddr = pci_resource_start(pdev, 0);
    fpgaBar0Data.ulBarsize = pci_resource_len(pdev, 0);
    fpgaBar0Data.regBase = ioremap(fpgaBar0Data.ulBaraddr, fpgaBar0Data.ulBarsize);
    if (!fpgaBar0Data.regBase) {
            dbg_log("ERROR: ioremap failed \n");
            goto err_probe_mem;
    }

    printk("\n pcie bar0 address 0x%x\n", fpgaBar0Data.ulBaraddr);
    printk("\n pcie bar0 reg_size 0x%x\n", fpgaBar0Data.ulBarsize);
    printk("\n pcie virtual reg_base 0x%p\n", fpgaBar0Data.regBase);

    /* This is to confirm the FPGA_DRV_REG_SIZE, should not be more than Bar Size */
    if (fpgaBar0Data.ulBarsize < FPGA_DRV_REG_SIZE) {
        printk("ERROR: Size overflow\n");
        goto err_probe_mem;
    }


    fpgaBar1Data.ulBaraddr = pci_resource_start(pdev, 1);
    fpgaBar1Data.ulBarsize = pci_resource_len(pdev, 1);
    fpgaBar1Data.regBase = ioremap(fpgaBar1Data.ulBaraddr, fpgaBar1Data.ulBarsize);
    if (!fpgaBar1Data.regBase) {
            dbg_log("ERROR: ioremap failed \n");
            goto err_probe_mem;
    }

    printk("\n pcie bar1 address 0x%x\n", fpgaBar1Data.ulBaraddr);
    printk("\n pcie bar 1 reg_size 0x%x\n", fpgaBar1Data.ulBarsize);
    printk("\n pcie bar 1 virtual reg_base 0x%p\n", fpgaBar1Data.regBase);

    /* This is to confirm the FPGA_DRV_REG_SIZE, should not be more than Bar Size */
    if (fpgaBar1Data.ulBarsize < FPGA_DRV_REG_SIZE) {
        printk("ERROR: Size overflow\n");
        goto err_probe_mem;
    }

    return 0;

err_probe_out:
    return -EFAULT;

err_probe_region:
    pci_disable_device(pdev);
    return -EFAULT;

err_probe_mem:
    pci_release_regions(pdev);
    pci_disable_device(pdev);
    return -EFAULT;
}

static void fpga_drv_remove(struct pci_dev *pdev)
{
    pci_release_regions(pdev);

    pci_disable_device(pdev);

    if (fpgaBar0Data.mem_io_flag & IORESOURCE_MEM) {
        /* Unmap the Memory region */
        iounmap(fpgaBar0Data.regBase);
    }
}

static const struct file_operations pcie_fpga_fops = {
    .owner          =   THIS_MODULE,
    .unlocked_ioctl =   fpga_dev_ioctl,
};

static struct pci_driver fpga_devdrv = {
    .name           =   FPGA_DRIVER_NAME,
    .id_table       =   fpga_dev_ids,
    .probe          =   fpga_drv_probe,
    .remove         =   fpga_drv_remove,
    .suspend        =   NULL,
    .resume         =   NULL,
};

int32_t pcie_fpga_wifi_led_set(uint32_t radio, uint32_t value)
{   
    unsigned long offset = 0;

    /* Radio parameter check */    
    if (( radio != WIFI_5G ) && ( radio != WIFI_2G )) {
        printk("%s: ERROR: Invalid radio\n", __func__);
        return -EFAULT;
    }
    /* LED Color Parameter check */
    if (( value != LED_GREEN ) && ( value != LED_RED )) {
        printk("%s: ERROR: Invalid LED Color \n", __func__);
        return -EFAULT;
    }
    /* Assign LED offset */
    if ( radio == WIFI_5G ) {
        offset = WIFI_5G_LED_OFFSET;
    } else {
        offset = WIFI_2G_LED_OFFSET;
    }
    /* Set LED value */
    iowrite32(value , fpgaBar0Data.regBase + offset);

    return 0;    
}

static int32_t __init fpgadrv_init(void)
{
    int32_t ret = 0;

    /* Register the PCI driver */
    ret = pci_register_driver(&fpga_devdrv);
    /* Allocate the character device */
    if (alloc_chrdev_region(&fpgaMajorNum, 0, 1, FPGA_DEVICE_NAME) < 0) {
        dbg_log("ERROR: alloc_chrdev_region \n");
        goto err_init_region;
    }

    /* create the character device class */
    fpgaDevclass = class_create(THIS_MODULE, FPGA_CLASS_NAME);
    if (IS_ERR(fpgaDevclass)) {
        dbg_log("ERROR: class_create \n");
        goto err_init_class;
    }

    /* create the character device node */
    if (device_create(fpgaDevclass, NULL, fpgaMajorNum, NULL, FPGA_DEVNODE_NAME) == NULL) {
        dbg_log("ERROR: device_create \n");
        goto err_init_dev;
    }

    cdev_init(&fpgaClassDev, &pcie_fpga_fops);

    if (cdev_add(&fpgaClassDev, fpgaMajorNum, 1) == -1) {
        dbg_log("ERROR: cdev_add \n");
        goto err_init_cdev;
    }

#ifdef IRQ_LAT_MEAS
    if(0 != gpio_direction_output(lat_meas_gpio_pin, 0)) {
        dbg_log("Error: Failed to set gpio%d as output\n", lat_meas_gpio_pin);
        goto err_init_cdev;
    }
    gpio_set_value(lat_meas_gpio_pin, 0);
#endif

    if(0 != gpio_direction_input(delorean_ts_ena_gpio_pin)) {
        dbg_log("Error: Failed to set gpio%d as input\n", delorean_ts_ena_gpio_pin);
        goto err_init_cdev;
    }
    delorean_ts_enabled = gpio_get_value(delorean_ts_ena_gpio_pin);

    if(delorean_ts_enabled > 0) {
        dbg_log("DeLorean timestamp enable gpio is HIGH.\n");

        if(0 != gpio_direction_input(pps_gpio_pin)) {
            dbg_log("Error: Failed to set gpio%d as input\n", pps_gpio_pin);
            goto err_init_cdev;
        }

        delorean_pps_irq = gpio_to_irq(pps_gpio_pin);
        if(0 > delorean_pps_irq) {
            dbg_log("Error: Failed to convert gpio%d to irq\n", pps_gpio_pin);
            goto err_init_cdev;
        }

        ppst = (struct pps_time *) kmalloc(sizeof(struct pps_time), GFP_KERNEL);
        if(ppst == NULL) {
            dbg_log("Error: kmalloc failed.\n");
            goto err_init_cdev;
        }

        if(0 != request_threaded_irq(delorean_pps_irq,
                                     delorean_pps_irq_hndlr,
                                     delorean_pps_thread,
                                     IRQF_TRIGGER_RISING | IRQF_ONESHOT,
                                     pps_gpio_label,
                                     NULL))
        {
            dbg_log("Error: Failed to register request_threaded_irq\n");
            goto err_req_irq;
        }
    }

    pr_info("%s init successfully.\n", FPGA_DRIVER_NAME);

    return ret;

err_init_region:
    pci_unregister_driver(&fpga_devdrv);
    return -EFAULT;
err_init_class:
    pci_unregister_driver(&fpga_devdrv);
    unregister_chrdev_region(fpgaMajorNum, 1);
    return -EFAULT;
err_init_dev:
    pci_unregister_driver(&fpga_devdrv);
    class_destroy(fpgaDevclass);
    unregister_chrdev_region(fpgaMajorNum, 1);
    return -EFAULT;
err_init_cdev:
    pci_unregister_driver(&fpga_devdrv);
    device_destroy(fpgaDevclass, fpgaMajorNum);
    class_destroy(fpgaDevclass);
    unregister_chrdev_region(fpgaMajorNum, 1);
    return -EFAULT;
err_req_irq:
    pci_unregister_driver(&fpga_devdrv);
    device_destroy(fpgaDevclass, fpgaMajorNum);
    class_destroy(fpgaDevclass);
    unregister_chrdev_region(fpgaMajorNum, 1);
    kfree(ppst);
    return -EFAULT;

}

static void __exit fpgadrv_exit(void)
{
    /* Unregister the PCI driver */
    pci_unregister_driver(&fpga_devdrv);

    /* Delete the device class */
    cdev_del(&fpgaClassDev);

    /* delete the device node */
    device_destroy(fpgaDevclass, fpgaMajorNum);

    /* destory the device class */
    class_destroy(fpgaDevclass);

    /* Unregister the character device */
    unregister_chrdev_region(fpgaMajorNum, 1);

    if(delorean_ts_enabled > 0) {
        free_irq(delorean_pps_irq, NULL);
        kfree(ppst);
    }
    pr_info("%s removed successfully.\n", FPGA_DRIVER_NAME);
}

MODULE_LICENSE("GPL");

module_init(fpgadrv_init);
module_exit(fpgadrv_exit);
EXPORT_SYMBOL(pcie_fpga_wifi_led_set);
