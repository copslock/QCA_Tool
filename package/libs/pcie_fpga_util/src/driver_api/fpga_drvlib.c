#include "fpga_drvlib.h"
#include "fpga_drv_lib_common.h"

int fpga_dev_open()
{
	return open("/dev/fpgadev", O_RDWR);
}

void fpga_dev_close(int fd)
{
	close(fd);
}

int fpga_read_value(int fd, uint32_t offset, uint32_t *value)
{
	FpgaStruct fpgaData;

    
	memset(&fpgaData, 0, sizeof(fpgaData));
	fpgaData.regOffset = offset;

	if(ioctl(fd, FPGA_IOCTL_READ_DATA, &fpgaData) < 0) {

		printf("\n ERROR : IOCTL");
		return -1;
	}

	*value = fpgaData.regValue;

	return 0;
}

int fpga_write_value(int fd, uint32_t offset, uint32_t value)
{
	FpgaStruct fpgaData;

    memset(&fpgaData, 0, sizeof(fpgaData));

	fpgaData.regOffset = offset;
	fpgaData.regValue = value;

	if(ioctl(fd, FPGA_IOCTL_WRITE_DATA, &fpgaData) < 0 ) {

		printf("\n ERROR : IOCTL");
		return -1;
	}

	return 0;
}

int get_ipq_sw_version(uint32_t *version)
{
     uint32_t fw_version = 0;
     int fd = -1;
     uint32_t offset = IPQ_FW_VER_REG;

     fd = fpga_dev_open();
     if (fd < 0 ) {
          printf("\n fpga device could not open \n");
          return -1;
     }

     if( fpga_read_value(fd, offset, &fw_version) < 0 ) {
         printf("\n Error: Reading ipq fw version is failed.\n");
         fpga_dev_close(fd);
         return -1;
     }

     *version = (0xFFFFFFFF & fw_version);
     fpga_dev_close(fd);
     return 0;
}

int set_ipq_upgrade_status(uint32_t value)
{
     int fd = -1;
     uint32_t offset = IPQ_UPGRADE_STATUS_REG;

     fd = fpga_dev_open();
     if (fd < 0 ) {
          printf("\n fpga device could not open \n");
          return -1;
     }

     if( fpga_write_value(fd, offset, value) < 0 ) {
         printf("\n Error: Writing to upgrade register is failed\n");
         fpga_dev_close(fd);
         return -1;
     }

     fpga_dev_close(fd);
     return 0;
}

int set_ipq_appln_bootup_status(uint32_t value)
{
     int fd = 0;
     uint32_t offset = IPQ_BOOTUP_STATUS_REG;

     fd = fpga_dev_open();
     if (fd < 0 ) {
          printf("\n fpga device could not open \n");
          return -1;
     }

     if( fpga_write_value(fd, offset, value) < 0 ) {
         printf("\n Error: Writing to upgrade register is failed\n");
         fpga_dev_close(fd);
         return -1;
     }

     fpga_dev_close(fd);
     return 0;
}
