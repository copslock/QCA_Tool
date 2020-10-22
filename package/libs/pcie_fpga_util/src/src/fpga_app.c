#include <stdlib.h>
#include <stdio.h>
#include "../driver_api/fpga_lib_common.h"

#define FPGA_READ_VALUE	    1
#define FPGA_WRITE_VALUE	2
#define FPGA_EXIT_APP		3

int main()
{
    int option = 0, ret = 0, fd = -1;
    uint32_t offsetVal = 0, value = 0;

    fd = fpga_dev_open();
    if (ret < 0) {
        printf("\n Error in device Open");
        exit(0);
    }
    printf("\n PCIE-FPGA Application");
    printf("\n =====================");

    do {
        printf("\n %d. FPGA_READ_VALUE\n", FPGA_READ_VALUE);
        printf(" %d. FPGA_WRITE_VALUE\n", FPGA_WRITE_VALUE);
        printf(" %d. FPGA_EXIT_APP\n", FPGA_EXIT_APP);
        printf("\n Enter the Option :\n");
        scanf("%d", &option);

        if (option == FPGA_EXIT_APP)
            break;

        switch(option) {
            case FPGA_READ_VALUE:
                printf("\n Enter the offset : \n");
                scanf("%x", &offsetVal);
                ret = fpga_read_value(fd, offsetVal, &value);
                if (ret < 0) {
                    printf("\n Error in read");
                }
                printf("\n Read Value is : 0x%x", value);
                break;
            case FPGA_WRITE_VALUE:
                printf("\n Enter the offset : \n");
                scanf("%x", &offsetVal);
                printf("Enter the value : \n");
                scanf("%x", &value);
                ret = fpga_write_value(fd, offsetVal, value);
                if (ret < 0) {
                    printf("\n Error in write");
                }
                break;
            default:
                break;
        }

    } while (option != FPGA_EXIT_APP);
    printf("\n\n");
}
