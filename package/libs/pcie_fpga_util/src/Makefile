#Makefile for ocmw and cli

CFLAGS=  -Wall -g
LIBS =   -lpthread -lm -lrt -lpciefpga
PCIE_FPGA= $(wildcard src/*.c)
INVENT_API_LIB:= *.o

PCIE_FPGA_API_OBJS:=fpga_drvlib.o
PCIE_FPGA_API_SRC:=driver_api/fpga_drvlib.c
PCIE_FPGA_API_LIB = libpciefpga.so
MOVE:=mv
RM = rm -rf

all:lib pcie_fpga_util

lib: object
	$(CC) $(PCIE_FPGA_API_OBJS) -Wall -Wno-pointer-sign -shared -o $(PCIE_FPGA_API_LIB)

object:
	$(CC) -c -Wall -Wno-pointer-sign  -fPIC $(CCFLAGS) $(PCIE_FPGA_API_SRC)


pcie_fpga_util:
	 $(CC)  -Wall -Wno-pointer-sign -g -o pcie_fpga_util $(PCIE_FPGA) $(INVENT_API_LIB) -lpthread

clean:
	rm -fr pcie_fpga_util driver_api/*.o src/*.o *.so *.o

