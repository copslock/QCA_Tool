########################################
# Makefile for the PCIE FPGA driver
########################################

obj ?= .

obj-m += pcie-fpga-drv.o

FPGADEV_INCLUDE = -I$(obj)/inc -I$(obj)/exports

ccflags-y += $(FPGADEV_INCLUDE)

export FPGADEV_INCLUDE
