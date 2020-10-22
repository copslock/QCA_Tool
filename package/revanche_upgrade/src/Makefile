#makefile for revanche_upgrade
include $(TOPDIR)/rules.mk

CFLAGS=  -I./inc -I$(TOPDIR)/package/libs/pcie_fpga_util/src/driver_api -Wall -g
REV_UPGRADE_LIB = $(STAGING_DIR_ROOT)/lib64/
LIBS =   -lpthread -lm -lrt -L$(REV_UPGRADE_LIB) -lpciefpga
REVANCHE_UPGRADE = $(wildcard src/*.c)

# --- Build  binary and executable files

all:    revanche_upgrade

revanche_upgrade:
	 $(CC)  $(REVANCHE_UPGRADE) -o revanche_upgrade  $(LIBS) $(CFLAGS) -DHW_RUN_CMD -Wl,-rpath="/lib64/"

clean:
	 rm -rf revanche_upgrade

