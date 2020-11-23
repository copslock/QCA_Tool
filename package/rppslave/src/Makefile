#Makefile for rppslave

include $(TOPDIR)/rules.mk

RDP419=1
WPA_DIR=$(TOPDIR)/qca/src/qca-hostap/src
CFLAGS=  -I./inc -I$(TOPDIR)/qca/src/qca-wifi/cmn_dev/qdf/inc -I. -I$(WPA_DIR) -Wall -g -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX
CFLAGS += -DRDP419

SWUPGRADE_LIB = $(STAGING_DIR_ROOT)/lib64/
LIBS =   -lpthread -lm -lrt -L$(SWUPGRADE_LIB)
LIBS += -lswupgrade -lpciefpga
RPPSLAVE = $(wildcard src/*.c)

WPA_FILES = $(WPA_DIR)/common/wpa_ctrl.c $(WPA_DIR)/utils/os_unix.c
WPA_OBJS=wpa_ctrl.o os_unix.o

# --- Build  binary and executable files

all:	rppslave

$(WPA_OBJS):
	$(CC) -c $(CFLAGS) $(WPA_FILES)

rppslave: $(WPA_OBJS)
	$(CC)  $(RPPSLAVE) -o rppslave $(WPA_OBJS) $(LIBS) $(CFLAGS) -Wl,-rpath="/lib64/"

clean:
	rm -fr rppslave

