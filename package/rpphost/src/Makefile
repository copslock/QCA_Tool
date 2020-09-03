#Makefile for rpphost

include $(TOPDIR)/rules.mk

WPA_DIR=$(TOPDIR)/qca/src/qca-hostap/src
CFLAGS=  -I../../../rppslave/src/inc -I./inc -I$(TOPDIR)/qca/src/qca-wifi/cmn_dev/qdf/inc -I. -I$(WPA_DIR) -Wall -g 

LIBS =   -lm -lrt 
RPPHOST = $(wildcard src/*.c)

# --- Build  binary and executable files

all:	rpphost

rpphost: $(RPPHOST)
	$(CC)  $(RPPHOST) -o rpphost $(LIBS) $(CFLAGS) -Wl,-rpath="/lib64/"

clean:
	rm -fr rpphost
