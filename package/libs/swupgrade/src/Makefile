#Makefile for ocmw and cli
include $(TOPDIR)/rules.mk

CFLAGS=  -Wall -g
LIBS =   -lpthread -lm -lrt -lswupgrade 

SWUPGRADE= src/swUpgrade_main.c
CRASHDUMP= src/rev_crashdump.c
INVENT_API_LIB:= *.o

SWUPGRADE_API_OBJS:=sw_upgrade.o
SWUPGRADE_API_SRC:=driver_api/sw_upgrade.c
SWUPGRADE_API_LIB = libswupgrade.so
MOVE:=mv
RM = rm -rf

all:lib swupgrade

lib: object
	$(CC) $(SWUPGRADE_API_OBJS) -Wall -Wno-pointer-sign -shared -o $(SWUPGRADE_API_LIB)

object:
	$(CC) -c -Wall -Wno-pointer-sign  -fPIC $(CCFLAGS) $(SWUPGRADE_API_SRC)


swupgrade:
	 $(CC)  -Wall -Wno-pointer-sign -g -o img_upgrade $(SWUPGRADE) $(INVENT_API_LIB) -lpthread
	 $(CC)  -Wall -Wno-pointer-sign -g -o rev_crashdump $(CRASHDUMP) $(INVENT_API_LIB) -lpthread

clean:
	rm -fr img_upgrade rev_crashdump driver_api/*.o src/*.o *.so *.o

