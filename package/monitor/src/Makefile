#makefile for monitor

CFLAGS=  -I./inc -Wall -g
LIBS =   -lpthread -lm -lrt -lpcap
MONITOR = $(wildcard src/*.c)

# --- Build  binary and executable files

all:    monitor

monitor:
	 $(CC)  $(MONITOR) -o monitord  $(LIBS) $(CFLAGS) -DHW_RUN_CMD

clean:
	 rm -rf monitord

