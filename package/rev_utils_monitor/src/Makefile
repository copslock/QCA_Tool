#makefile for rev_utils_monitor

CFLAGS=  -I./inc -Wall -g
LIBS =   -lpthread -lm -lrt
MONITOR = $(wildcard src/*.c)

# --- Build  binary and executable files

all:    rev_utils_monitor

rev_utils_monitor:
	 $(CC)  $(MONITOR) -o rev_utils_monitor  $(LIBS) $(CFLAGS) -DHW_RUN_CMD

clean:
	 rm -rf rev_utils_monitor

