ROOT_DIR := ..
OUTPUT_DIR = $(ROOT_DIR)/build/
INCLUDE_DIRS := $(ROOT_DIR)/common
LIBS := 
C_SRC := 
OBJS := $(patsubst %.c,${OUTPUT_DIR}/%.o,$(C_SRC))
all:socket_client socket_server
socket_client:socket_client.c 
	gcc -o $@ $^ -I$(INCLUDE_DIRS) 
socket_server:socket_server.c 
	gcc -o $@ $^ -I$(INCLUDE_DIRS) 
clean:
	rm -f socket_client socket_server