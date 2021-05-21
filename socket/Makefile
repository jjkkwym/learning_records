ROOT_DIR := ..
OUTPUT_DIR = build/
TARGET_DIR = bin/
INCLUDE_DIRS := $(ROOT_DIR)/common
LIBS := 
C_SRC := 
OBJS := $(patsubst %.c,${OUTPUT_DIR}/%.o,$(C_SRC))
all:$(TARGET_DIR)/socket_client $(TARGET_DIR)/socket_server
	mkdir -p $(OUTPUT_DIR) $(TARGET_DIR)
$(TARGET_DIR)/socket_client:socket_client.c
	mkdir -p $(OUTPUT_DIR) $(TARGET_DIR)
	gcc -o $@ $^ -I$(INCLUDE_DIRS) 
$(TARGET_DIR)/socket_server:socket_server.c 
	gcc -o $@ $^ -I$(INCLUDE_DIRS) 
clean:
	rm -rf socket_client socket_server $(OUTPUT_DIR) $(TARGET_DIR)