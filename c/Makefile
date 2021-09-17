C_SRC  := $(wildcard ./*.c)
OUTPUT_DIR := build
OBJS   := $(patsubst %.c,${OUTPUT_DIR}/%.o,$(C_SRC))
INCLUDE:= -I./
LIBS   := -lpthread -lcrypto -lm
TARGET := $(OUTPUT_DIR)/demo
#C_FLAGS := -std=gnu99
# all:
# 	@echo $(C_SRC)
# 	@echo $(OBJS)
$(TARGET):$(OBJS)
	@echo $(C_SRC)
	@echo $(LIBS)
	@echo $(OBJS)
	gcc -o $@ $^ $(LIBS) $(C_FLAGS)
${OUTPUT_DIR}/%.o:%.c
	mkdir -p build/
	gcc -o $@ -g -c $< $(INCLUDE) $(LIBS) $(C_FLAGS) 
clean:
	rm -rf $(OUTPUT_DIR)
run:
	./build/demo
test:
	gcc -o test1 main.c log.c common.c list.c -lpthread