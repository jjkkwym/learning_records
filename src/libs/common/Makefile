include ../libs.mk
$(info $(wildcard ./*.c))
C_SRC := $(wildcard ./*.c)
HEARER := $(wildcard ./*.h)
OBJS := $(patsubst %.c,$(SUB_BUILD_DIR)/%.o,$(C_SRC)) 

build : $(OBJS) $(print_files)
	@echo copy $(HEARER) to $(ROOT_DIR)/inc 
	cp $(HEARER) $(ROOT_DIR)/inc
	$(AR) rcs $(LIBS_DIR)/$(SUB_BUILD_DIR_BASENAME).a $(OBJS)

$(SUB_BUILD_DIR)/%.o : %.c
	@echo $(C_SRC)
	$(MK) -p $(dir $@)
	$(CC) -o $@ -c $<
clean:
	$(RM) -rf $(SUB_BUILD_DIR) $(LIBS_DIR)/$(SUB_BUILD_DIR_BASENAME).a
# build:: $(OBJS)
# 	@mkdir -p $(LIBS_DIR)/
# 	$(AR) rcs $(LIBS_DIR)/common.a $(OBJS)
# $(OBJS) : $(C_SRC)
# 	$(CC) -c $< -o $@