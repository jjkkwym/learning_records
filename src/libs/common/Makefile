include ../../../Makefile.cfg
$(info $(wildcard *.c))
C_SRC := $(wildcard *.c)
OBJS := $(patsubst %.c,$(SUB_BUILD_DIR)/%.o,$(C_SRC)) 

build : $(OBJS) $(print_files)
	$(AR) rcs $(LIBS_DIR)/$(SUB_BUILD_DIR_BASENAME).a $(OBJS)
$(OBJS) : $(C_SRC)
	$(MK) -p $(SUB_BUILD_DIR)
	$(CC) -c $< -o $@
clean:
	$(RM) -rf $(SUB_BUILD_DIR) $(LIBS_DIR)/$(SUB_BUILD_DIR_BASENAME).a
# build:: $(OBJS)
# 	@mkdir -p $(LIBS_DIR)/
# 	$(AR) rcs $(LIBS_DIR)/common.a $(OBJS)
# $(OBJS) : $(C_SRC)
# 	$(CC) -c $< -o $@