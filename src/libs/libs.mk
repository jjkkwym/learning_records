ROOT_DIR := ../../..#$(shell dirname $(abspath $(shell find $(MAKEFILE_LIST) -name *.cfg)))
#ROOT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))#$(shell pwd)
BUILD_DIR := $(ROOT_DIR)/build
LIBS_DIR := $(BUILD_DIR)/libs
SUB_BUILD_DIR_BASENAME := $(shell basename $(shell pwd))
SUB_BUILD_DIR := $(BUILD_DIR)/$(SUB_BUILD_DIR_BASENAME)#$(shell dirname $)
COMMON_LIBS_DIR := #$(ROOT_DIR)/common
COMMON_LIBS_BUILD_DIR := #$(BUILD_DIR)/common

INCLUDE_DIRS :=#$(COMMON_LIBS_DIR)
LIBS :=  
C_SRC:=#$(wildcard $(COMMON_LIBS_DIR)/*.c)
OBJS :=#$(patsubst %.c,%.o,$(C_SRC)) 
# bar := ${subst not, totally, "I am not superman"}
# $(info bar:$(bar))
# $(info($(foreach a,$(MAKEFILE_LIST),ifeq(a,Makefile.cfg))))
# ifeq ($(foreach a,$(MAKEFILE_LIST),a))
#$(foreach file,$(MAKEFILE_LIST),$(info $(file)))
$(info makefile $(shell find $(MAKEFILE_LIST) -name *.cfg))

CC := gcc
AR := ar
MK := mkdir
RM := rm
# build:: $(OBJS)
# 	@mkdir -p $(LIBS_DIR)/
# 	$(AR) rcs $(LIBS_DIR)/common.a $(OBJS)
# $(OBJS) : $(C_SRC)
# 	$(CC) -c $< -o $@
# clean:
# 	$(RM) -rf $(BUILD_DIR)
define print_files 
$(info ############ makefile.cfg ###############)
$(info 				  $(MAKEFILE_LIST))
$(info ROOT_DIR:      $(ROOT_DIR))
$(info BUILD_DIR:     $(BUILD_DIR))
$(info LIBS_DIR:      $(LIBS_DIR))
$(info SUB_BUILD_DIR_BASENAME: $(SUB_BUILD_DIR_BASENAME))
$(info SUB_BUILD_DIR: $(SUB_BUILD_DIR))
$(info INCLUDE_DIRS:  $(INCLUDE_DIRS))
$(info LIBS: 		  $(LIBS))
$(info C_SRC: 	      $(C_SRC))
$(info OBJS: 		  $(OBJS)) 
$(info #########################################)
endef