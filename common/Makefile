include ../Makefile.cfg
all:
	echo makefile list : $(MAKEFILE_LIST)
	echo $(ROOT_DIR)
	echo $(SUB_BUILD_DIR)
	mkdir -p $(LIBS_DIR) $(SUB_BUILD_DIR)   
	gcc -c common.c -o common.o
clean:
	rm -rf $(SUB_BUILD_DIR)