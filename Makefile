all:
	make -C src/libs/common/
	make -C datastructure/
clean:
	make clean -C src/libs/common/
	make clean -C datastructure/