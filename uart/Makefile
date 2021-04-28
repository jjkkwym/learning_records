all:
	gcc -c ../common/common.c
	gcc -c uart.c -I../common
	gcc -o uart common.o uart.o -lpthread