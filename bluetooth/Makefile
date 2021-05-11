all:
	gcc -c ../common/common.c
	gcc -c hci_cmd_tool.c -I../common
	gcc -o uart common.o hci_cmd_tool.o -lpthread