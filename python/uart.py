#!/usr/bin/python3
import sys
import os
import serial
import serial.tools.list_ports


def hci_parse_group():
    i = 1
    i +=1
    print(i)
    # 串口检测

class serial_port(object):
    def __init__(self) -> None:
        super().__init__()
        self.ser = serial.Serial()
        self.port_check()
        self.open_port()
        self.close_port()

    def port_check(self):
        # 检测所有存在的串口，将信息存储在字典中
        Com_Dict = {}
        port_list = list(serial.tools.list_ports.comports())
        print('port_list:',port_list)
        for port in port_list:
            Com_Dict["%s" % port[0]] = "%s" % port[1]
            print('port[0]:',port[0],'prot[1]:',port[1])
            print(port)
        print(Com_Dict)
        if len(Com_Dict) == 0:
            print('no serial')
    def open_port(self):
        self.ser.port = '/dev/ttyUSB0'
        self.ser.baudrate = 115200
        self.ser.bytesize = 8
        self.ser.stopbits = 1
        self.ser.parity = 'N'
        try:
            self.ser.open()
        except:
            print('open port error')
            return None
        print('open port suss')
    def close_port(self):
        try:
            self.ser.close()
        except:
            print('close port faild')
        print('close port suss')

if __name__ == '__main__':
    hci_parse_group()
    test = serial_port()
    #test.open_port()