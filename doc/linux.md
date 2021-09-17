# LINUX

## Linux cmd

压缩
tar -cvzf test.tar.gz test/

解压单个
tar -zvxf file
tar -jvxf file
解压多个
cat filename.tar.bz2.* | tar -jvx

cat filename.tar.gz.*  | tar -zvx

linux命令行连接wifi
linux命令行连接wifi
作者：supersyd 时间: 2021-02-05 08:51:43
标签：linuxwifiwpa
【摘要】一、如果您想连接的网络是没有加密的，您可以用下面的命令直接连接：$ iw dev wlan0 connect [网络 SSID]二、如果网络是用 WEP 加密的，也非常容易：$ iw dev wlan0 connect [网络 SSID] key 0:[WEP 密钥] 三、如果是WPA或WPA2就麻烦一点 1、查看无线网卡名$ iwconfig一般来说，无线接口都叫做 wlan0 2、扫描s...
一、如果您想连接的网络是没有加密的，您可以用下面的命令直接连接：
$ iw dev wlan0 connect [网络 SSID]
二、如果网络是用 WEP 加密的，也非常容易：
$ iw dev wlan0 connect [网络 SSID] key 0:[WEP 密钥]

三、如果是WPA或WPA2就麻烦一点
1、查看无线网卡名
$ iwconfig
一般来说，无线接口都叫做 wlan0

2、扫描ssid列表
$ iw dev wlan0 scan | less

3、确定了无线网卡名和ssid，那么在wpa服务中添加配置
$ wpa_passphrase ssid 'my password' >> /etc/wpa_supplicant/wpa_supplicant.conf

4、再启动 wpa_supplicant
$ wpa_supplicant -i wlan0 -B -c /etc/wpa_supplicant/wpa_supplicant.conf

5、如果调试查看错误信息，那么可以去掉步骤4中的-B选项使其不在后台启动；或者查看日志文件。

注意：
1、有线网卡和无线网卡不能同时使用，禁止其中一个即可
2、NetworkManager服务需停止，否则会不停重启报错


sed -i "s/.../.../" file

CONFIG_FILE="./test_config.conf"
TARGET_KEY=abc
REPLACEMENT_VALUE=3
sed -i "s/\($TARGET_KEY *= *\).*/\1$REPLACEMENT_VALUE/" $CONFIG_FILE
