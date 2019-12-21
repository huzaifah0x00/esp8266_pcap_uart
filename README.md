# ESP8266 PCAP Sniffer - RTOS SDK Version

ESP8266 Sniffer firmware which outputs PCAP data via UART. Use the sniffer to
stream 802.11 packets from ESP8266 to Wireshark or dump into a PCAP file.

## Overview

to be an [ESP8266 RTOS-SDK](https://github.com/espressif/ESP8266_RTOS_SDK) based firmware which sniffs 802.11 4-way handshake packets using 
ESP8266 and save them to sdcard (or flash if possible ).

## Compile & Flash

You should have the RTOS SDK installed. Go to the examples/wifi path and clone
this project. Enter the project directory, change the sniffer options on the
menuconfig, compile and flash:

```sh
cd $IDF_PATH/examples/wifi
git clone https://github.com/huzaifah0x00/esp8266_pcap_uart.git
cd esp8266_pcap_uart
make menuconfig
make -j8 flash
```
