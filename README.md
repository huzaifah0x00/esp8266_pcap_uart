### Archived... Because it can't work on an ESP8266, and I bought an ESP32
# ESP8266 handshake Sniffer - RTOS SDK Version

ESP8266 Sniffer firmware which captures 4way handshakes and saves them to a pcap file on sdcard

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
