#!/usr/bin/python3
# Made by @xdavidhu (github.com/xdavidhu, https://xdavidhu.me/)

import serial
import io
import os
import subprocess
import signal
import time

try:
    if os.name == 'nt': # check if windows ..
        serialportInput = input("[?] Select a serial port (default 'COM3'): ")
    else:
        serialportInput = input("[?] Select a serial port (default 'COM3'): ")
        
    if serialportInput == "":
        serialport = "COM3" if (os.name == 'nt') else "/dev/ttyUSB0"
    else:
        serialport = serialportInput
except KeyboardInterrupt:
    print("\n[+] Exiting...")
    exit()

try:
    canBreak = False
    while not canBreak:
        boardRateInput = input("[?] Select a baudrate (default '115200'): ")
        if boardRateInput == "":
            boardRate = 115200
            canBreak = True
        else:
            try:
                boardRate = int(boardRateInput)
            except KeyboardInterrupt:
                print("\n[+] Exiting...")
                exit()
            except Exception as e:
                print("[!] Please enter a number!")
                continue
            canBreak = True
except KeyboardInterrupt:
    print("\n[+] Exiting...")
    exit()

try:
    filenameInput = input("[?] Select a filename (default 'capture.pcap'): ")
    if filenameInput == "":
        filename = "capture.pcap"
    else:
        filename = filenameInput
except KeyboardInterrupt:
    print("\n[+] Exiting...")
    exit()

canBreak = False
while not canBreak:
    try:
        ser = serial.Serial(serialport, boardRate)
        canBreak = True
    except KeyboardInterrupt:
        print("\n[+] Exiting...")
        exit()
    except Exception as e:
        print("[!] Serial connection failed... Retrying...")
        print(e)
        time.sleep(1)
        continue

print("[+] Serial connected. Name: " + ser.name)
counter = 0
f = open(filename,'wb')

check = 0
while check == 0:
    line = ser.readline()
    if b"<<START>>" in line:
        check = 1
        print("[+] Stream started...")
    #else: print '"'+line+'"'

if os.name == 'nt': # check if windows ..
    print("[+] NOT Starting up wireshark...")
else:
    print("[+] Starting up wireshark...")
    cmd = "tail -f -c +0 " + filename + " | wireshark -k -i -"
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                           shell=True, preexec_fn=os.setsid)

try:
    while True:
        ch = ser.read()
        f.write(ch)
        f.flush()
except KeyboardInterrupt:
    print("[+] Stopping...")
    if os.name != 'nt':
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    else:
        pass # cuz we never started wireshark 

f.close()
ser.close()
print("[+] Done.")
