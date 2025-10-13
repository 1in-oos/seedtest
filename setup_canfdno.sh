#!/bin/bash
sudo ip link set can0 down
#sudo ip link set can0 up type can bitrate 500000 dbitrate 2000000 fd on
# can0 仲裁段波特率为500K 采样点为0.8，数据场波特率为2M bitrate 采样点为0.8
#sudo ip link set can0 up type can bitrate 500000 sample-point 0.8 dbitrate 2000000 dsample-point 0.8 fd on restart-ms 1000 
sudo ip link set can0 up type can bitrate 500000 sample-point 0.75 dbitrate 2000000 dsample-point 0.75 fd on fd-non-iso on restart-ms 1000
#sudo ip link set can0 up type can bitrate 500000 sample-point 0.75 dbitrate 2000000 dsample-point 0.75 fd on restart-ms 1000
#sudo ip link set can0 up

