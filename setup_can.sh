#!/bin/bash

# 提示用户输入接口名称，如果没有输入，则使用默认的 can0
echo "Enter interface (default: can0):"
read interface

# 如果接口名称为空，设置为默认的 can0
if [ -z "$interface" ]; then
    interface="can0"
fi

# 判断接口名称，并执行相应的配置
if [ "$interface" == "can0" ]; then
    echo "Enter bitrate (default: 500000):"
    read bitrate
    if [ -z "$bitrate" ]; then
        bitrate=500000
    fi

    sudo modprobe can_dev
    sudo modprobe can
    sudo modprobe can_raw
    sudo ip link set $interface type can bitrate $bitrate
    sudo ip link set up $interface
elif [ "$interface" == "vcan0" ]; then
    sudo modprobe can
    sudo modprobe can_raw
    sudo modprobe vcan
    sudo ip link add dev vcan0 type vcan
    sudo ip link set up vcan0
else
    echo "Invalid interface. Please enter either can0 or vcan0."
fi
