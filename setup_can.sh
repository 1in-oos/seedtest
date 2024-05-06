#!/bin/bash

echo "Enter interface (can0/vcan0):"
read interface

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
    sudo ip link add dev can0 type vcan
    sudo ip link set up can0
else
    echo "Invalid interface. Please enter either can0 or vcan0."
fi

