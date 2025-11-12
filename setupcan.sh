#!/bin/bash
#
# CAN / VCAN / CAN FD / CAN FD ISO interface setup script
# Author: lin ye
# Version: 2.0
#

# 默认值
DEFAULT_IF="can0"
DEFAULT_BITRATE=500000

echo "Enter interface name (default: ${DEFAULT_IF}):"
read interface
interface=${interface:-$DEFAULT_IF}

echo "Select mode: [1] can  [2] vcan  [3] canfd  [4] canfd-iso"
read mode

# 加载基础模块
sudo modprobe can
sudo modprobe can_raw

# 根据模式进行配置
case "$mode" in
    1|"can")
        echo "Enter bitrate (default: ${DEFAULT_BITRATE}):"
        read bitrate
        bitrate=${bitrate:-$DEFAULT_BITRATE}

        sudo modprobe can_dev
        sudo ip link set $interface type can bitrate $bitrate
        sudo ip link set up $interface
        echo "✅ Configured $interface as CAN with bitrate $bitrate"
        ;;
    2|"vcan")
        sudo modprobe vcan
        # 如果已存在则删除重新创建
        if ip link show $interface >/dev/null 2>&1; then
            sudo ip link delete $interface type vcan
        fi
        sudo ip link add dev $interface type vcan
        sudo ip link set up $interface
        echo "✅ Configured $interface as VCAN (virtual CAN)"
        ;;
    3|"canfd")
        echo "Enter bitrate (default: ${DEFAULT_BITRATE}):"
        read bitrate
        bitrate=${bitrate:-$DEFAULT_BITRATE}

        sudo modprobe can_dev
        sudo ip link set $interface type can bitrate $bitrate dbitrate $((bitrate * 2)) fd on
        sudo ip link set up $interface
        echo "✅ Configured $interface as CAN FD (no ISO) with bitrate $bitrate"
        ;;
    4|"canfd-iso")
        echo "Enter bitrate (default: ${DEFAULT_BITRATE}):"
        read bitrate
        bitrate=${bitrate:-$DEFAULT_BITRATE}

        sudo modprobe can_dev
        sudo ip link set $interface type can bitrate $bitrate dbitrate $((bitrate * 2)) fd on fd-non-iso off
        sudo ip link set up $interface
        echo "✅ Configured $interface as CAN FD ISO with bitrate $bitrate"
        ;;
    *)
        echo "❌ Invalid mode. Please select 1-4."
        exit 1
        ;;
esac

# 显示接口状态
echo
echo "🔎 Interface status:"
ip -details link show $interface
